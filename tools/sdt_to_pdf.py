#!/usr/bin/env python3
"""Offline PDF report for Go `sdt` scans (Phase 1, pipeline-ready).

Reads the deterministic `sdt` artifacts — no server, DB, or network:
  reports/findings.json       (canonical secure-dev/report/v1alpha1)
  reports/run-manifest.json   (digests, tool versions, task health)
  reports/summary.txt         (optional, echoed on cover)

Writes:
  reports/security-report.pdf (A4, secrets stay redacted — inputs already are)

Usage (local or Jenkins sidecar, after `sdt scan`):
  python3 tools/sdt_to_pdf.py --from reports/findings.json \
    --manifest reports/run-manifest.json --out reports/security-report.pdf

Env/flags beat defaults so CI reproduces local runs bit-for-bit:
  --from / --manifest / --out / --project / --profile (all optional with sane defaults).
  Exit 0 on success, 2 on invalid input (mirrors sdt exit-code style).

Pipeline notes:
  - Run AFTER `sdt scan`, even on policy_failed (reports are finalized pre-exit).
  - Archive `reports/` always: findings.json + findings.sarif + run-manifest.json + security-report.pdf.
  - Needs only `reportlab>=4.0` (already in requirements.txt).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        Preformatted,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
except ImportError:
    print("sdt_to_pdf: reportlab not installed (pip install 'reportlab>=4.0')", file=sys.stderr)
    sys.exit(2)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#B00020"),
    "high": colors.HexColor("#E65100"),
    "medium": colors.HexColor("#C77700"),
    "low": colors.HexColor("#3B6E9B"),
    "info": colors.HexColor("#555555"),
}
SEV_ORDER = ("critical", "high", "medium", "low", "info")


def _esc(text) -> str:
    return _xml_escape("" if text is None else str(text))


def _short_rule(rule_id: str, limit: int = 90) -> str:
    """Collapse long vendored prefixes to the meaningful tail."""
    if not rule_id:
        return "-"
    tail = rule_id.split(".")[-1] if "." in rule_id else rule_id.split("/")[-1]
    disp = tail or rule_id
    if len(disp) > limit:
        disp = disp[: limit - 1] + "…"
    return disp


def _loc(f: dict) -> str:
    loc = f.get("location") or {}
    path = loc.get("path") or (f.get("artifact") or {}).get("target") or "-"
    sl = loc.get("startLine")
    if sl:
        return f"{path}:{sl}"
    return str(path)


def _sev(f: dict) -> str:
    sev = f.get("severity") or {}
    return str(sev.get("canonical") or sev.get("original") or "info").lower()


def _priority(sev: str) -> str:
    return {"critical": "High", "high": "High"}.get(sev, "Medium" if sev == "medium" else "Low")


# Static finding enrichment (Sonar-hotspot style, no AI — deterministic text).
# Matched by substring against the lowercased rule-id tail + category.
# Each entry: category label, risk blurb, assess checklist, fix guidance,
# optional compliant snippet, reference list. Keep entries short: they render
# once per finding. `rule.references` / `rule.cwe` from findings.json are
# appended automatically. AI explain (`sdt explain`) can layer on later —
# it never changes the verdict, same as here.
KNOWLEDGE = [
    {
        "match": ["private-key", "private_key", "privatekey"],
        "label": "Secrets",
        "risk": "Private key material committed to the repository. Anyone with read access "
                "can impersonate the service, decrypt traffic, or sign artifacts as you. "
                "Git history keeps it forever — deleting the file later does not revoke it.",
        "assess": [
            "Is this key used in production, or test-only? Production keys are critical.",
            "Who has (or had) read access to this repository, including forks and clones?",
            "Has the key been used to sign anything an attacker could now forge?",
        ],
        "fix": "Generate a new key, revoke/replace the exposed one everywhere it is trusted, "
               "purge it from git history, and load it at runtime from a vault or CI/CD secret — never from source.",
        "compliant": "# load at runtime, never commit:\nkey = vault.read('prod/jwt-signing-key')",
        "refs": ["CWE-798 Use of Hard-coded Credentials", "OWASP Top 10 A07 Identification and Authentication Failures"],
    },
    {
        "match": ["api-key", "api_key", "apikey", "generic-secret", "sendinblue", "secret"],
        "label": "Secrets",
        "risk": "A credential committed to source. Every clone, fork, backup, and CI log is now "
                "in scope for rotation. Attackers scan public and leaked repositories for exactly these patterns.",
        "assess": [
            "What service does this credential unlock, and is that service production?",
            "Is the same value reused anywhere else (other repos, environments)?",
            "Do access logs show use you cannot explain?",
        ],
        "fix": "Rotate the credential at the provider, remove it from source and history, "
               "and inject it at runtime via environment, CI/CD secrets, or a vault. Enable least-privilege scopes.",
        "compliant": "# runtime injection, never source:\napi_key = os.environ['PAYMENT_API_KEY']",
        "refs": ["CWE-798 Use of Hard-coded Credentials", "OWASP Top 10 A07 Identification and Authentication Failures"],
    },
    {
        "match": ["pseudorandom", "predictable-random", "weak-random", "insecure-random", "std-random", "math-random", "rand"],
        "label": "Weak Cryptography",
        "risk": "Predictable pseudorandom values (e.g. java.util.Random) in a security context let an "
                "attacker guess the next value and impersonate users or bypass controls. Past impact includes "
                "CVE-2013-6386, CVE-2006-3419, CVE-2008-4102.",
        "assess": [
            "Does the generated value need to be unpredictable (tokens, salts, nonces, lottery/draw logic)?",
            "Is the generator predictable (PRNG) rather than cryptographically strong?",
            "Is the value reused or exposed to an attacker?",
        ],
        "fix": "Use a cryptographically strong RNG (java.security.SecureRandom), use each value once, "
               "and never expose or persist the raw value insecurely.",
        "compliant": "SecureRandom random = new SecureRandom(); // compliant\nbyte[] bytes = new byte[20];\nrandom.nextBytes(bytes);",
        "refs": ["CWE-338 Weak PRNG", "CWE-330 Insufficiently Random Values", "OWASP Top 10 A02 Cryptographic Failures", "CERT MSC02-J Generate strong random numbers"],
    },
    {
        "match": ["no-string-eqeq", "string-eqeq"],
        "label": "Reliability / Correctness",
        "risk": "Comparing strings with == tests reference identity, not content. The branch silently "
                "takes the wrong path whenever equal strings are different objects — a logic bug that "
                "can bypass checks (approval, auth, validation).",
        "assess": [
            "Is this comparison guarding a security decision (role, approval, ownership)?",
            "Can the operands be distinct objects with equal content (deserialized, request params)?",
        ],
        "fix": "Compare content with .equals() (null-safe: constant first or Objects.equals).",
        "compliant": "if (\"expected\".equals(actual)) { ... } // or Objects.equals(a, b)",
        "refs": ["CWE-595 Comparison of Object References Instead of Contents"],
    },
    {
        "match": ["eqeq", "assignment-comparison", "hardcoded-conditional"],
        "label": "Reliability / Correctness",
        "risk": "A comparison that is always true (or always false) means dead logic: the guarded branch "
                "either never runs or always runs. If it guards validation, auth, or error handling, the "
                "protection is illusory.",
        "assess": [
            "Which branch is dead, and what protection was it supposed to provide?",
            "Is the compared value ever reassigned between reads (concurrency, aliasing)?",
        ],
        "fix": "Compare distinct values; for NaN checks use Double.isNaN. Remove conditionals that cannot vary.",
        "compliant": "if (!Double.isNaN(value) && value == other) { ... }",
        "refs": ["CWE-571 Expression Is Always True", "CWE-570 Expression Is Always False"],
    },
    {
        "match": ["redos", "regex-dos", "regex-injection", "pattern-from-string"],
        "label": "Denial of Service",
        "risk": "A regular expression built from uncontrolled input can exhibit catastrophic backtracking: "
                "a short crafted string ties up a thread (ReDoS). One request can exhaust a server pool.",
        "assess": [
            "Is the pattern (or the input it runs on) attacker-controlled?",
            "Is there a timeout or input-length cap on the match?",
        ],
        "fix": "Validate/allow-list input, avoid nested quantifiers, prefer linear-time matching or precompiled "
               "safe patterns, and cap input length.",
        "compliant": "if (!INPUT.matcher(user).matches()) throw new IllegalArgumentException(); // allow-listed pattern",
        "refs": ["CWE-1333 Inefficient Regular Expression Complexity", "OWASP Top 10 A04 Insecure Design"],
    },
    {
        "match": ["xxe", "xmlinputfactory", "external-entities", "saxparser", "documentbuilder"],
        "label": "XML External Entity (XXE)",
        "risk": "An XML parser with external entities enabled lets an attacker read local files, probe "
                "internal hosts (SSRF), or detonate billion-laughs DoS via a crafted document.",
        "assess": [
            "Does the parser accept XML from outside your trust boundary (uploads, APIs, feeds)?",
            "Are DTDs/external entities actually required for this use case?",
        ],
        "fix": "Disable DTDs and external entities; prefer simple formats (JSON) where possible.",
        "compliant": "factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
        "refs": ["CWE-611 XXE", "OWASP Top 10 A05 Security Misconfiguration"],
    },
    {
        "match": ["sql-injection", "tainted-sql", "sqli"],
        "label": "Injection",
        "risk": "SQL built by concatenating input lets an attacker rewrite the query: dump tables, "
                "escalate, or delete data. Taint tracking fired because untrusted data reaches the sink.",
        "assess": [
            "Is the concatenated value reachable from request/user input?",
            "Does the DB account have more privilege than this query needs?",
        ],
        "fix": "Use parameterized queries / prepared statements; never concatenate. Least-privilege DB credentials.",
        "compliant": "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "refs": ["CWE-89 SQL Injection", "OWASP Top 10 A03 Injection"],
    },
    {
        "match": ["command-injection", "os-exec", "system-call", "spawn-process", "subprocess", "code-run", "eval", "dangerous-globals"],
        "label": "Injection",
        "risk": "Untrusted data reaching a shell, process launcher, or code evaluator is remote code "
                "execution: an attacker runs OS commands with service privileges.",
        "assess": [
            "Can an attacker influence any argument, flag, or the executable path?",
            "Is a shell involved (shell=True, string command, eval)?",
        ],
        "fix": "Avoid shells: argument arrays, allow-listed commands, no eval. Sandbox and drop privileges.",
        "compliant": "subprocess.run([\"/usr/bin/convert\", allowlisted_file], shell=False)",
        "refs": ["CWE-78 OS Command Injection", "CWE-94 Code Injection", "OWASP Top 10 A03 Injection"],
    },
    {
        "match": ["deserialization", "pickle", "yaml-load", "unsafe-load", "jackson", "snakeyaml", "jms-deserialization"],
        "label": "Insecure Deserialization",
        "risk": "Deserializing untrusted bytes with a powerful codec executes attacker-chosen object graphs — "
                "a classic RCE primitive (pickle, unsafe YAML, Jackson gadgets, JMS).",
        "assess": [
            "Does the deserialized payload cross a trust boundary?",
            "Is the codec the unsafe variant (pickle, yaml.load, default constructors)?",
        ],
        "fix": "Use safe loaders (yaml.safe_load), signed/validated formats (JSON + schema), and deny gadget classes.",
        "compliant": "data = yaml.safe_load(payload)  # never yaml.load(untrusted)",
        "refs": ["CWE-502 Deserialization of Untrusted Data", "OWASP Top 10 A08 Software and Data Integrity Failures"],
    },
    {
        "match": ["path-traversal", "filepath-clean", "zip-slip", "decompression-bomb", "open-redirect", "ssrf", "url-host"],
        "label": "Unvalidated Input",
        "risk": "Untrusted input used as a path, URL, or redirect target escapes its sandbox: read/write "
                "outside the intended directory, SSRF into the internal network, or open-redirect phishing.",
        "assess": [
            "Can ../, absolute paths, or alternate hosts survive to the sink?",
            "Is the resolved path/URL validated against an allow-listed root?",
        ],
        "fix": "Canonicalize and confine to an allow-listed root; validate hosts against an allow-list.",
        "compliant": "p = (ROOT / name).resolve()\nassert str(p).startswith(str(ROOT))",
        "refs": ["CWE-22 Path Traversal", "CWE-918 SSRF", "OWASP Top 10 A01 Broken Access Control"],
    },
    {
        "match": ["xss", "servletresponse-writer", "template-string", "html-in-template", "raw-html"],
        "label": "Cross-Site Scripting (XSS)",
        "risk": "Unescaped user data rendered as HTML/JavaScript runs attacker script in victims' browsers: "
                "session theft, actions on their behalf, defacement.",
        "assess": [
            "Does untrusted data reach the response without escaping/encoding?",
            "Is the sink HTML, attribute, JS, or URL context (each needs its own encoding)?",
        ],
        "fix": "Context-appropriate output encoding by default; framework auto-escaping; Content-Security-Policy.",
        "compliant": "<c:out value=\"${name}\" /> // context-escaped output",
        "refs": ["CWE-79 XSS", "OWASP Top 10 A03 Injection"],
    },
    {
        "match": ["weak-hash", "insecure-hash", "md5", "sha1", "uuid-version", "ecb", "null-cipher", "deprecated", "defaulthttpclient"],
        "label": "Weak Cryptography",
        "risk": "Broken primitives (MD5/SHA-1/ECB/null cipher) or deprecated clients fail their security "
                "contract: collisions forge integrity checks, ECB leaks patterns, deprecated stacks miss patches.",
        "assess": [
            "Is the primitive protecting integrity, passwords, or tokens (vs. non-security checksums)?",
            "Is there a drop-in strong alternative (SHA-256/bcrypt/GCM/current client)?",
        ],
        "fix": "Migrate to SHA-256+ / password hashing (bcrypt/argon2) / AES-GCM; upgrade deprecated clients.",
        "compliant": "MessageDigest.getInstance(\"SHA-256\"); // or BCrypt.hashpw(pw, BCrypt.gensalt())",
        "refs": ["CWE-327 Broken Crypto", "CWE-328 Weak Hash", "OWASP Top 10 A02 Cryptographic Failures"],
    },
    {
        "match": ["ssl", "tls", "verify", "hostname-verification", "unverified", "truststore", "socket", "cookie-missing", "csrf", "cors"],
        "label": "Transport / Session Security",
        "risk": "Missing TLS verification or insecure session flags expose traffic and sessions to "
                "interception, downgrade, and hijack on hostile networks.",
        "assess": [
            "Does this path carry credentials, tokens, or PII over untrusted networks?",
            "Are Secure/HttpOnly/SameSite and verification actually enforced, or merely configured?",
        ],
        "fix": "Enforce verified TLS (and hostname checks), Secure/HttpOnly/SameSite cookies, CSRF tokens.",
        "compliant": "cookie.setSecure(true); cookie.setHttpOnly(true); // + verified TLS",
        "refs": ["CWE-297 Improper Hostname Verification", "CWE-614 Sensitive Cookie Without Secure", "OWASP Top 10 A05 Security Misconfiguration"],
    },
    {
        "match": ["privileged", "allow-privilege", "run-as-non-root", "hostpid", "hostipc", "hostnetwork", "seccomp", "writable-filesystem", "secrets-in-config", "docker-socket", "skip-tls-verify"],
        "label": "Container / K8s Hardening",
        "risk": "Over-privileged workloads turn any single RCE into cluster takeover: host namespaces, "
                "writable roots, missing seccomp, secrets in env/config, or skipped TLS verification widen blast radius.",
        "assess": [
            "Does this workload genuinely need host access, privilege escalation, or writable root?",
            "Are secrets mounted as files/volumes instead of env literals?",
        ],
        "fix": "runAsNonRoot, readOnlyRootFilesystem, drop ALL capabilities, seccomp default, secrets via volumes.",
        "compliant": "securityContext:\n  runAsNonRoot: true\n  readOnlyRootFilesystem: true\n  allowPrivilegeEscalation: false",
        "refs": ["CWE-250 Execution with Unnecessary Privileges", "K8s Hardening Guidance (NSA/CISA)"],
    },
    {
        "match": ["github-actions", "workflow", "script-injection", "mutable-action-tag", "pull-request-target", "secrets-inherit", "curl-pipe-shell", "shai-hulud", "prompt-injection", "staged-publishing"],
        "label": "CI Pipeline Integrity",
        "risk": "Untrusted PR input in workflow scripts, mutable action pins, or curl|sh installers give "
                "attackers code execution inside your pipeline — with your secrets and signing keys.",
        "assess": [
            "Does any run: step interpolate PR-controlled values (title, body, branch)?",
            "Are third-party actions pinned to full SHAs (not mutable tags)?",
        ],
        "fix": "Never interpolate untrusted context in scripts; pin actions by SHA; require environments/approvals for secrets.",
        "compliant": "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 // pinned SHA",
        "refs": ["CWE-829 Untrusted Control Sphere", "OWASP Top 10 A08 Software and Data Integrity Failures"],
    },
]

CATEGORY_FALLBACK = {
    "secret": {
        "label": "Secrets",
        "risk": "Committed credential or secret-adjacent material. Assume every copy of this repository "
                "(clones, forks, backups, CI caches) now holds it until rotated.",
        "assess": ["Which system does it unlock, and is that production?", "Where else is the value reused?", "Do logs show unexplained use?"],
        "fix": "Rotate at the provider, purge from history, inject at runtime from a vault or CI/CD secret.",
        "compliant": "secret = vault.read('path/to/secret')  # never in source",
        "refs": ["CWE-798 Use of Hard-coded Credentials"],
    },
    "sast": {
        "label": "Code Weakness",
        "risk": "Static analysis flags a code pattern that is unsafe in general. Exploitability depends on "
                "whether untrusted data can reach it and what the surrounding code does with the result.",
        "assess": ["Is untrusted input reachable here?", "What is the worst case if this triggers in production?", "Is there a compensating control (validation, auth, sandbox)?"],
        "fix": "Follow the rule-specific guidance below; add a regression test proving the unsafe input is handled.",
        "compliant": "",
        "refs": [],
    },
    "dependency-vulnerability": {
        "label": "Vulnerable Dependency",
        "risk": "A known CVE in a vendored library version. The CVE description below carries the concrete "
                "impact; reachability decides urgency — reachable + exploitable first.",
        "assess": ["Is the vulnerable code path reachable from your application?", "Is there a public exploit?", "Does the fix version break your build (check changelog)?"],
        "fix": "Upgrade to the fixed version; if blocked, apply the vendor workaround and pin a renewal date.",
        "compliant": "",
        "refs": [],
    },
    "misconfiguration": {
        "label": "Misconfiguration",
        "risk": "An infrastructure-as-code setting weakens a guardrail (privilege, network, TLS, secrets). "
                "Individually small; combined they decide blast radius after any foothold.",
        "assess": ["Is this workload internet-facing or multi-tenant?", "Is the relaxation load-bearing or copy-paste?", "What compensates (admission policy, network policy)?"],
        "fix": "Tighten to least privilege; enforce the invariant with admission/OPA policy so it cannot regress.",
        "compliant": "",
        "refs": ["OWASP Top 10 A05 Security Misconfiguration"],
    },
}

DEFAULT_KB = {
    "label": "Review",
    "risk": "A scanner-reported weakness. Triage by reachability and impact before scheduling the fix.",
    "assess": ["Is it reachable with untrusted input?", "What is the worst-case impact?", "Is there a compensating control?"],
    "fix": "Remediate per the scanner guidance; add a regression test.",
    "compliant": "",
    "refs": [],
}


def _kb_for(f: dict):
    """Pick the first knowledge entry whose keyword hits the rule tail or category."""
    rule = f.get("rule", {}) or {}
    hay = f"{rule.get('id', '')} {f.get('category', '')}".lower().replace("_", "-")
    for entry in KNOWLEDGE:
        if any(k in hay for k in entry["match"]):
            return entry
    return CATEGORY_FALLBACK.get(f.get("category"), DEFAULT_KB)


def _snippet(src_root: Path, path: str, start, end, context: int = 6, cap_lines: int = 16) -> list | None:
    """Read source context for Where-sections. Never raises.

    Safety: callers must skip key/secret findings entirely (see _sensitive_source).
    Defense-in-depth here: any line resembling key material (PEM armor or a long
    high-entropy token) is replaced — a live secret must never reach the PDF,
    even if rule metadata mislabels the finding.
    """
    import re as _re

    _armor = _re.compile(r"-----(BEGIN|END) [A-Z0-9 ]*?(PRIVATE KEY|PUBLIC KEY|CERTIFICATE|OPENSSH PRIVATE KEY)-----")
    _blob = _re.compile(r"[A-Za-z0-9+/=_\-]{48,}")

    def _scrub(line: str) -> str:
        if _armor.search(line):
            return "[redacted: key armor withheld — rotate, do not inspect]"
        m = _blob.search(line)
        if m and len(m.group(0)) >= 48:
            return _blob.sub("[redacted]", line)
        return line

    try:
        if not path or path == "-":
            return None
        p = (src_root / path) if not str(path).startswith("/") else Path(path)
        if not p.is_file() or p.stat().st_size > 2_000_000:
            return None
        lines = p.read_text(errors="replace").splitlines()
        if not lines or len(lines) > 20000:
            return None
        s = max(1, int(start or 1))
        e = max(s, int(end or s))
        lo = max(1, s - context)
        hi = min(len(lines), e + context, lo + cap_lines - 1)
        out = []
        for n in range(lo, hi + 1):
            mark = ">>" if s <= n <= e else "  "
            out.append(f"{mark} {n:>5}  {_scrub(lines[n - 1])[:160]}")
        return [lo, "\n".join(out)]
    except (OSError, ValueError, UnicodeError):
        return None


_KEY_EXTS = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".asc", ".gpg", ".ppk")


def _sensitive_source(f: dict) -> bool:
    """True when source must never render: secrets, key-material rules, key files.

    Opengrep flags committed PEMs as SAST `private-key` (not `secret`), so the
    category check alone is insufficient — match rule + file extension too.
    """
    if f.get("category") == "secret":
        return True
    rule = f.get("rule", {}) or {}
    hay = str(rule.get("id", "")).lower().replace("_", "-")
    if any(k in hay for k in ("private-key", "privatekey", "api-key", "apikey", "secret", "password", "token", "credential")):
        return True
    loc = f.get("location") or {}
    return str(loc.get("path", "")).lower().endswith(_KEY_EXTS)


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=20, spaceAfter=6),
        "subtitle": ParagraphStyle("s", parent=base["Heading3"], textColor=colors.HexColor("#64748B")),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], spaceBefore=10, spaceAfter=6),
        "body": base["BodyText"],
        "mono": ParagraphStyle("m", parent=base["Code"], fontSize=8.5, textColor=colors.HexColor("#475569")),
        "small": ParagraphStyle("sm", parent=base["BodyText"], fontSize=8.5, textColor=colors.HexColor("#475569")),
        "sect": ParagraphStyle("sect", parent=base["Heading4"], fontSize=10, spaceBefore=6, spaceAfter=2),
        "code": ParagraphStyle("c", parent=base["Code"], fontSize=7.5, backColor=colors.HexColor("#F1F5F9")),
    }


def _meta_table(styles, rows) -> Table:
    t = Table(
        [[Paragraph(_esc(k), styles["mono"]), Paragraph(_esc(v), styles["body"])] for k, v in rows],
        colWidths=[3.8 * cm, 12.7 * cm],
    )
    t.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return t


def _count_table(styles, title_row, counts: Counter, order) -> Table:
    rows = [title_row]
    total = 0
    for key in order:
        n = int(counts.get(key, 0))
        total += n
        rows.append([str(key).capitalize(), str(n)])
    rows.append(["Total", str(total)])
    t = Table(rows, colWidths=[6 * cm, 3 * cm])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -2), 0.5, colors.HexColor("#D1D5DB")),
        ("BACKGROUND", (0, len(rows) - 1), (-1, len(rows) - 1), colors.HexColor("#F8FAFC")),
        ("FONTNAME", (0, len(rows) - 1), (-1, len(rows) - 1), "Helvetica-Bold"),
    ]
    t.setStyle(TableStyle(style))
    return t


def build_pdf(findings_doc: dict, manifest: dict, project: str, profile: str, out: Path, src_root: Path | None = None) -> None:
    styles = _styles()
    story: list = []
    findings = findings_doc.get("findings", [])
    policy = findings_doc.get("policy", {}) or {}
    blockers = {b.get("findingId") for b in policy.get("blockers", []) if isinstance(b, dict)}

    tools = ", ".join(
        f"{t.get('adapter')} {t.get('version', '')}".strip()
        for t in (manifest.get("tools", []) or [])
    ) or "-"
    status = findings_doc.get("status") or manifest.get("status") or "-"

    story.append(Paragraph("Security Scan Report (sdt)", styles["title"]))
    story.append(Paragraph("Local-first SAST + secrets + supply-chain — offline, deterministic", styles["subtitle"]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(
        _meta_table(
            styles,
            [
                ["Project", project],
                ["Profile", profile or manifest.get("profile", "-")],
                ["Status", status],
                ["Generated", findings_doc.get("generatedAt") or manifest.get("completedAt") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
                ["Run / Plan", f"{findings_doc.get('runId', manifest.get('runId', '-'))} / {str(findings_doc.get('planId', manifest.get('planId', '-')))[:19]}…"],
                ["Tools", tools],
            ],
        )
    )
    story.append(Spacer(1, 0.3 * cm))
    story.append(
        Paragraph(
            "Secrets are redacted in all evidence. AI was not used for verdicts. "
            "Blockers first; full list follows. Correlate with Sonar via fingerprints in findings.json.",
            styles["small"],
        )
    )

    sev_counts = Counter(_sev(f) for f in findings)
    cat_counts = Counter(str(f.get("category", "-")) for f in findings)
    story.append(Paragraph("Executive Summary", styles["h2"]))
    story.append(_count_table(styles, ["Severity", "Count"], sev_counts, SEV_ORDER))
    story.append(Spacer(1, 0.3 * cm))
    story.append(_count_table(styles, ["Category", "Count"], cat_counts, sorted(cat_counts)))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(f"Policy: {policy.get('status', status)} — blockers: {len(blockers)}, warnings: {policy.get('warnings', 0) if isinstance(policy.get('warnings'), int) else 0}", styles["body"]))

    def block(f: dict):
        sev = _sev(f)
        color = SEVERITY_COLORS.get(sev, colors.HexColor("#555555"))
        scanner = f.get("scanner", {}) or {}
        rule = f.get("rule", {}) or {}
        loc = f.get("location") or {}
        kb = _kb_for(f)
        rule_id = str(rule.get("id", "-"))
        header = f"{sev.upper()} | {scanner.get('adapter', '-')}/{scanner.get('tool', '')} | {_short_rule(rule_id)}"
        cwe = rule.get("cwe")
        if isinstance(cwe, list) and cwe:
            header += f" | {cwe[0]}"
        elif isinstance(cwe, str) and cwe:
            header += f" | {cwe}"
        mark = "BLOCKER " if f.get("id") in blockers else ""
        sev_style = ParagraphStyle(f"sev_{sev}_{mark}", parent=styles["body"], fontName="Helvetica-Bold", textColor=color, fontSize=10)
        catego = kb.get("label") or str(f.get("category", "-"))
        cells = [
            Paragraph(_esc(mark + header), sev_style),
            Paragraph(
                _esc(f"Review priority: {_priority(sev)}  ·  Category: {catego}  ·  State: {f.get('baselineState', '-')}"),
                styles["mono"],
            ),
            Paragraph(_esc(f"Where: {_loc(f)}"), styles["mono"]),
            Paragraph(f"<b>What's the risk?</b> {_esc((f.get('message') or '-').strip()[:1200])}", styles["body"]),
        ]
        if kb.get("risk"):
            cells.append(Paragraph(f"<b>Why it matters:</b> {_esc(kb['risk'])}", styles["body"]))
        # Where — code. Key/secret findings never render source (values may be
        # live — note opengrep flags committed PEMs as SAST, not secret);
        # their redacted evidence + rotation guidance carry the section.
        if _sensitive_source(f):
            ev = (f.get("evidence") or {}).get("text") if isinstance(f.get("evidence"), dict) else None
            cells.append(
                Paragraph(
                    _esc(f"Evidence: {ev or '[redacted]'} — value withheld by design; rotate, do not inspect."),
                    styles["mono"],
                )
            )
        else:
            snip = _snippet(src_root or Path("."), str(loc.get("path") or ""), loc.get("startLine"), loc.get("endLine"))
            if snip:
                cells.append(Paragraph(_esc(f"Code (line {snip[0]}+, >> marks flagged lines):"), styles["mono"]))
                cells.append(Preformatted(_esc(snip[1]), styles["code"]))
        art = f.get("artifact") or {}
        if art.get("package"):
            cells.append(
                Paragraph(
                    _esc(f"Package: {art.get('package')} {art.get('installedVersion', '')} → fix: {art.get('fixedVersion') or '-'}"),
                    styles["mono"],
                )
            )
        if kb.get("assess"):
            cells.append(Paragraph("<b>Assess the risk — ask yourself whether:</b>", styles["sect"]))
            for q in kb["assess"]:
                cells.append(Paragraph(f"•  {_esc(q)}", styles["body"]))
        rem = (f.get("remediation") or {}).get("guidance") if isinstance(f.get("remediation"), dict) else None
        fix_text = rem or kb.get("fix") or ""
        if fix_text:
            cells.append(Paragraph(f"<b>How to fix:</b> {_esc(fix_text)}", styles["body"]))
        if kb.get("compliant"):
            cells.append(Preformatted(_esc(kb["compliant"]), styles["code"]))
        refs = list((rule.get("references") or []) if isinstance(rule.get("references"), list) else [])
        refs += [r for r in (kb.get("refs") or []) if r not in refs]
        if refs:
            cells.append(Paragraph(_esc("See: " + "  ·  ".join(str(r)[:110] for r in refs[:5])), styles["mono"]))
        fp = (f.get("fingerprint") or {}).get("value", "-")
        cells.append(Paragraph(_esc(f"Fingerprint: {fp}"), styles["mono"]))
        t = Table([[c] for c in cells], colWidths=[16.5 * cm])
        t.setStyle(
            TableStyle(
                [
                    ("LINEBEFORE", (0, 0), (0, -1), 4, color),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        return t

    ordered = sorted(findings, key=lambda f: (f.get("id") not in blockers, SEV_ORDER.index(_sev(f)) if _sev(f) in SEV_ORDER else 99, _loc(f)))
    story.append(Paragraph(f"Findings — blockers first ({len(ordered)})", styles["h2"]))
    if not ordered:
        story.append(Paragraph("No findings.", styles["body"]))
    for f in ordered:
        story.append(block(f))

    story.append(PageBreak())
    story.append(Paragraph("Appendix — reproducibility", styles["h2"]))
    story.append(
        _meta_table(
            styles,
            [
                ["runId", manifest.get("runId", findings_doc.get("runId", "-"))],
                ["planId", manifest.get("planId", findings_doc.get("planId", "-"))],
                ["planDigest", manifest.get("planDigest", "-")],
                ["contextDigest", manifest.get("contextDigest", "-")],
                ["configDigest", manifest.get("configDigest", "-")],
                ["policyDigest", manifest.get("policyDigest", "-")],
                ["Tasks", "; ".join(f"{t.get('adapter')}:{t.get('state')}" for t in (manifest.get("tasks", []) or [])) or "-"],
                ["Artifacts", "; ".join(f"{a.get('path')} {a.get('checksum', '')[:19]}…" for a in (manifest.get("artifacts", []) or [])) or "-"],
                ["AI used", str((manifest.get("ai") or {}).get("used", False))],
            ],
        )
    )
    story.append(Spacer(1, 0.3 * cm))
    story.append(
        Paragraph(
            "Jenkins: archive the whole reports/ dir always (even on policy_failed). "
            "Reproduce locally by copying SDT_PROFILE/SDT_BASE/SDT_HEAD from the build log. "
            "Trivy offline: TRIVY_OFFLINE_SCAN=true + TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2 avoids Maven Central 429s.",
            styles["small"],
        )
    )

    out.parent.mkdir(parents=True, exist_ok=True)
    SimpleDocTemplate(
        str(out),
        pagesize=A4,
        title="Security Scan Report (sdt)",
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    ).build(story)


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline sdt findings.json -> PDF (no server, deterministic).")
    ap.add_argument("--from", dest="src", default="reports/findings.json", help="canonical findings.json path")
    ap.add_argument("--manifest", default="reports/run-manifest.json", help="run-manifest.json path (optional)")
    ap.add_argument("--out", default="reports/security-report.pdf", help="output PDF path")
    ap.add_argument("--project", default="", help="project label for cover (default: CWD name)")
    ap.add_argument("--profile", default="", help="profile label for cover (default: manifest profile)")
    ap.add_argument("--src-root", default=".", help="source tree for Where-code snippets (default: CWD; secrets never render source)")
    args = ap.parse_args()

    src = Path(args.src)
    if not src.is_file():
        print(f"sdt_to_pdf: findings not found: {src}", file=sys.stderr)
        return 2
    try:
        findings_doc = json.loads(src.read_text())
    except (OSError, ValueError) as exc:
        print(f"sdt_to_pdf: invalid findings.json: {exc}", file=sys.stderr)
        return 2
    manifest: dict = {}
    if args.manifest and Path(args.manifest).is_file():
        try:
            manifest = json.loads(Path(args.manifest).read_text())
        except ValueError as exc:
            print(f"sdt_to_pdf: invalid manifest (continuing without): {exc}", file=sys.stderr)
    project = args.project or Path.cwd().name
    profile = args.profile or str(manifest.get("profile", ""))
    try:
        build_pdf(findings_doc, manifest, project, profile, Path(args.out), Path(args.src_root))
    except Exception as exc:  # never emit a partial PDF silently
        print(f"sdt_to_pdf: build failed: {exc}", file=sys.stderr)
        return 2
    print(f"sdt_to_pdf: wrote {args.out} ({len(findings_doc.get('findings', []))} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
