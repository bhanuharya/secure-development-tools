"""Shared SDT finding knowledge (stdlib-only, no reportlab, no network, no AI).

Single source of truth for offline rendering — imported by tools/sdt_to_pdf.py
(and available to any future renderer/dashboard) so guidance is authored once.

Contents:
  * finding helpers (severity, location, rule display, escaping)
  * a reviewed, versioned knowledge base (risk / assess / fix / refs)
  * source-snippet reading with key-material safety and path confinement

Safety invariants:
  * `sensitive_source()` decides when source must never render (secrets,
    key-material rules, key files); opengrep flags committed PEMs as SAST
    `private-key`, so the category check alone is insufficient.
  * `read_snippet()` confines reads to the selected source root (no ../ escape,
    no symlink escape) and scrubs PEM armor, long high-entropy blobs, and
    sensitive assignment values line-by-line — a live secret must never reach
    an output file even if rule metadata mislabels the finding.
"""

from __future__ import annotations

import re
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

# Bump when knowledge wording/keys change materially; surfaced in reports so an
# auditor can tie a rendered explanation back to a reviewed revision.
KNOWLEDGE_VERSION = "1"

SEV_ORDER = ("critical", "high", "medium", "low", "info")


def escape(text) -> str:
    return _xml_escape("" if text is None else str(text))


def short_rule(rule_id: str, limit: int = 90) -> str:
    """Collapse long vendored prefixes to the meaningful tail."""
    if not rule_id:
        return "-"
    tail = rule_id.split(".")[-1] if "." in rule_id else rule_id.split("/")[-1]
    disp = tail or rule_id
    if len(disp) > limit:
        disp = disp[: limit - 1] + "…"
    return disp


def rule_segments(rule_id: str) -> list[str]:
    """Split a rule id into comparable lowercase segments (`.`/`/` separated)."""
    return [s for s in re.split(r"[./]+", str(rule_id or "").lower().replace("_", "-")) if s]


def location_of(f: dict) -> str:
    loc = f.get("location") or {}
    path = loc.get("path") or (f.get("artifact") or {}).get("target") or "-"
    sl = loc.get("startLine")
    if sl:
        return f"{path}:{sl}"
    return str(path)


def severity_of(f: dict) -> str:
    sev = f.get("severity") or {}
    return str(sev.get("canonical") or sev.get("original") or "info").lower()


def review_priority(sev: str) -> str:
    return {"critical": "High", "high": "High"}.get(sev, "Medium" if sev == "medium" else "Low")


# Reviewed enrichment guidance.
#   `keys`     = exact rule-id segment matches (precise; used for short/ambiguous
#                tokens such as "ssl", "rand", "eval", "xss").
#   `contains` = substring matches within a single segment (descriptive tokens
#                such as "pattern-from-string"). Never matched across segments,
#                so a token cannot hit an unrelated part of a long vendored id.
# `rule.references` / `rule.cwe` from findings.json are appended by the renderer.
KNOWLEDGE = [
    {
        "keys": ["private-key", "privatekey"],
        "contains": [],
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
        "keys": ["api-key", "generic-api-key", "sendinblue-api-token", "aws-access-token", "aws-access-key-id"],
        "contains": ["secret"],
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
        "keys": ["rand", "random"],
        "contains": ["pseudorandom", "predictable-random", "weak-random", "insecure-random", "std-random", "math-random"],
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
        "keys": ["no-string-eqeq", "string-eqeq"],
        "contains": [],
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
        "keys": ["eqeq", "assignment-comparison", "hardcoded-conditional"],
        "contains": [],
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
        "keys": ["redos", "regex-dos", "regex-injection"],
        "contains": ["pattern-from-string"],
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
        "keys": ["xxe", "xmlinputfactory", "external-entities", "saxparser", "documentbuilder"],
        "contains": [],
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
        "keys": ["sqli", "sql-injection", "tainted-sql"],
        "contains": [],
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
        "keys": ["eval", "os-exec", "system-call", "spawn-process", "subprocess", "code-run", "command-injection", "dangerous-globals"],
        "contains": [],
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
        "keys": ["pickle", "jackson", "snakeyaml", "jms-deserialization"],
        "contains": ["deserialization", "yaml-load", "unsafe-load"],
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
        "keys": ["ssrf", "open-redirect", "zip-slip", "path-traversal", "filepath-clean", "decompression-bomb", "url-host"],
        "contains": [],
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
        "keys": ["xss", "raw-html"],
        "contains": ["servletresponse-writer", "template-string", "html-in-template"],
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
        "keys": ["md5", "sha1", "ecb", "null-cipher", "uuid-version"],
        "contains": ["weak-hash", "insecure-hash", "deprecated", "defaulthttpclient"],
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
        "keys": ["ssl", "tls", "verify", "hostname-verification", "unverified", "truststore", "socket", "csrf", "cors"],
        "contains": ["cookie-missing", "skip-tls-verify"],
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
        "keys": ["privileged", "allow-privilege", "run-as-non-root", "hostpid", "hostipc", "hostnetwork", "seccomp", "writable-filesystem", "secrets-in-config", "docker-socket"],
        "contains": [],
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
        "keys": ["github-actions", "workflow", "script-injection", "mutable-action-tag", "pull-request-target", "secrets-inherit", "curl-pipe-shell", "shai-hulud", "prompt-injection", "staged-publishing"],
        "contains": [],
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
    "image-vulnerability": {
        "label": "Vulnerable Image",
        "risk": "A known CVE in a base image or OS package. The CVE description carries the concrete impact.",
        "assess": ["Is the vulnerable component reachable at runtime?", "Is a patched base image available?"],
        "fix": "Rebuild on a patched base image and re-pin the digest.",
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

# CWE-based fallback used only for code-level findings (SAST/secret) when no
# rule segment matched. Dependency/image/misconfiguration findings keep their
# category guidance (the actionable fix is "upgrade"/"tighten"), so CWE is not
# applied there.
_CWE_INDEX = {
    "CWE-798": 0,
    "CWE-89": 7,
    "CWE-78": 8,
    "CWE-94": 8,
    "CWE-502": 9,
    "CWE-611": 6,
    "CWE-79": 11,
    "CWE-1333": 5,
    "CWE-338": 2,
    "CWE-330": 2,
    "CWE-327": 12,
    "CWE-328": 12,
}

_CATEGORY_GUIDANCE_FIRST = ("dependency-vulnerability", "image-vulnerability", "misconfiguration")


def _cwe_first(f: dict) -> str:
    cwe = (f.get("rule") or {}).get("cwe")
    if isinstance(cwe, list) and cwe:
        token = str(cwe[0]).strip()
    elif isinstance(cwe, str):
        token = cwe.strip()
    else:
        return ""
    m = re.match(r"(CWE-\d+)", token, re.IGNORECASE)
    return m.group(1).upper() if m else ""


def _segment_match(entry: dict, segs: list[str]) -> bool:
    if any(tok in segs for tok in entry["keys"]):
        return True
    return any(tok in seg for tok in entry["contains"] for seg in segs)


def knowledge_for(f: dict):
    """Resolve reviewed guidance for a finding.

    Deterministic lookup order:
      1. dependency/image/misconfiguration -> their category guidance;
      2. exact/segment rule-id match, then CWE mapping (SAST/secret);
      3. category fallback.
    Tokens are matched against individual rule-id segments, never the whole id.
    """
    cat = f.get("category")
    if cat in _CATEGORY_GUIDANCE_FIRST:
        return CATEGORY_FALLBACK.get(cat, DEFAULT_KB)
    segs = rule_segments((f.get("rule") or {}).get("id", ""))
    for entry in KNOWLEDGE:
        if _segment_match(entry, segs):
            return entry
    mapped = _CWE_INDEX.get(_cwe_first(f))
    if mapped is not None:
        return KNOWLEDGE[mapped]
    return CATEGORY_FALLBACK.get(cat, DEFAULT_KB)


_KEY_EXTS = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".asc", ".gpg", ".ppk")


def sensitive_source(f: dict) -> bool:
    """True when source must never render: secrets, key-material rules, key files.

    Opengrep flags committed PEMs as SAST `private-key` (not `secret`), so the
    category check alone is insufficient — match rule segments + file extension too.
    """
    if f.get("category") == "secret":
        return True
    segs = rule_segments((f.get("rule") or {}).get("id", ""))
    for tok in ("private-key", "privatekey", "api-key", "secret", "password", "token", "credential"):
        if any(tok in seg for seg in segs):
            return True
    loc = f.get("location") or {}
    return str(loc.get("path", "")).lower().endswith(_KEY_EXTS)


_ARMOR_RE = re.compile(r"-----(BEGIN|END) [A-Z0-9 ]*?(PRIVATE KEY|PUBLIC KEY|CERTIFICATE|OPENSSH PRIVATE KEY)-----")
_BLOB_RE = re.compile(r"[A-Za-z0-9+/=_\-]{48,}")
# key=value / key: value where the key name is security-sensitive.
_ASSIGN_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key"
    r"|credential|client[_-]?secret|auth[_-]?token)\b(\s*[:=]\s*)(\S+)"
)


def _scrub(line: str) -> str:
    if _ARMOR_RE.search(line):
        return "[redacted: key armor withheld — rotate, do not inspect]"
    line = _ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", line)
    if _BLOB_RE.search(line):
        line = _BLOB_RE.sub("[redacted]", line)
    return line


def read_snippet(src_root: Path, path: str, start, end, context: int = 6, cap_lines: int = 16) -> list | None:
    """Read source context for Where-sections. Never raises.

    Confines reads to `src_root` (resolved, so symlink escape is refused) and
    scrubs key material line-by-line as defense-in-depth. Returns
    [first_lineno, rendered_text] or None.
    """
    try:
        if not path or path == "-":
            return None
        root = Path(src_root).resolve()
        p = (root / path) if not str(path).startswith("/") else Path(path)
        p = p.resolve()
        if p != root and root not in p.parents:
            return None
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
