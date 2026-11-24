#!/usr/bin/env python3
"""Optional AI review of what a pull request changes, for the problems rules do not find.

Pattern scanners are good at known-bad calls and weak at logic: an endpoint added without a
permission check, a record fetched by id without checking its owner, a validation that was
dropped, a double-spend race, or a violated business invariant. This sends the changed lines of a
pull request — enriched with resolved HTTP route protection (endpoints.json), matching domain
invariants (.secure-dev/invariants.yaml), and 1-hop local callee definitions — to Codex and asks
only for security problems the change introduces.

The answer is advice for the reviewer of the pull request (ai-change-review.json and .md): it
never blocks a build, never enters SonarQube, and every item must point at a line the change added.

Off unless SDT_AI_DIFF_REVIEW=1. Guardrails are the ones of sdt_triage_codex.py: likely secret
values are redacted before sending; Codex runs non-interactively in a read-only sandbox, in an
empty directory, with an enforced JSON answer; per-call timeout, whole-run budget, and a stop
after repeated failures. Lock files, tests, generated and binary files are not sent.

  python3 tools/sdt_review_diff.py --src-root source --base origin/main \\
      --endpoints reports/endpoints.json \\
      --out out/ai-change-review.json --markdown out/ai-change-review.md
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - stdlib fallback parser handles simple invariants YAML
    yaml = None

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sdt_triage_codex  # noqa: E402  (the same Codex call and limits)
from sdt_advisory import redact  # noqa: E402

SEVERITIES = ("high", "medium", "low")
CONFIDENCE = ("low", "medium", "high")
ABUSE_CLASSES = (
    "bola-idor",
    "bfla-authz",
    "mass-assignment",
    "race-double-spend",
    "state-machine",
    "maker-checker",
    "numeric-integrity",
    "replay-webhook-otp",
    "tenant-isolation",
    "trust-boundary",
    "injection-or-ssrf",
    "other",
)
MAX_TEXT = 500
CONTEXT = 12            # unchanged lines shown around each change
MAX_FILE_LINES = 400    # of numbered diff per file; a larger change is cut and reported as partial
MAX_CALL_CHARS = 28000  # of numbered diff + context per Codex call
MAX_CALLEE_SNIPPETS = 4
MAX_CALLEE_LINES = 30

CODE_FILE = re.compile(r"\.(js|jsx|mjs|cjs|ts|tsx|vue|svelte|py|go|java|kt|kts|dart|swift|php|rb|cs|rs|scala|sql|"
                       r"ya?ml|json|tf|sh|gradle|xml|properties|env)$|(^|/)Dockerfile[^/]*$", re.IGNORECASE)
NOT_REVIEWED = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|mocks?|node_modules|vendor|dist|build|generated)/|"
                          r"\.(test|spec)\.[^/]+$|_test\.(go|dart)$|\.min\.[^/]+$|\.lock$|-lock\.(json|ya?ml)$|"
                          r"(^|/)(package-lock\.json|go\.sum|pubspec\.lock)$", re.IGNORECASE)
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

HIGH_RISK_PATH = re.compile(
    r"(?i)(auth|login|oauth|jwt|session|token|otp|pin|password|security|rbac|acl|guard|middleware|policy|"
    r"route|router|controller|handler|payment|payout|ledger|wallet|transfer|withdraw|disburs|refund|"
    r"billing|checkout|order|account|admin|backoffice|webhook|callback|tenant|invoice)"
)
REMOVED_GUARD = re.compile(
    r"(?i)^-(?!-).*\b(auth|jwt|role|admin|owner|tenant|principal|guard|protect|verify|check|validate|"
    r"permit|deny|for\s+update|lock|idempoten|csrf|hmac|signature|preauthorize|secured|rolesallowed)\b",
    re.MULTILINE,
)
CALL_IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")
BORING_CALLS = frozenset({
    "if", "for", "while", "switch", "catch", "return", "sizeof", "len", "cap", "make", "new",
    "append", "copy", "delete", "close", "panic", "print", "printf", "println", "sprintf", "errorf",
    "log", "info", "warn", "error", "debug", "format", "string", "int", "float", "bool", "str",
    "dict", "list", "set", "tuple", "range", "enumerate", "isinstance", "getattr", "setattr",
    "require", "import", "console", "json", "parse", "stringify", "map", "filter", "reduce",
    "foreach", "push", "pop", "slice", "split", "join", "trim", "replace", "match", "test",
    "get", "post", "put", "patch", "head", "options", "use", "status", "send", "next", "super",
    "tostring", "equals", "hashcode", "valueof", "stream", "collect", "orelse", "orelsethrow",
})

RESPONSE_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["findings"],
    "properties": {"findings": {"type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": ["path", "line", "title", "severity", "confidence", "abuse_class",
                     "attack_scenario", "evidence", "check", "fix"],
        "properties": {
            "path": {"type": "string"},
            "line": {"type": "integer"},
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": list(SEVERITIES)},
            "confidence": {"type": "string", "enum": list(CONFIDENCE)},
            "abuse_class": {"type": "string", "enum": list(ABUSE_CLASSES)},
            "attack_scenario": {"type": "string"},
            "evidence": {"type": "string"},
            "check": {"type": "string"},
            "fix": {"type": "string"},
        }}}},
}

VERIFY_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["decisions"],
    "properties": {"decisions": {"type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": ["index", "exploitable", "reason"],
        "properties": {
            "index": {"type": "integer"},
            "exploitable": {"type": "boolean"},
            "reason": {"type": "string"},
        }}}},
}


def reviewable(path: str) -> bool:
    return bool(CODE_FILE.search(path)) and not NOT_REVIEWED.search(path)


def numbered_diff(diff: str) -> tuple[str, set[int], bool]:
    """A unified diff as numbered lines of the new file, the added line numbers, and whether it was cut.

    Added lines read "+  123 | code", unchanged "   122 | code", removed "-      | code", so the
    reviewer can name a line of the file as it is after the change.
    """
    out, added, line = [], set(), 0
    for raw in diff.splitlines():
        hunk = HUNK.match(raw)
        if hunk:
            line = int(hunk.group(1))
            out.append("   ...")
        elif not line or raw.startswith(("+++", "---", "\\")):
            continue
        elif raw.startswith("+"):
            out.append(f"+{line:>5} | {raw[1:].rstrip()[:220]}")
            added.add(line)
            line += 1
        elif raw.startswith("-"):
            out.append(f"-      | {raw[1:].rstrip()[:220]}")
        else:
            out.append(f" {line:>5} | {raw[1:].rstrip()[:220]}")
            line += 1
        if len(out) >= MAX_FILE_LINES:
            return redact("\n".join(out)), added, True
    return redact("\n".join(out)), added, False


def load_endpoint_context(path: Path | None) -> dict[str, list[dict]]:
    """Index resolved HTTP routes from endpoints.json by relative source file path."""
    if not path or not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    routes = doc.get("routes") if isinstance(doc, dict) else None
    if not isinstance(routes, list):
        return {}
    by_file: dict[str, list[dict]] = {}
    for rt in routes:
        if not isinstance(rt, dict):
            continue
        file_path = str(rt.get("file") or "").lstrip("./")
        if not file_path:
            continue
        by_file.setdefault(file_path, []).append({
            "method": str(rt.get("method") or ""),
            "path": str(rt.get("externalPath") or rt.get("path") or ""),
            "protection": str(rt.get("protection") or ""),
            "roles": [str(r) for r in (rt.get("roles") or []) if isinstance(r, str)],
            "handler": str(rt.get("handler") or ""),
            "line": int(rt.get("line") or 0),
            "upstreamAuth": str(rt.get("upstreamAuth") or ""),
        })
    return by_file


def _parse_invariants_fallback(raw: str) -> list[dict]:
    """Minimal stdlib parser for domainInvariants when PyYAML is not installed."""
    out: list[dict] = []
    in_domain = False
    cur: dict | None = None
    in_statement = False
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            in_domain = stripped.startswith("domainInvariants:")
            in_statement = False
            continue
        if not in_domain:
            continue
        if stripped.startswith("- id:"):
            if cur:
                out.append(cur)
            cur = {"id": stripped.split(":", 1)[1].strip().strip("\"'"), "paths": [], "abuseClasses": [], "statement": "", "severity": "high"}
            in_statement = False
            continue
        if cur is None:
            continue
        if in_statement and line.startswith("      "):
            cur["statement"] = (cur["statement"] + " " + stripped).strip()
            continue
        in_statement = False
        if stripped.startswith("paths:"):
            val = stripped.split(":", 1)[1].strip()
            if val.startswith("[") and val.endswith("]"):
                cur["paths"] = [p.strip().strip("\"'") for p in val[1:-1].split(",") if p.strip()]
        elif stripped.startswith("abuseClasses:"):
            val = stripped.split(":", 1)[1].strip()
            if val.startswith("[") and val.endswith("]"):
                cur["abuseClasses"] = [p.strip().strip("\"'") for p in val[1:-1].split(",") if p.strip()]
        elif stripped.startswith("severity:"):
            cur["severity"] = stripped.split(":", 1)[1].strip().strip("\"'")
        elif stripped.startswith("statement:"):
            val = stripped.split(":", 1)[1].strip()
            if val in (">-", ">", "|-", "|"):
                in_statement = True
            else:
                cur["statement"] = val.strip("\"'")
    if cur:
        out.append(cur)
    return [d for d in out if d.get("id") and d.get("paths") and d.get("statement")]


def load_domain_invariants(src_root: Path | None, explicit: Path | None = None) -> list[dict]:
    """Load semantic domainInvariants from .secure-dev/invariants.yaml when present."""
    path = explicit
    if path is None and src_root is not None:
        candidate = src_root / ".secure-dev" / "invariants.yaml"
        if candidate.is_file():
            path = candidate
    if not path or not path.is_file():
        return []
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return []
    if yaml is not None:
        try:
            doc = yaml.safe_load(raw) or {}
        except Exception:
            return []
        items = doc.get("domainInvariants") if isinstance(doc, dict) else None
        if not isinstance(items, list):
            return []
        out = []
        for item in items:
            if not isinstance(item, dict):
                continue
            inv_id = str(item.get("id") or "").strip()
            paths = [str(p) for p in (item.get("paths") or []) if isinstance(p, str) and p.strip()]
            stmt = " ".join(str(item.get("statement") or "").split())
            if inv_id and paths and stmt:
                out.append({
                    "id": inv_id,
                    "paths": paths,
                    "abuseClasses": [str(a) for a in (item.get("abuseClasses") or []) if isinstance(a, str)],
                    "statement": stmt,
                    "severity": str(item.get("severity") or "high"),
                })
        return out
    return _parse_invariants_fallback(raw)


def _glob_matches(path: str, pattern: str) -> bool:
    norm_path = path.lstrip("./")
    norm_pat = pattern.lstrip("./")
    if fnmatch.fnmatch(norm_path, norm_pat):
        return True
    if norm_pat.endswith("/**"):
        prefix = norm_pat[:-3].rstrip("/")
        return norm_path == prefix or norm_path.startswith(prefix + "/")
    if "**/" in norm_pat:
        tail = norm_pat.split("**/", 1)[1]
        if fnmatch.fnmatch(norm_path, tail) or fnmatch.fnmatch(Path(norm_path).name, tail):
            return True
    return False


def match_domain_invariants(invariants: list[dict], path: str) -> list[dict]:
    return [inv for inv in invariants if any(_glob_matches(path, pat) for pat in inv.get("paths", []))]


def _confined_read(src_root: Path, rel: str) -> str | None:
    try:
        root = src_root.resolve()
        target = (root / rel).resolve()
        if root not in target.parents or not target.is_file():
            return None
        return target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _extract_symbol_snippet(text: str, symbol: str, rel_path: str = "", max_lines: int = MAX_CALLEE_LINES) -> str | None:
    """Find a local function/method definition for `symbol` and return up to max_lines."""
    ext = Path(rel_path).suffix.lower()
    sym = re.escape(symbol)
    if ext == ".py":
        patterns = (re.compile(rf"(?m)^[ \t]*(?:async[ \t]+)?def[ \t]+{sym}\s*\("),)
    elif ext == ".go":
        patterns = (re.compile(rf"(?m)^func[ \t]+(?:\([^)]*\)[ \t]+)?{sym}\s*\("),)
    elif ext in (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"):
        patterns = (
            re.compile(rf"(?m)^[ \t]*(?:export[ \t]+)?(?:async[ \t]+)?function[ \t]+{sym}\s*\("),
            re.compile(rf"(?m)^[ \t]*(?:export[ \t]+)?(?:const|let|var)[ \t]+{sym}\s*=\s*(?:async[ \t]+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"),
        )
    elif ext in (".kt", ".kts"):
        patterns = (re.compile(rf"(?m)^[ \t]*(?:(?:public|private|protected|internal|override|suspend|inline)[ \t]+)*fun[ \t]+(?:<[^>]+>[ \t]+)?{sym}\s*\("),)
    else:
        patterns = (
            re.compile(rf"(?m)^[ \t]*(?:(?:public|private|protected|static|final|synchronized)[ \t]+)+(?:[\w<>, \[\]?]+[ \t]+)+{sym}\s*\("),
        )
    lines = text.splitlines()
    for pat in patterns:
        m = pat.search(text)
        if not m:
            continue
        start_line = text[:m.start()].count("\n")
        end_line = min(len(lines), start_line + max_lines)
        snippet = "\n".join(f" {n + 1:>5} | {lines[n][:200]}" for n in range(start_line, end_line))
        return redact(snippet)
    return None


def collect_callee_context(src_root: Path | None, rel_path: str, diff_text: str) -> list[tuple[str, str]]:
    """Collect up to MAX_CALLEE_SNIPPETS 1-hop local function definitions referenced by added lines."""
    if not src_root:
        return []
    added_lines = [ln[1:] for ln in diff_text.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    if not added_lines:
        return []
    candidates: list[str] = []
    seen: set[str] = set()
    for ln in added_lines:
        for name in CALL_IDENT.findall(ln):
            low = name.lower()
            if low in BORING_CALLS or name in seen:
                continue
            seen.add(name)
            candidates.append(name)
    if not candidates:
        return []

    search_files: list[str] = [rel_path]
    try:
        root = src_root.resolve()
        parent = (root / rel_path).resolve().parent
        ext = Path(rel_path).suffix
        if parent == root or root in parent.parents:
            for sib in sorted(parent.iterdir()):
                if sib.is_file() and sib.suffix == ext:
                    sib_rel = sib.relative_to(root).as_posix()
                    if sib_rel != rel_path and reviewable(sib_rel):
                        search_files.append(sib_rel)
                        if len(search_files) >= 8:
                            break
    except OSError:
        pass

    file_texts: dict[str, str] = {}
    for f in search_files:
        content = _confined_read(src_root, f)
        if content is not None:
            file_texts[f] = content

    out: list[tuple[str, str]] = []
    for sym in candidates:
        if len(out) >= MAX_CALLEE_SNIPPETS:
            break
        for f, content in file_texts.items():
            snippet = _extract_symbol_snippet(content, sym, f)
            if snippet:
                out.append((f"{f} ({sym})", snippet))
                break
    return out


def risk_score(path: str, diff_text: str, routes_by_file: dict[str, list[dict]], invariants: list[dict]) -> int:
    """Rank changed files by business-logic & access-control risk so high-risk files are always reviewed first."""
    score = 0
    if match_domain_invariants(invariants, path):
        score += 5
    if REMOVED_GUARD.search(diff_text):
        score += 4
    if routes_by_file.get(path.lstrip("./")):
        score += 3
    if HIGH_RISK_PATH.search(path):
        score += 2
    return score


def format_file_context(path: str, routes_by_file: dict[str, list[dict]], invariants: list[dict],
                        callees: list[tuple[str, str]]) -> str:
    sections: list[str] = []
    routes = routes_by_file.get(path.lstrip("./")) or []
    if routes:
        lines = []
        for r in routes[:20]:
            roles = f" roles={r['roles']}" if r["roles"] else ""
            upstream = f" upstreamAuth={r['upstreamAuth']!r}" if r["upstreamAuth"] else ""
            lines.append(f"- {r['method']} {r['path']} (line {r['line']}, handler {r['handler']}, protection={r['protection']}{roles}{upstream})")
        sections.append("Resolved HTTP routes in this file (from endpoints.json):\n" + redact("\n".join(lines)))
    matched = match_domain_invariants(invariants, path)
    if matched:
        lines = [f"- [{inv['id']}] ({inv.get('severity', 'high')}) {inv['statement']}" for inv in matched]
        sections.append("Repository security invariants that MUST hold for this file:\n" + redact("\n".join(lines)))
    if callees:
        blocks = [f"// Referenced helper: {label}\n{snippet}" for label, snippet in callees]
        sections.append("1-hop local helper definitions referenced by added lines:\n```\n" + "\n\n".join(blocks) + "\n```")
    return "\n\n".join(sections)


def build_prompt(files: list[tuple[str, str]], contexts: dict[str, str] | None = None) -> str:
    contexts = contexts or {}
    parts = []
    for path, text in files:
        extra = contexts.get(path, "")
        block = f"### {path}\n```\n{text}\n```"
        if extra:
            block += "\n\n" + extra
        parts.append(block)
    blocks = "\n\n".join(parts)
    classes = ", ".join(ABUSE_CLASSES)
    return f"""You are a senior application security reviewer auditing the changes of one pull request for logic abuse and access-control flaws.
Pattern-based scanners already ran. Report only what they miss: security or business-logic problems that this
change INTRODUCES or makes reachable. Focus specifically on:
- BOLA / IDOR (bola-idor): a record read, changed or deleted by an id from the request without binding it to the caller or tenant;
- BFLA / authz (bfla-authz): a new or changed endpoint, route, job or handler missing authentication, role, or permission checks (or dropping an existing check);
- Mass assignment (mass-assignment): copying client request fields (role, status, price, discount, balance, isAdmin) into persisted records;
- Race conditions / double-spend (race-double-spend): check-then-act on balances, quotas, coupons, inventory, or single-use tokens without row locking or atomic conditional updates;
- State-machine & maker-checker bypass (state-machine, maker-checker): skipping prior-state checks or allowing requester == approver on sensitive transitions;
- Numeric / financial integrity (numeric-integrity): negative/zero/NaN amounts, client-trusted prices/discounts, or float rounding abuse;
- Replay / webhook / OTP abuse (replay-webhook-otp): unverified webhook HMACs, non-expiring or reusable OTPs/tokens, weak PRNG;
- Multi-tenant isolation & trust boundaries (tenant-isolation, trust-boundary): cross-tenant leaks, spoofable identity headers, weakened CORS/cookie/TLS/rate-limit/pagination bounds;
- Unvalidated input reaching queries, commands, paths, URLs, or HTML (injection-or-ssrf).

If repository security invariants are listed below a file, explicitly verify whether the diff violates any of them.

Rules:
- Lines starting with "+" were added, "-" removed, the rest is unchanged context. Numbers are
  line numbers in the file after the change.
- Every finding must point at an added ("+") line: path exactly as in the heading, line as shown.
- Report a problem only when the code and context shown concretely support an exploitable scenario.
  No style, naming, performance or test remarks, and nothing a linter would say. An empty list is a good answer.
- abuse_class: one of [{classes}].
- attack_scenario: one or two concrete sentences describing the step-by-step abuse (who sends what request/sequence and what unauthorized state results).
- evidence: one or two sentences naming the lines and identifiers that show the problem.
- check: the ONE thing the reviewer verifies to confirm or dismiss it (name the file or function).
- fix: one short concrete change.
- You have no tools; use only the code and context shown. Values shown as [REDACTED] were removed on purpose.

{blocks}
"""


def build_verify_prompt(findings: list[dict], diff_map: dict[str, str], contexts: dict[str, str]) -> str:
    items = []
    for idx, f in enumerate(findings):
        path = f["path"]
        ctx = contexts.get(path, "")
        items.append(
            f"### Finding {idx}: {f['title']} ({f['severity']}, {f.get('abuse_class') or 'other'})\n"
            f"- Location: {path}:{f['line']}\n"
            f"- Claimed attack scenario: {f.get('attack_scenario') or f['evidence']}\n"
            f"- Claimed evidence: {f['evidence']}\n"
            f"Diff:\n```\n{diff_map.get(path, '')[:6000]}\n```"
            + (f"\nContext:\n{ctx[:3000]}" if ctx else "")
        )
    joined = "\n\n".join(items)
    return f"""You are a sceptical principal security engineer verifying candidate logic-abuse findings from a PR review.
Your job is to REJECT speculative or non-exploitable findings so developers only see high-signal issues.
For each finding index, decide exploitable=true ONLY if the diff and context genuinely allow the claimed attack
without contradicting an existing guard, lock, role check, or ownership filter shown in the code.
Answer every index exactly once.

{joined}
"""


def validate(answer: object, added: dict[str, set[int]]) -> list[dict]:
    """Well-formed findings on a line the change added; anything else is dropped."""
    if not isinstance(answer, dict) or not isinstance(answer.get("findings"), list):
        raise ValueError("answer has no findings list")
    out = []
    for item in answer["findings"]:
        if not isinstance(item, dict):
            continue
        path, line = str(item.get("path", "")), item.get("line")
        if path not in added or not isinstance(line, int) or line not in added[path]:
            continue
        if item.get("severity") not in SEVERITIES or item.get("confidence") not in CONFIDENCE:
            continue
        clean = {key: " ".join(str(item.get(key, "")).split())[:MAX_TEXT]
                 for key in ("title", "evidence", "check", "fix", "attack_scenario")}
        abuse_class = str(item.get("abuse_class") or "").strip().lower()
        if abuse_class not in ABUSE_CLASSES:
            abuse_class = ""
        if clean["title"] and clean["evidence"]:
            entry = {
                "path": path, "line": line,
                "severity": item["severity"], "confidence": item["confidence"],
                "title": clean["title"], "evidence": clean["evidence"],
                "check": clean["check"], "fix": clean["fix"],
            }
            if abuse_class:
                entry["abuse_class"] = abuse_class
            if clean["attack_scenario"]:
                entry["attack_scenario"] = clean["attack_scenario"]
            out.append(entry)
    return out


def batches(files: list[tuple[str, str]], contexts: dict[str, str] | None = None) -> list[list[tuple[str, str]]]:
    """Files grouped so one call stays under MAX_CALL_CHARS (a single large file goes alone)."""
    contexts = contexts or {}
    groups, current, size = [], [], 0
    for path, text in files:
        item_size = len(text) + len(contexts.get(path, ""))
        if current and size + item_size > MAX_CALL_CHARS:
            groups.append(current)
            current, size = [], 0
        current.append((path, text))
        size += item_size
    return groups + ([current] if current else [])


EFFORTS = ("minimal", "low", "medium", "high", "max", "inherit")


def apply_diff_reasoning(env=None) -> str:
    """The change review's reasoning depth: SDT_AI_DIFF_REASONING when set, else the finding
    triage's SDT_CODEX_REASONING (default medium). Set for this process only, so the triage keeps
    its own depth. Returns the depth in use."""
    env = os.environ if env is None else env
    own = env.get("SDT_AI_DIFF_REASONING", "").strip().lower()
    if own in EFFORTS:
        env["SDT_CODEX_REASONING"] = own
    elif own:
        print(f"sdt_review_diff: SDT_AI_DIFF_REASONING={own!r} is not one of {', '.join(EFFORTS)}; ignored",
              file=sys.stderr)
    return env.get("SDT_CODEX_REASONING", "medium")


def verify_findings(findings: list[dict], diff_map: dict[str, str], contexts: dict[str, str],
                    codex: str, model: str, *, timeout: float,
                    call=sdt_triage_codex.run_codex) -> tuple[list[dict], int]:
    """Run a sceptical verification pass over high/medium findings; returns (kept, dropped)."""
    if not findings:
        return findings, 0
    to_check = [(i, f) for i, f in enumerate(findings) if f.get("severity") in ("high", "medium")]
    if not to_check:
        return findings, 0
    candidates = [f for _, f in to_check]
    answer = call(codex, model, build_verify_prompt(candidates, diff_map, contexts), timeout, VERIFY_SCHEMA)
    if not isinstance(answer, dict) or not isinstance(answer.get("decisions"), list):
        return findings, 0
    decided: dict[int, bool] = {}
    for d in answer["decisions"]:
        if isinstance(d, dict) and isinstance(d.get("index"), int) and isinstance(d.get("exploitable"), bool):
            decided[d["index"]] = d["exploitable"]
    check_idx = {orig_i: pos for pos, (orig_i, _) in enumerate(to_check)}
    kept, dropped = [], 0
    for orig_i, f in enumerate(findings):
        pos = check_idx.get(orig_i)
        if pos is None:
            kept.append(f)
            continue
        if decided.get(pos, True):
            item = dict(f)
            item["verified"] = True
            kept.append(item)
        else:
            dropped += 1
    return kept, dropped


def review(diffs: dict[str, str], codex: str, model: str, *, per_call_timeout: float, budget: float,
           max_failures: int = 2, call=sdt_triage_codex.run_codex, clock=time.monotonic,
           src_root: Path | None = None, routes_by_file: dict[str, list[dict]] | None = None,
           invariants: list[dict] | None = None, verify: bool = False) -> dict:
    """Review the per-file diffs; ``diffs`` maps path -> unified diff."""
    routes_by_file = routes_by_file or {}
    invariants = invariants or []
    report = {"engine": "codex", "model": model, "advisory": True,
              "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "files_reviewed": [], "files_partial": [], "calls": 0, "failed_calls": 0,
              "stopped": "", "findings": [], "dropped_by_verifier": 0}
    files, added, contexts, diff_map = [], {}, {}, {}
    ranked_paths = sorted(
        diffs,
        key=lambda p: (-risk_score(p, diffs[p], routes_by_file, invariants), p),
    )
    for path in ranked_paths:
        text, lines, cut = numbered_diff(diffs[path])
        if not lines:
            continue
        files.append((path, text))
        added[path] = lines
        diff_map[path] = text
        callees = collect_callee_context(src_root, path, diffs[path])
        ctx_text = format_file_context(path, routes_by_file, invariants, callees)
        if ctx_text:
            contexts[path] = ctx_text
        if cut:
            report["files_partial"].append(path)
    started, failures = clock(), 0
    for group in batches(files, contexts):
        remaining = budget - (clock() - started)
        if remaining < 10:
            report["stopped"] = "time budget spent"
            break
        report["calls"] += 1
        try:
            answer = call(codex, model, build_prompt(group, contexts), min(per_call_timeout, remaining), RESPONSE_SCHEMA)
            found = validate(answer, {path: added[path] for path, _ in group})
        except (subprocess.TimeoutExpired, RuntimeError, ValueError, OSError) as exc:
            failures += 1
            report["failed_calls"] += 1
            reason = "timed out" if isinstance(exc, subprocess.TimeoutExpired) else str(exc)
            print(f"sdt_review_diff: {reason[:200]}", file=sys.stderr)
            if failures >= max_failures:
                report["stopped"] = f"{failures} consecutive failed calls"
                break
            continue
        failures = 0
        report["files_reviewed"] += [path for path, _ in group]
        report["findings"] += found

    if verify and report["findings"]:
        remaining = budget - (clock() - started)
        if remaining >= 15:
            report["calls"] += 1
            try:
                kept, dropped = verify_findings(
                    report["findings"], diff_map, contexts, codex, model,
                    timeout=min(per_call_timeout, remaining), call=call,
                )
                report["findings"] = kept
                report["dropped_by_verifier"] = dropped
            except (subprocess.TimeoutExpired, RuntimeError, ValueError, OSError) as exc:
                report["failed_calls"] += 1
                print(f"sdt_review_diff: verifier failed ({str(exc)[:160]}), keeping unverified findings", file=sys.stderr)

    order = {s: n for n, s in enumerate(SEVERITIES)}
    report["findings"].sort(key=lambda f: (order[f["severity"]], f["path"], f["line"]))
    return report


def markdown(report: dict, base: str, skipped: int, over_limit: int = 0) -> str:
    lines = ["# AI review of this change (advisory)", "",
             f"Model `{report['model']}`"
             + (f" (reasoning {report['reasoning']})" if report.get("reasoning") else "")
             + f" read {len(report['files_reviewed'])} changed files against `{base}` "
             f"and reported {len(report['findings'])} possible security problems. {skipped} changed files were "
             "not sent (tests, lock files, generated or non-code files).",
             "This is advice for the reviewer: confirm each item in the code before acting on it. "
             "No finding here blocks the build or enters SonarQube.", ""]
    if report.get("dropped_by_verifier"):
        lines += [f"A sceptical verification pass dismissed {report['dropped_by_verifier']} speculative candidate(s).", ""]
    if over_limit:
        lines += [f"{over_limit} more changed code files were NOT read: the change is larger than the per-review "
                  "file limit (highest-risk files were prioritized). Review those by hand.", ""]
    if report["files_partial"]:
        lines += ["Only the first part of these large changes was read: " + ", ".join(report["files_partial"]) + ".", ""]
    if report["stopped"]:
        lines += [f"The review stopped early ({report['stopped']}); files not listed above were not read.", ""]
    for n, f in enumerate(report["findings"], 1):
        cls = f" [{f['abuse_class']}]" if f.get("abuse_class") else ""
        lines += [f"## {n}. {f['title']}{cls}", "",
                  f"- **Where:** `{f['path']}:{f['line']}`",
                  f"- **Severity:** {f['severity']} (confidence {f['confidence']})"
                  + (" · verified" if f.get("verified") else "")]
        if f.get("attack_scenario"):
            lines.append(f"- **Attack scenario:** {f['attack_scenario']}")
        lines += [f"- **Evidence:** {f['evidence']}", f"- **Check:** {f['check']}", f"- **Fix:** {f['fix']}", ""]
    if not report["findings"]:
        lines += ["No security problems were found in the changed lines.", ""]
    return "\n".join(lines)


def git(src_root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(src_root), *args], capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"git {args[0]} failed: {result.stderr.strip()[:200]}")
    return result.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description="Optional Codex review of a pull request's changes (advisory).")
    ap.add_argument("--src-root", type=Path, required=True)
    ap.add_argument("--base", required=True, help="what the change is compared with, e.g. origin/main")
    ap.add_argument("--out", type=Path, required=True, help="ai-change-review.json to write (only when Codex ran)")
    ap.add_argument("--markdown", type=Path, help="also write the review as Markdown")
    ap.add_argument("--endpoints", type=Path, help="optional endpoints.json to enrich prompts with route protection")
    ap.add_argument("--invariants", type=Path, help="optional invariants.yaml (defaults to <src-root>/.secure-dev/invariants.yaml)")
    ap.add_argument("--verify", action="store_true",
                    default=os.environ.get("SDT_AI_DIFF_VERIFY", "0") == "1",
                    help="run a sceptical verification pass over high/medium findings (or set SDT_AI_DIFF_VERIFY=1)")
    ap.add_argument("--codex", default="")
    ap.add_argument("--model", default=os.environ.get("SDT_CODEX_MODEL", sdt_triage_codex.DEFAULT_MODEL))
    ap.add_argument("--per-call-timeout", type=float, default=float(os.environ.get("SDT_CODEX_TIMEOUT", 120)) * 2)
    ap.add_argument("--budget", type=float, default=float(os.environ.get("SDT_CODEX_BUDGET", 600)))
    ap.add_argument("--max-files", type=int, default=60, help="most changed code files to send; the rest are named as unread")
    args = ap.parse_args()
    codex = sdt_triage_codex.find_codex(args.codex)
    if not codex or os.environ.get("SDT_AI_DIFF_REVIEW", "0") != "1":
        print("sdt_review_diff: off (set SDT_AI_DIFF_REVIEW=1 and install Codex): no change review")
        return 0
    reasoning = apply_diff_reasoning()
    routes_by_file = load_endpoint_context(args.endpoints)
    invariants = load_domain_invariants(args.src_root, args.invariants)
    try:
        scope = f"{args.base}...HEAD"
        changed = [p for p in git(args.src_root, "diff", "--name-only", "--diff-filter=AMR", scope).splitlines() if p]
        code = [p for p in changed if reviewable(p)]
        all_diffs = {p: git(args.src_root, "diff", f"-U{CONTEXT}", scope, "--", p) for p in code}
        ranked = sorted(code, key=lambda p: (-risk_score(p, all_diffs[p], routes_by_file, invariants), p))
        chosen = ranked[:max(args.max_files, 0)]
        diffs = {p: all_diffs[p] for p in chosen}
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"sdt_review_diff: cannot read the change ({exc}): no change review", file=sys.stderr)
        return 0
    report = review(
        diffs, codex, args.model,
        per_call_timeout=args.per_call_timeout, budget=args.budget,
        src_root=args.src_root, routes_by_file=routes_by_file,
        invariants=invariants, verify=args.verify,
    )
    report["reasoning"] = reasoning
    report["base"] = args.base
    report["files_over_limit"] = ranked[len(chosen):]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    if args.markdown:
        args.markdown.write_text(markdown(report, args.base, len(changed) - len(code), len(code) - len(chosen)))
    print(f"sdt_review_diff: {len(report['findings'])} possible problems in {len(report['files_reviewed'])} of "
          f"{len(code)} changed code files ({len(code) - len(chosen)} over the limit, not read), "
          f"{report['calls']} calls ({report['failed_calls']} failed)"
          f"{'; stopped: ' + report['stopped'] if report['stopped'] else ''}")
    return 0  # advisory: never fails the build


if __name__ == "__main__":
    sys.exit(main())
