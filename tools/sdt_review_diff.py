#!/usr/bin/env python3
"""Optional AI review of what a pull request changes, for the problems rules do not find.

Pattern scanners are good at known-bad calls and weak at logic: an endpoint added without a
permission check, a record fetched by id without checking its owner, a validation that was
dropped. This sends the changed lines of a pull request (with a few lines around them) to
Codex and asks only for security problems the change introduces. The answer is advice for the
reviewer of the pull request (ai-change-review.json and .md): it never blocks a build, never
enters SonarQube, and every item must point at a line the change added.

Off unless SDT_AI_DIFF_REVIEW=1. Guardrails are the ones of sdt_triage_codex.py: likely secret
values are redacted before sending; Codex runs non-interactively in a read-only sandbox, in an
empty directory, with an enforced JSON answer; per-call timeout, whole-run budget, and a stop
after repeated failures. Lock files, tests, generated and binary files are not sent.

  python3 tools/sdt_review_diff.py --src-root source --base origin/main \\
      --out out/ai-change-review.json --markdown out/ai-change-review.md
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sdt_triage_codex  # noqa: E402  (the same Codex call and limits)
from sdt_advisory import redact  # noqa: E402

SEVERITIES = ("high", "medium", "low")
CONFIDENCE = ("low", "medium", "high")
MAX_TEXT = 500
CONTEXT = 12            # unchanged lines shown around each change
MAX_FILE_LINES = 400    # of numbered diff per file; a larger change is cut and reported as partial
MAX_CALL_CHARS = 28000  # of numbered diff per Codex call

CODE_FILE = re.compile(r"\.(js|jsx|mjs|cjs|ts|tsx|vue|svelte|py|go|java|kt|kts|dart|swift|php|rb|cs|rs|scala|sql|"
                       r"ya?ml|json|tf|sh|gradle|xml|properties|env)$|(^|/)Dockerfile[^/]*$", re.IGNORECASE)
NOT_REVIEWED = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|mocks?|node_modules|vendor|dist|build|generated)/|"
                          r"\.(test|spec)\.[^/]+$|_test\.(go|dart)$|\.min\.[^/]+$|\.lock$|-lock\.(json|ya?ml)$|"
                          r"(^|/)(package-lock\.json|go\.sum|pubspec\.lock)$", re.IGNORECASE)
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

RESPONSE_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["findings"],
    "properties": {"findings": {"type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": ["path", "line", "title", "severity", "confidence", "evidence", "check", "fix"],
        "properties": {"path": {"type": "string"}, "line": {"type": "integer"}, "title": {"type": "string"},
                       "severity": {"type": "string", "enum": list(SEVERITIES)},
                       "confidence": {"type": "string", "enum": list(CONFIDENCE)},
                       "evidence": {"type": "string"}, "check": {"type": "string"}, "fix": {"type": "string"}}}}},
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


def build_prompt(files: list[tuple[str, str]]) -> str:
    blocks = "\n\n".join(f"### {path}\n```\n{text}\n```" for path, text in files)
    return f"""You are a senior application security reviewer reading the changes of one pull request.
Pattern-based scanners already ran. Report only what they miss: security problems that this
change INTRODUCES or makes reachable. Typical ones:
- a new or changed endpoint, route, job or handler without authentication or a permission check;
- a record read, changed or deleted by an id from the request without checking it belongs to
  the caller or their tenant;
- input from a request, file, message or another service used without validation, or a
  validation, escape or allow-list that the change removes or bypasses;
- queries, commands, paths, URLs or HTML built from such input;
- secrets, tokens or personal data written to logs, responses, errors or URLs;
- a security setting weakened (CORS, cookies, TLS, CSP, rate limits, upload limits, debug);
- money, approval or status flows whose order or checks the change lets a caller skip.

Rules:
- Lines starting with "+" were added, "-" removed, the rest is unchanged context. Numbers are
  line numbers in the file after the change.
- Every finding must point at an added ("+") line: path exactly as in the heading, line as shown.
- Report a problem only when the code shown supports it. No style, naming, performance or test
  remarks, and nothing a linter would say. An empty list is a good answer.
- evidence: one or two sentences naming the lines and identifiers that show the problem.
- check: the ONE thing the reviewer verifies to confirm or dismiss it (name the file or function).
- fix: one short concrete change.
- You have no tools; use only the code shown. Values shown as [REDACTED] were removed on purpose.

{blocks}
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
        clean = {key: " ".join(str(item.get(key, "")).split())[:MAX_TEXT] for key in ("title", "evidence", "check", "fix")}
        if clean["title"] and clean["evidence"]:
            out.append({"path": path, "line": line, "severity": item["severity"], "confidence": item["confidence"], **clean})
    return out


def batches(files: list[tuple[str, str]]) -> list[list[tuple[str, str]]]:
    """Files grouped so one call stays under MAX_CALL_CHARS (a single large file goes alone)."""
    groups, current, size = [], [], 0
    for path, text in files:
        if current and size + len(text) > MAX_CALL_CHARS:
            groups.append(current)
            current, size = [], 0
        current.append((path, text))
        size += len(text)
    return groups + ([current] if current else [])


def review(diffs: dict[str, str], codex: str, model: str, *, per_call_timeout: float, budget: float,
           max_failures: int = 2, call=sdt_triage_codex.run_codex, clock=time.monotonic) -> dict:
    """Review the per-file diffs; ``diffs`` maps path -> unified diff."""
    report = {"engine": "codex", "model": model, "advisory": True,
              "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "files_reviewed": [], "files_partial": [], "calls": 0, "failed_calls": 0, "stopped": "", "findings": []}
    files, added = [], {}
    for path in sorted(diffs):
        text, lines, cut = numbered_diff(diffs[path])
        if not lines:
            continue
        files.append((path, text))
        added[path] = lines
        if cut:
            report["files_partial"].append(path)
    started, failures = clock(), 0
    for group in batches(files):
        remaining = budget - (clock() - started)
        if remaining < 10:
            report["stopped"] = "time budget spent"
            break
        report["calls"] += 1
        try:
            answer = call(codex, model, build_prompt(group), min(per_call_timeout, remaining), RESPONSE_SCHEMA)
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
    order = {s: n for n, s in enumerate(SEVERITIES)}
    report["findings"].sort(key=lambda f: (order[f["severity"]], f["path"], f["line"]))
    return report


def markdown(report: dict, base: str, skipped: int, over_limit: int = 0) -> str:
    lines = ["# AI review of this change (advisory)", "",
             f"Model `{report['model']}` read {len(report['files_reviewed'])} changed files against `{base}` "
             f"and reported {len(report['findings'])} possible security problems. {skipped} changed files were "
             "not sent (tests, lock files, generated or non-code files).",
             "This is advice for the reviewer: confirm each item in the code before acting on it. "
             "No finding here blocks the build or enters SonarQube.", ""]
    if over_limit:
        lines += [f"{over_limit} more changed code files were NOT read: the change is larger than the per-review "
                  "file limit. Review those by hand.", ""]
    if report["files_partial"]:
        lines += ["Only the first part of these large changes was read: " + ", ".join(report["files_partial"]) + ".", ""]
    if report["stopped"]:
        lines += [f"The review stopped early ({report['stopped']}); files not listed above were not read.", ""]
    for n, f in enumerate(report["findings"], 1):
        lines += [f"## {n}. {f['title']}", "",
                  f"- **Where:** `{f['path']}:{f['line']}`",
                  f"- **Severity:** {f['severity']} (confidence {f['confidence']})",
                  f"- **Evidence:** {f['evidence']}", f"- **Check:** {f['check']}", f"- **Fix:** {f['fix']}", ""]
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
    try:
        scope = f"{args.base}...HEAD"
        changed = [p for p in git(args.src_root, "diff", "--name-only", "--diff-filter=AMR", scope).splitlines() if p]
        code = [p for p in changed if reviewable(p)]
        chosen = code[:max(args.max_files, 0)]
        diffs = {p: git(args.src_root, "diff", f"-U{CONTEXT}", scope, "--", p) for p in chosen}
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"sdt_review_diff: cannot read the change ({exc}): no change review", file=sys.stderr)
        return 0
    report = review(diffs, codex, args.model, per_call_timeout=args.per_call_timeout, budget=args.budget)
    report["base"] = args.base
    report["files_over_limit"] = code[len(chosen):]
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
