#!/usr/bin/env python3
"""Optional AI-assisted review of code-security findings, with Codex as the reviewer.

For each code-security rule in the report (same source and order as sdt_to_docx.py),
the flagged code of up to --max-per-rule occurrences is sent to Codex in one call, and
the model returns, per occurrence, an advisory verdict:

  likely_true_positive | likely_false_positive | needs_context, a confidence and a reason.

The result (triage.json) is advice for the reader of the report: it never changes a
SonarQube status or an SDT verdict. Without Codex the script does nothing and exits 0,
so the normal report is produced unchanged.

Guardrails, because tokens cost money and code is sensitive:
  * only code-security findings are sent; secret findings never are, and likely secret
    values in the code shown are redacted before sending;
  * Codex runs non-interactively in a read-only sandbox, in an empty directory, with an
    enforced JSON schema for its answer;
  * every call has a timeout, the whole run has a time budget, and the run stops after
    --max-failures consecutive failed calls (bad model name, auth, outage) instead of
    spending more.

  SONAR_TOKEN=... python3 tools/sdt_triage_codex.py --sonar-url http://localhost:9000 \\
      --project-key KEY --branch main --src-root source --out out/triage.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sdt_to_docx  # noqa: E402  (same findings, same order as the report)

DEFAULT_MODEL = "gpt-6-luna"
VERDICTS = ("likely_true_positive", "likely_false_positive", "needs_context")
CONFIDENCE = ("low", "medium", "high")
CONTEXT_LINES = 40  # enough to see where a flagged value comes from
PROMPT_VERSION = "2"  # part of every remembered verdict: change it when the prompt or context changes
MAX_REASON = 400

RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["results"],
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "verdict", "confidence", "reason", "check", "suggested_fix"],
                "properties": {
                    "id": {"type": "string"},
                    "verdict": {"type": "string", "enum": list(VERDICTS)},
                    "confidence": {"type": "string", "enum": list(CONFIDENCE)},
                    "reason": {"type": "string"},
                    "check": {"type": "string"},
                    "suggested_fix": {"type": "string"},
                },
            },
        },
    },
}

from sdt_advisory import redact  # noqa: E402  (one redaction for prompts and reports)


MAX_BLOCK_LINES = 150
BRACE_FILE = re.compile(r"\.(dart|java|kt|kts|js|jsx|ts|tsx|go|swift|c|cc|cpp|h|cs|scala|php|rs)$")
STRINGS_AND_COMMENTS = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//.*$')
CONTROL_BLOCK = re.compile(r"^\}?\s*(if|else|for|while|switch|try|catch|do|finally)\b")


def _code(text: str) -> str:
    return STRINGS_AND_COMMENTS.sub("", text)


def enclosing_block(lines: list[str], index: int) -> tuple[int, int] | None:
    """(start, end), 0-based, of the innermost function or class body around lines[index].

    Brace counting ignores braces inside strings and // comments; if/for/while bodies are
    skipped so the reviewer sees the whole function, where values come from.
    """
    depths, depth = [], 0
    for text in lines:
        depths.append(depth)
        code = _code(text)
        depth += code.count("{") - code.count("}")
    level = depths[index]
    while level > 0:
        start = next((i for i in range(index, -1, -1) if depths[i] == level - 1 and "{" in _code(lines[i])), None)
        if start is None:
            return None
        end = next((i for i in range(start + 1, len(lines)) if i + 1 == len(lines) or depths[i + 1] <= level - 1),
                   len(lines) - 1)
        if not CONTROL_BLOCK.search(lines[start].strip()):
            return start, end
        level -= 1
    return None


IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]{3,}")
COMMON_WORDS = frozenset("""await async break case catch class const continue default else export false final from
function import return static string super switch this throw true undefined void while with null new let var
value values item items data result results index length name type key keys error props attrs slot template
href class style http https""".split())
RELATED_MATCHES, RELATED_PAD, RELATED_MAX_LINES = 6, 2, 60


def related_lines(lines: list[str], index: int, start: int, end: int) -> list[tuple[int, int]]:
    """Ranges elsewhere in the file that mention the names used on the flagged line.

    A value is often built or sanitised far from where it is used; the lines that share its
    names (most shared names first, then nearest) are where a reviewer would look next.
    """
    # The raw line, strings included: in a template the expression is inside an attribute value.
    names = {n for n in IDENTIFIER.findall(lines[index]) if n.lower() not in COMMON_WORDS}
    if not names:
        return []
    scored = []
    for n, text in enumerate(lines):
        if start <= n <= end:
            continue
        hits = len(names & set(IDENTIFIER.findall(text)))
        if hits:
            scored.append((-hits, abs(n - index), n))
    ranges: list[tuple[int, int]] = []
    budget = RELATED_MAX_LINES
    for _, _, n in sorted(scored)[:RELATED_MATCHES]:
        low, high = max(0, n - RELATED_PAD), min(len(lines) - 1, n + RELATED_PAD)
        low = end + 1 if start <= low <= end else low
        high = start - 1 if start <= high <= end else high
        if high - low + 1 > budget or low > high:
            continue
        budget -= high - low + 1
        ranges.append((low, high))
    merged: list[tuple[int, int]] = []
    for low, high in sorted(ranges):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(high, merged[-1][1]))
        else:
            merged.append((low, high))
    return merged


def context(src_root: Path | None, occurrence: sdt_to_docx.Occurrence) -> str:
    """The enclosing function (up to MAX_BLOCK_LINES) or +/-CONTEXT_LINES around the flagged line,
    then the lines elsewhere in the file that share its names; numbered with ">" marking the
    flagged line, redacted; "" when unreadable."""
    if not src_root or not occurrence.path or occurrence.line < 1:
        return ""
    root = src_root.resolve()
    path = (root / occurrence.path).resolve()
    if root not in path.parents or not path.is_file():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if occurrence.line > len(lines):
        return ""
    index = occurrence.line - 1
    block = enclosing_block(lines, index) if BRACE_FILE.search(occurrence.path) else None
    if block and block[1] - block[0] + 1 <= MAX_BLOCK_LINES:
        start, end = block
    else:
        start, end = max(0, index - CONTEXT_LINES), min(len(lines) - 1, index + CONTEXT_LINES)
    def numbered(low: int, high: int) -> list[str]:
        return [f"{'>' if n == index else ' '}{n + 1:>5}  {lines[n].rstrip()[:200]}" for n in range(low, high + 1)]

    body = numbered(start, end)
    for low, high in related_lines(lines, index, start, end):
        body += ["   ...  (elsewhere in this file, same names)"] + numbered(low, high)
    return redact("\n".join(body))


def memory_key(model: str, rule: str, path: str, code: str) -> str:
    """Identity of one review question: same model, rule, file and code shown -> same verdict."""
    digest = hashlib.sha256("\x00".join((PROMPT_VERSION, model, rule, path, code)).encode()).hexdigest()
    return "sha256:" + digest


def load_memory(path: Path | None) -> dict:
    """Remembered verdicts; an unreadable or foreign file is an empty memory, never an error."""
    try:
        data = json.loads(path.read_text()) if path and path.is_file() else {}
    except (OSError, ValueError):
        return {}
    entries = data.get("entries") if isinstance(data, dict) else None
    return entries if isinstance(entries, dict) else {}


def save_memory(path: Path, entries: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps({"version": 1, "entries": entries}, indent=1) + "\n")
    temporary.replace(path)


def build_prompt(group: sdt_to_docx.Group, items: list[tuple[str, sdt_to_docx.Occurrence, str]]) -> str:
    risk = " ".join(group.risk)[:1200] or "(no rule description available)"
    fixes = "; ".join(group.fixes)[:600]
    blocks = "\n\n".join(f"### {item_id}: {o.path}:{o.line}\nScanner message: {o.message or '-'}\n```\n{code}\n```"
                         for item_id, o, code in items)
    return f"""You are a senior application security reviewer. Your main job is to find FALSE POSITIVES:
static-analysis findings that are not a real, exploitable problem in this code, so the team
does not waste time on them. Confirm a finding as real only when the code supports it.

Rule: {group.rule} ({group.kind}, severity {group.severity})
Rule name: {group.name}
Why the rule exists: {risk}
Recommended practice: {fixes or '-'}

For each occurrence, first check these false-positive causes against the code shown:
1. Test, example, mock or generated code (paths or names with test/spec/mock/example/generated).
2. The flagged value is a constant, a literal, or comes only from the app itself (not user,
   network, deep link, clipboard, file or another app).
3. The input is validated, escaped, allow-listed or sanitised before the risky call, or where
   the value is built (check the lines shown after "..." from elsewhere in the file).
4. The framework or API used is safe by default for this case, or the risky option is disabled.
5. The code is unreachable, debug-only, or behind a check that makes the risk impossible.
6. The rule matched something that only looks like the pattern (a name, a comment, a string).

Then decide:
- likely_false_positive: one of the causes above clearly applies - name the line or call.
- likely_true_positive: the risky pattern is reachable with unsafe or attacker-influenced data
  and none of the causes apply - name the line where the unsafe data enters or is used.
- needs_context: the code shown genuinely cannot settle it (say exactly what is missing).
  Do not use this to avoid a decision the code already supports.

Answer rules (short, factual, no hedging words like "may" or "might"):
- Use only the code shown; you have no tools and must not run commands.
- reason: the evidence - one or two sentences naming the exact line numbers and identifiers.
- check: ONE concrete thing a developer verifies to close the finding:
    false positive -> what to confirm before marking it Safe (e.g. "confirm loadRequest at
                      line 72 only receives the constant PRIVACY_URL");
    real issue     -> where to confirm the impact (e.g. "confirm deepLink.uri reaches
                      launchUrl without an allow-list");
    needs context  -> exactly which file, function or value to inspect.
- suggested_fix: real issue -> one short concrete code change; false positive -> the note to
  record when marking it Safe (e.g. "constant URL, no user input"); needs context -> what to
  do for each outcome of the check.
- confidence: low, medium or high.
- Answer every id exactly once. Values shown as [REDACTED] were removed on purpose.

{blocks}
"""


def validate(answer: object, ids: set[str]) -> list[dict]:
    """Only well-formed results for ids we asked about; everything else is dropped."""
    if not isinstance(answer, dict) or not isinstance(answer.get("results"), list):
        raise ValueError("answer has no results list")
    out, seen = [], set()
    for item in answer["results"]:
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id", ""))
        if item_id not in ids or item_id in seen:
            continue
        if item.get("verdict") not in VERDICTS or item.get("confidence") not in CONFIDENCE:
            continue
        seen.add(item_id)
        out.append({"id": item_id, "verdict": item["verdict"], "confidence": item["confidence"],
                    "reason": " ".join(str(item.get("reason", "")).split())[:MAX_REASON],
                    "check": " ".join(str(item.get("check", "")).split())[:MAX_REASON],
                    "suggested_fix": " ".join(str(item.get("suggested_fix", "")).split())[:MAX_REASON]})
    return out


def run_codex(codex: str, model: str, prompt: str, timeout: float) -> dict:
    """One non-interactive, read-only Codex call in an empty directory; its JSON answer."""
    with tempfile.TemporaryDirectory(prefix="sdt-triage-") as work:
        schema = Path(work) / "schema.json"
        answer = Path(work) / "answer.json"
        schema.write_text(json.dumps(RESPONSE_SCHEMA))
        command = [codex, "exec", "--model", model, "--sandbox", "read-only", "--skip-git-repo-check",
                   "--ephemeral", "--cd", work, "--output-schema", str(schema), "--output-last-message", str(answer), "-"]
        result = subprocess.run(command, input=prompt, capture_output=True, text=True, timeout=timeout, cwd=work)
        if result.returncode != 0:
            last = (result.stderr or result.stdout).strip().splitlines()[-3:]
            raise RuntimeError(f"codex exited {result.returncode}: {' | '.join(last)[:300]}")
        if not answer.is_file() or not answer.read_text().strip():
            raise RuntimeError("codex wrote no answer")
        return json.loads(answer.read_text())


def triage(groups: list[sdt_to_docx.Group], src_root: Path | None, codex: str, model: str, *,
           per_call_timeout: float, budget: float, max_rules: int, max_per_rule: int, max_failures: int,
           call=run_codex, clock=time.monotonic, memory: dict | None = None) -> dict:
    """Review up to max_rules code rules, stopping on budget or repeated failure.

    ``memory`` holds earlier verdicts by memory_key: a question already answered for the same
    code is answered from it, so a rescan of unchanged code repeats the verdict instead of
    asking again; new answers are added to it.
    """
    started, failures = clock(), 0
    report = {"engine": "codex", "model": model, "advisory": True,
              "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "calls": 0, "failed_calls": 0, "remembered": 0, "stopped": "", "results": []}
    memory = {} if memory is None else memory
    for group in groups[:max_rules]:
        remaining = budget - (clock() - started)
        if remaining < 10:
            report["stopped"] = "time budget spent"
            break
        items, lookup, keys, considered = [], {}, {}, 0
        for occurrence in group.occurrences:
            code = context(src_root, occurrence)
            if not code:
                continue
            considered += 1
            key = memory_key(model, group.rule, occurrence.path, code)
            if isinstance(memory.get(key), dict):
                report["remembered"] += 1
                report["results"].append({"rule": group.rule, "path": occurrence.path, "line": occurrence.line,
                                          **memory[key], "remembered": True})
            else:
                item_id = f"o{len(items) + 1}"
                items.append((item_id, occurrence, code))
                lookup[item_id], keys[item_id] = occurrence, key
            if considered >= max_per_rule:
                break
        if not items:
            continue
        report["calls"] += 1
        try:
            answer = call(codex, model, build_prompt(group, items), min(per_call_timeout, remaining))
            results = validate(answer, set(lookup))
        except (subprocess.TimeoutExpired, RuntimeError, ValueError, OSError) as exc:
            failures += 1
            report["failed_calls"] += 1
            reason = "timed out" if isinstance(exc, subprocess.TimeoutExpired) else str(exc)
            print(f"sdt_triage_codex: {group.rule}: {reason}", file=sys.stderr)
            if failures >= max_failures:
                report["stopped"] = f"{failures} consecutive failed calls (last: {reason[:200]})"
                break
            continue
        failures = 0
        for result in results:
            item_id = result.pop("id")
            occurrence = lookup[item_id]
            memory[keys[item_id]] = dict(result)
            report["results"].append({"rule": group.rule, "path": occurrence.path, "line": occurrence.line, **result})
    return report


def find_codex(explicit: str) -> str:
    candidate = explicit or os.environ.get("SDT_CODEX_BIN", "") or "codex"
    return shutil.which(candidate) or ""


def main() -> int:
    ap = argparse.ArgumentParser(description="Optional Codex review of code-security findings (advisory).")
    ap.add_argument("--out", type=Path, required=True, help="triage.json to write (only when Codex ran)")
    ap.add_argument("--sonar-url")
    ap.add_argument("--project-key")
    ap.add_argument("--branch", default="")
    ap.add_argument("--pull-request", default="")
    ap.add_argument("--findings", type=Path, help="SDT findings.json (used when SonarQube is not given)")
    ap.add_argument("--src-root", type=Path, required=True)
    ap.add_argument("--codex", default="", help="codex binary (default: $SDT_CODEX_BIN, else codex on PATH)")
    ap.add_argument("--model", default=os.environ.get("SDT_CODEX_MODEL", DEFAULT_MODEL))
    ap.add_argument("--per-call-timeout", type=float, default=float(os.environ.get("SDT_CODEX_TIMEOUT", 120)))
    ap.add_argument("--budget", type=float, default=float(os.environ.get("SDT_CODEX_BUDGET", 900)),
                    help="seconds for the whole review")
    ap.add_argument("--max-rules", type=int, default=15)
    ap.add_argument("--max-per-rule", type=int, default=6)
    ap.add_argument("--max-failures", type=int, default=2, help="stop after this many consecutive failed calls")
    ap.add_argument("--memory", type=Path, help="file of remembered verdicts (default: $SDT_TRIAGE_MEMORY, else "
                                                "~/.cache/sdt/triage/<project>.json); unchanged code is not asked again")
    ap.add_argument("--refresh", action="store_true", help="ignore remembered verdicts and ask again")
    args = ap.parse_args()

    codex = find_codex(args.codex)
    if not codex or os.environ.get("SDT_AI_TRIAGE", "1") == "0":
        print("sdt_triage_codex: Codex not available (or SDT_AI_TRIAGE=0): normal report, no AI review")
        return 0
    try:
        if args.sonar_url:
            _, found = sdt_to_docx.from_sonar(sdt_to_docx.Sonar(args.sonar_url, os.environ.get("SONAR_TOKEN", "")),
                                              args.project_key, args.branch, args.pull_request)
        elif args.findings:
            found = sdt_to_docx.from_findings(json.loads(args.findings.read_text()), args.src_root)
        else:
            print("sdt_triage_codex: give --sonar-url or --findings", file=sys.stderr)
            return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f"sdt_triage_codex: cannot read findings ({exc}): no AI review", file=sys.stderr)
        return 0
    groups = sdt_to_docx.merge(found, None)["code"]
    memory_path = args.memory or Path(os.environ.get("SDT_TRIAGE_MEMORY", "") or Path.home() / ".cache" / "sdt" / "triage" /
                                      (re.sub(r"[^\w.-]", "_", args.project_key or "findings") + ".json"))
    memory = {} if args.refresh else load_memory(memory_path)
    report = triage(groups, args.src_root, codex, args.model, per_call_timeout=args.per_call_timeout,
                    budget=args.budget, max_rules=args.max_rules, max_per_rule=args.max_per_rule,
                    max_failures=args.max_failures, memory=memory)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    try:
        save_memory(memory_path, memory)
    except OSError as exc:
        print(f"sdt_triage_codex: verdicts not remembered ({exc})", file=sys.stderr)
    print(f"sdt_triage_codex: {len(report['results'])} occurrences reviewed by {args.model} in {report['calls']} calls "
          f"({report['failed_calls']} failed, {report['remembered']} remembered from earlier scans)"
          f"{'; stopped: ' + report['stopped'] if report['stopped'] else ''}")
    return 0  # advisory: never fails the build


if __name__ == "__main__":
    sys.exit(main())
