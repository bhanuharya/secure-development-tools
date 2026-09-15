#!/usr/bin/env python3
"""Dart analyzer output -> SonarQube generic-issue JSON (offline, deterministic).

`dart analyze` (or `flutter analyze`) is the only real SAST surface for Dart:
SonarQube has no Dart analyzer, and opengrep/semgrep cannot parse Dart, so a
Flutter app is otherwise 100% unscanned.

Usage:
  dart analyze --format=json > reports/dart-analyze.json
  python3 tools/dart_to_sonar.py --from reports/dart-analyze.json \\
      --out reports/sonar-dart-external.json --repo-root .

Then pass BOTH report paths (they are comma-separated):
  -Dsonar.externalIssuesReportPaths=reports/sonar-external.json,reports/sonar-dart-external.json

Classification (first match wins):
  * codes in SECURITY_CODES      -> VULNERABILITY / SECURITY      (TRUSTWORTHY)
  * type ERROR / severity ERROR  -> BUG / RELIABILITY             (LOGICAL)
  * type LINT | HINT (style)     -> CODE_SMELL / MAINTAINABILITY  (CONVENTIONAL)
  * everything else (WARNING)    -> CODE_SMELL / MAINTAINABILITY  (CONVENTIONAL)

Most `flutter_lints` output is style/correctness, NOT security. Forcing it all
into SECURITY inflates the security count with noise; that is why the split is
by rule semantics. Use --force-security to override (everything becomes
VULNERABILITY/SECURITY) if a policy demands a single bucket.

Pure stdlib, offline, reproducible.
Exit 0 on success, 2 on invalid input.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ENGINE_ID = "dart-analyze"

# Diagnostics with a genuine security dimension. Source: dart.dev lint index,
# plus analyzer errors that indicate the analysed code is not what it appears
# to be (unresolved imports silently disabling security-relevant packages).
SECURITY_CODES = {
    # dynamic dispatch defeats static type guarantees
    "avoid_dynamic_calls",
    # logging can leak tokens/PII
    "avoid_print",
    # dart:html inside Flutter undermines platform sandboxing
    "avoid_web_libraries_in_flutter",
    # silently swallowing errors hides auth/validation failures
    "empty_catches",
    "avoid_catches_without_on_clauses",
    # unresolved or missing imports: a package can be silently absent
    "uri_does_not_exist",
    "undefined_class",
    "undefined_function",
    "undefined_identifier",
    "undefined_method",
}

# Sonar legacy severity + impact mapping per tier.
TIER = {
    "security": ("VULNERABILITY", "SECURITY", "TRUSTWORTHY", "MAJOR", "HIGH"),
    "error":    ("BUG", "RELIABILITY", "LOGICAL", "MAJOR", "MEDIUM"),
    "warning":  ("CODE_SMELL", "MAINTAINABILITY", "CONVENTIONAL", "MINOR", "LOW"),
    "style":    ("CODE_SMELL", "MAINTAINABILITY", "CONVENTIONAL", "MINOR", "LOW"),
}
EFFORT = {"MAJOR": 30, "MINOR": 15, "CRITICAL": 60, "INFO": 5}


def _clean_rule_id(code: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]", "-", code or "unknown")[:200]


def _tier(diag: dict, force_security: bool) -> str:
    if force_security:
        return "security"
    code = str(diag.get("code") or "")
    if code in SECURITY_CODES:
        return "security"
    severity = str(diag.get("severity") or "").upper()
    dtype = str(diag.get("type") or "").upper()
    if severity == "ERROR" or dtype == "ERROR":
        return "error"
    if dtype in ("LINT", "HINT"):
        return "style"
    return "warning"


def _rel_path(file_field: str, repo_root: Path) -> str:
    """Sonar wants a path relative to the project base, forward-slashed."""
    p = Path(file_field)
    if p.is_absolute():
        try:
            p = p.relative_to(repo_root)
        except ValueError:
            return ""
    return str(p).replace(os.sep, "/").lstrip("./")


def convert(doc: dict, repo_root: Path, force_security: bool = False):
    diags = doc.get("diagnostics")
    if not isinstance(diags, list):
        raise ValueError("input has no 'diagnostics' array (not dart analyze JSON)")

    rules: dict[str, dict] = {}
    issues: list[dict] = []
    skipped = 0

    for d in diags:
        code = str(d.get("code") or "unknown")
        loc = d.get("location") or {}
        path = _rel_path(str(loc.get("file") or ""), repo_root)
        if not path:
            skipped += 1
            continue

        tier = _tier(d, force_security)
        itype, quality, attr, sev, impact = TIER[tier]
        key = f"dart-{_clean_rule_id(code)}"

        if key not in rules:
            desc = str(d.get("message") or "")
            correction = str(d.get("correction") or "")
            if correction:
                desc = f"{desc} — {correction}"
            url = str(d.get("url") or "")
            if url:
                desc = f"{desc} ({url})"
            rules[key] = {
                "id": key,
                "name": code[:200],
                "description": desc[:2000] or code,
                "engineId": ENGINE_ID,
                "cleanCodeAttribute": attr,
                "type": itype,
                "severity": sev,
                "impacts": [{"softwareQuality": quality, "severity": impact}],
            }

        rng = (loc.get("range") or {}).get("start") or {}
        start_line = rng.get("line")
        primary: dict = {
            "message": str(d.get("message") or code)[:1000],
            "filePath": path,
        }
        if isinstance(start_line, int) and start_line > 0:
            primary["textRange"] = {"startLine": start_line, "endLine": start_line}
        issues.append({
            "ruleId": key,
            "effortMinutes": EFFORT.get(sev, 5),
            "primaryLocation": primary,
        })

    issues.sort(key=lambda i: (i["ruleId"], i["primaryLocation"]["filePath"],
                               i["primaryLocation"].get("textRange", {}).get("startLine", 0)))
    return {"rules": [rules[k] for k in sorted(rules)], "issues": issues}, skipped


def main() -> int:
    ap = argparse.ArgumentParser(description="dart analyze JSON -> SonarQube generic issues.")
    ap.add_argument("--from", dest="src", default="reports/dart-analyze.json")
    ap.add_argument("--out", default="reports/sonar-dart-external.json")
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--force-security", action="store_true",
                    help="classify every diagnostic as VULNERABILITY/SECURITY")
    args = ap.parse_args()

    src = Path(args.src)
    if not src.is_file():
        print(f"dart_to_sonar: not found: {src}", file=sys.stderr)
        return 2
    try:
        doc = json.loads(src.read_text())
    except (OSError, ValueError) as exc:
        print(f"dart_to_sonar: invalid JSON: {exc}", file=sys.stderr)
        return 2
    try:
        payload, skipped = convert(doc, Path(args.repo_root).resolve(), args.force_security)
    except Exception as exc:                                       # noqa: BLE001
        print(f"dart_to_sonar: convert failed: {exc}", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"dart_to_sonar: wrote {out} ({len(payload['issues'])} issues, "
          f"{len(payload['rules'])} rules, {skipped} skipped-no-path)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
