#!/usr/bin/env python3
"""Offline SDT findings.json -> SonarQube generic-issue JSON (no server, deterministic).

SonarQube (10.3+ schema, mandatory on 10.8+, accepted on 10.7) imports
third-party reports with NO plugin via:
  sonar.externalIssuesReportPaths=reports/sonar-external.json

Usage (after `sdt scan`, BEFORE sonar-scanner runs in the same workspace):
  python3 tools/sdt_to_sonar.py --from reports/findings.json --out reports/sonar-external.json

Then add to the sonar-scanner invocation:
  -Dsonar.externalIssuesReportPaths=reports/sonar-external.json

Mapping (first match wins, deterministic):
  secret                        -> VULNERABILITY / SECURITY:HIGH   (TRUSTWORTHY)
  dependency/image vulnerability-> VULNERABILITY / SECURITY by sev (TRUSTWORTHY)
  misconfiguration              -> VULNERABILITY / SECURITY by sev (TRUSTWORTHY)
  sast security families        -> VULNERABILITY / SECURITY by sev (TRUSTWORTHY)
  sast correctness families     -> BUG / RELIABILITY (INTENTIONAL) or
                                   CODE_SMELL / MAINTAINABILITY (CONVENTIONAL)

Rule severity: critical->CRITICAL, high->MAJOR, medium->MINOR, else INFO.
Findings without a file path are skipped (counted on stderr) — Sonar requires
primaryLocation.filePath. Secrets stay redacted: inputs already are, and no
source is read here at all.

Exit 0 on success (even with skips), 2 on invalid input.
Pipeline-ready: pure stdlib, offline, reproducible from the same reports/ dir.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SEV_RULE = {"critical": "CRITICAL", "high": "MAJOR", "medium": "MINOR", "low": "INFO", "info": "INFO"}
SEV_IMPACT = {"critical": "HIGH", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
EFFORT = {"critical": 60, "high": 30, "medium": 15, "low": 10, "info": 5}

# substring match (lowercased, _ -> -) on rule-id tail + category
_CORRECTNESS = (
    "eqeq", "no-string-eqeq", "assignment-comparison", "hardcoded-conditional",
    "hardcoded-conditional", "no-string", "correctness",
)


def _tail(rule_id: str) -> str:
    if not rule_id:
        return "unknown"
    t = rule_id.split(".")[-1] if "." in rule_id else rule_id.split("/")[-1]
    return t or rule_id


def _rule_key(adapter: str, tail: str) -> str:
    raw = f"sdt-{adapter}-{tail}"
    return re.sub(r"[^A-Za-z0-9_.\-]", "-", raw)[:200]


def _sev(f: dict) -> str:
    sev = f.get("severity") or {}
    return str(sev.get("canonical") or sev.get("original") or "info").lower()


def _classify(f: dict):
    """Return (type, softwareQuality, cleanCodeAttribute)."""
    cat = str(f.get("category", ""))
    hay = f"{_tail((f.get('rule') or {}).get('id', ''))} {cat}".lower().replace("_", "-")
    if cat == "secret":
        return ("VULNERABILITY", "SECURITY", "TRUSTWORTHY")
    if cat in ("dependency-vulnerability", "image-vulnerability"):
        return ("VULNERABILITY", "SECURITY", "TRUSTWORTHY")
    if cat == "misconfiguration":
        return ("VULNERABILITY", "SECURITY", "TRUSTWORTHY")
    if any(k in hay for k in _CORRECTNESS):
        return ("BUG", "RELIABILITY", "INTENTIONAL")
    if cat == "sast":
        return ("VULNERABILITY", "SECURITY", "TRUSTWORTHY")
    return ("CODE_SMELL", "MAINTAINABILITY", "CONVENTIONAL")


def _path(f: dict) -> str:
    loc = f.get("location") or {}
    p = loc.get("path") or (f.get("artifact") or {}).get("target") or ""
    return str(p).lstrip("/")


def convert(findings_doc: dict) -> tuple[dict, int]:
    findings = findings_doc.get("findings", [])
    rules: dict[str, dict] = {}
    issues: list[dict] = []
    skipped = 0
    for f in findings:
        path = _path(f)
        if not path:
            skipped += 1
            continue
        sev = _sev(f)
        rule = f.get("rule", {}) or {}
        adapter = (f.get("scanner", {}) or {}).get("adapter", "sdt")
        key = _rule_key(adapter, _tail(str(rule.get("id", "unknown"))))
        if key not in rules:
            itype, quality, attr = _classify(f)
            cwe = rule.get("cwe")
            cwe_s = cwe[0] if isinstance(cwe, list) and cwe else (cwe if isinstance(cwe, str) else "")
            desc = str(f.get("message", ""))[:500]
            if cwe_s:
                desc = f"{cwe_s}: {desc}"
            rules[key] = {
                "id": key,
                "name": _tail(str(rule.get("id", key)))[:200],
                "description": desc[:2000],
                "engineId": f"sdt-{adapter}",
                "cleanCodeAttribute": attr,
                "type": itype,
                "severity": SEV_RULE.get(sev, "INFO"),
                "impacts": [{"softwareQuality": quality, "severity": SEV_IMPACT.get(sev, "INFO")}],
            }
        loc = f.get("location") or {}
        tr: dict = {}
        sl = loc.get("startLine")
        el = loc.get("endLine")
        if isinstance(sl, int) and sl > 0:
            tr["startLine"] = sl
            if isinstance(el, int) and el >= sl:
                tr["endLine"] = el
        primary: dict = {"message": str(f.get("message", ""))[:1000], "filePath": path}
        if tr:
            primary["textRange"] = tr
        issues.append({"ruleId": key, "effortMinutes": EFFORT.get(sev, 5), "primaryLocation": primary})
    # deterministic order: rule id, then path, then line
    issues.sort(key=lambda i: (i["ruleId"], i["primaryLocation"]["filePath"],
                               i["primaryLocation"].get("textRange", {}).get("startLine", 0)))
    return ({"rules": [rules[k] for k in sorted(rules)], "issues": issues}, skipped)


def main() -> int:
    ap = argparse.ArgumentParser(description="SDT findings.json -> SonarQube generic-issue JSON (offline).")
    ap.add_argument("--from", dest="src", default="reports/findings.json")
    ap.add_argument("--out", default="reports/sonar-external.json")
    args = ap.parse_args()

    src = Path(args.src)
    if not src.is_file():
        print(f"sdt_to_sonar: findings not found: {src}", file=sys.stderr)
        return 2
    try:
        doc = json.loads(src.read_text())
    except (OSError, ValueError) as exc:
        print(f"sdt_to_sonar: invalid findings.json: {exc}", file=sys.stderr)
        return 2
    try:
        payload, skipped = convert(doc)
    except Exception as exc:
        print(f"sdt_to_sonar: convert failed: {exc}", file=sys.stderr)
        return 2
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"sdt_to_sonar: wrote {out} ({len(payload['issues'])} issues, "
          f"{len(payload['rules'])} rules, {skipped} skipped-no-path)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
