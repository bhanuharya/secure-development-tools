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
primaryLocation.filePath. Secrets stay redacted: inputs already are, and with
--repo-root only a source file's line count is read, never its contents.
With --repo-root an issue line past end of file is clamped to the file: SonarQube
rejects the whole Compute Engine import over one out-of-range pointer.

Trivy dependency findings are the noisy majority, so they get a one-line
message ('<pkg>@<ver> — CVE-x <short title>. Fixed in <ver>.'), a two-sentence
rule description pointing at the workbook for the full advisory, tags, and a
flat 10-minute effort. Everything else keeps the verbatim message.

Exit 0 on success (even with skips), 2 on invalid input.
Pipeline-ready: pure stdlib, offline, reproducible from the same reports/ dir.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SEV_RULE = {"critical": "CRITICAL", "high": "MAJOR", "medium": "MINOR", "low": "INFO", "info": "INFO"}
SEV_IMPACT = {"critical": "HIGH", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
EFFORT = {"critical": 60, "high": 30, "medium": 15, "low": 10, "info": 5}

MESSAGE_LIMIT = 200
DESCRIPTION_LIMIT = 400
TITLE_LIMIT = 120
TAG_LIMIT = 20
TAG_COUNT_LIMIT = 5
DEPENDENCY_EFFORT = 10
ADVISORY_POINTER = " Full advisory in the SDT report (fleet-findings.xlsx)."
_VULN_CATEGORIES = ("dependency-vulnerability", "image-vulnerability")

# A sentence ends at a period followed by whitespace/end, so "e.g.," and "5.4,"
# never cut a short title in the middle of an abbreviation or a version.
_SENT_END = re.compile(r"\.(?=\s|$)")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_FLAT_RE = re.compile(r"\b([\w][\w.+-]*)@([0-9][\w.+-]*)")
_THROUGH_RE = re.compile(r"\b([A-Za-z][\w.+-]*)\s+([0-9][\w.+-]*)\s+through\b")
_NOUN_RE = re.compile(r"\b(?:the|in)\s+([A-Za-z][\w.+-]*)\s+(?:package|library|module|gem|crate)\b", re.I)
_HEAD_RE = re.compile(r"^([A-Za-z][\w.+-]*)\s+is\b")
_FIX_RE = re.compile(r"\b(?:fixed in|prior to|versions? before)\s+(?:version\s+)?v?([0-9][\w.+-]*)", re.I)

# Order follows the task's mapping; each pattern is anchored on word boundaries
# so prose like "pipeline" is never read as an ecosystem.
_ECOSYSTEMS = (
    ("npm", re.compile(r"\b(?:npm|yarn|pnpm|package-lock|package\.json)\b", re.I)),
    ("pypi", re.compile(r"\b(?:pip|pypi|poetry|requirements|pyproject)\b", re.I)),
    ("maven", re.compile(r"\b(?:maven|gradle|pom)\b|\.jar\b", re.I)),
    ("golang", re.compile(r"\b(?:golang|go\.mod|go\.sum)\b", re.I)),
)

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


def _rule_key(adapter: str, rule_id: str) -> str:
    """Keep the readable tail while retaining the full rule's identity."""
    raw = f"sdt-{adapter}-{_tail(rule_id)}"
    safe = re.sub(r"[^A-Za-z0-9_.\-]", "-", raw)[:183]
    digest = hashlib.sha256(f"{adapter}\0{rule_id}".encode()).hexdigest()[:16]
    return f"{safe}-{digest}"


def _sev(f: dict) -> str:
    sev = f.get("severity") or {}
    return str(sev.get("canonical") or sev.get("original") or "info").lower()


def _classify(f: dict):
    """Return (type, softwareQuality, cleanCodeAttribute)."""
    cat = str(f.get("category", ""))
    classification = str((f.get("metadata") or {}).get("classification") or "")
    hay = f"{_tail((f.get('rule') or {}).get('id', ''))} {cat}".lower().replace("_", "-")
    if cat == "secret":
        return ("VULNERABILITY", "SECURITY", "TRUSTWORTHY")
    if cat in ("dependency-vulnerability", "image-vulnerability"):
        return ("VULNERABILITY", "SECURITY", "TRUSTWORTHY")
    if cat == "misconfiguration":
        return ("VULNERABILITY", "SECURITY", "TRUSTWORTHY")
    if classification == "correctness" or any(k in hay for k in _CORRECTNESS):
        return ("BUG", "RELIABILITY", "LOGICAL")
    if cat == "sast":
        return ("VULNERABILITY", "SECURITY", "TRUSTWORTHY")
    return ("CODE_SMELL", "MAINTAINABILITY", "CONVENTIONAL")


def _clip(text: str, width: int) -> str:
    """Trim to `width` characters, dropping a trailing partial word when it fits."""
    if len(text) <= width:
        return text.strip()
    head = text[:width]
    cut = head[: head.rfind(" ")] if " " in head else head
    if len(cut.strip()) < width // 2:
        cut = head
    return cut.strip().rstrip(" ,;:-")


def _sentences(text: str, count: int) -> list[str]:
    """Up to `count` leading sentences, each without its terminating period."""
    parts: list[str] = []
    start = 0
    for match in _SENT_END.finditer(text):
        part = text[start:match.start()].strip()
        start = match.end()
        if part:
            parts.append(part)
            if len(parts) == count:
                return parts
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _token(text: str) -> str:
    """A regex-pulled package/version token, without the sentence punctuation after it."""
    return text.strip().strip("\"'([{<").rstrip(".,:;")


def extract_vuln_fields(message: str) -> dict:
    """package/version/fix/CVE/title pulled out of one advisory message.

    Any key may come back empty: SDT flattens trivy output, so the advisory
    prose is the only place this information survives for older reports.
    """
    text = str(message or "")
    found = _CVE_RE.search(text)
    cve = found.group(0) if found else ""
    body = text.replace(cve, " ") if cve else text
    body = " ".join(re.sub(r"\(\s*\)", " ", body).split())

    package = version = ""
    for pattern in (_FLAT_RE, _THROUGH_RE):
        match = pattern.search(body)
        if match:
            package, version = match.group(1), match.group(2)
            break
    else:
        for pattern in (_NOUN_RE, _HEAD_RE):
            match = pattern.search(body)
            if match:
                package = match.group(1)
                break
    fix_match = _FIX_RE.search(body)
    sentences = _sentences(body, 1)
    return {
        "package": _token(package),
        "version": _token(version),
        "fix": _token(fix_match.group(1)) if fix_match else "",
        "cve": cve,
        "title": _clip(sentences[0], TITLE_LIMIT) if sentences else "",
    }


def _vuln_view(f: dict) -> dict | None:
    """Sonar-friendly fields for a trivy dependency finding, None for anything else."""
    if str(f.get("category", "")) not in _VULN_CATEGORIES:
        return None
    rule = f.get("rule") or {}
    artifact = f.get("artifact") or {}
    extracted = extract_vuln_fields(str(f.get("message", "")))
    rule_id = str(rule.get("id") or "")
    view = {
        "package": str(artifact.get("package") or "") or extracted["package"],
        "version": str(artifact.get("installedVersion") or "") or extracted["version"],
        "fix": str(artifact.get("fixedVersion") or "") or extracted["fix"],
        "cve": rule_id if _CVE_RE.fullmatch(rule_id) else extracted["cve"],
        "title": extracted["title"],
    }
    if not view["cve"] and not view["package"]:
        return None
    return view


def _vuln_message(view: dict) -> str:
    """One bounded line: '<pkg>@<ver> — CVE-x <short title>. Fixed in <ver>.'"""
    head = "@".join(part for part in (view["package"], view["version"]) if part)
    title = view["title"]
    if "@" in head and title.startswith(head):
        title = title[len(head):].strip()
    label = f"{view['cve']} {title or 'Dependency vulnerability'}".strip()
    tail = f"Fixed in {view['fix']}." if view["fix"] else "No fix available."
    prefix = f"{head} — " if head else ""
    budget = max(MESSAGE_LIMIT - len(prefix) - len(tail) - 2, 0)
    label = _clip(label, budget)
    if not label:
        return f"{prefix}{tail}".strip()
    return f"{prefix}{label}. {tail}"


def _vuln_description(message: str) -> str:
    """Two sentences of the advisory, then where to read the whole thing."""
    lead = ". ".join(_sentences(" ".join(str(message or "").split()), 2))
    body = f"{lead}." if lead else ""
    return _clip(body, DESCRIPTION_LIMIT - len(ADVISORY_POINTER)) + ADVISORY_POINTER


def _cwe(rule: dict) -> str:
    """Leading CWE id from a rule, however the adapter serialized it."""
    cwe = rule.get("cwe")
    if isinstance(cwe, list) and cwe:
        return str(cwe[0])
    return cwe if isinstance(cwe, str) else ""


def _ecosystem(f: dict) -> str:
    """Manifest identity first, advisory prose only as a fallback."""
    rule = f.get("rule") or {}
    artifact = f.get("artifact") or {}
    for hay in (f"{artifact.get('target') or ''} {rule.get('id') or ''}", str(f.get("message") or "")):
        for name, pattern in _ECOSYSTEMS:
            if pattern.search(hay):
                return name
    return ""


def _tags(f: dict, view: dict | None) -> list[str]:
    """Sonar tags: lowercase, <=20 chars each, at most 5 per rule."""
    tags = ["sdt"]
    if view:
        tags.append("dependency")
        ecosystem = _ecosystem(f)
        if ecosystem:
            tags.append(ecosystem)
    if _cwe(f.get("rule") or {}):
        tags.append("cwe")
    return [re.sub(r"[^a-z0-9.-]", "-", str(tag).lower())[:TAG_LIMIT] for tag in tags[:TAG_COUNT_LIMIT]]


def _path(f: dict) -> str:
    loc = f.get("location") or {}
    p = loc.get("path") or (f.get("artifact") or {}).get("target") or ""
    p = str(p).replace("\\", "/")
    # Sonar paths must resolve inside this checkout. Never turn an absolute
    # scanner path into a misleading relative path by stripping '/'.
    if p.startswith("/") or re.match(r"^[A-Za-z]:/", p):
        return ""
    parts = p.split("/")
    if any(part == ".." for part in parts):
        return ""
    return "/".join(part for part in parts if part not in ("", "."))


def _line_count(source: Path) -> int:
    """Lines in a real file; 0 when it holds none or cannot be read."""
    try:
        return len(source.read_text(errors="replace").splitlines())
    except OSError:
        return 0


def _clamp_range(tr: dict, count: int) -> dict:
    """Keep every pointer line inside [1, count]; an out-of-range line fails the import.

    A file with no readable lines cannot host any pointer, so its range is dropped
    and the issue stays as a file-level one rather than failing the whole import.
    """
    if count < 1:
        return {}
    start = min(max(tr["startLine"], 1), count)
    clamped: dict = {"startLine": start}
    if "endLine" in tr:
        end = min(max(tr["endLine"], 1), count)
        if end >= start:
            clamped["endLine"] = end
    return clamped


def convert(findings_doc: dict, repo_root: Path | None = None) -> tuple[dict, int]:
    findings = findings_doc.get("findings", [])
    rules: dict[str, dict] = {}
    issues: list[dict] = []
    skipped = 0
    line_counts: dict[Path, int] = {}
    for f in findings:
        path = _path(f)
        source: Path | None = None
        if path and repo_root is not None:
            root = repo_root.resolve()
            source = (root / path).resolve()
            if not source.is_file() or (source != root and root not in source.parents):
                path = ""
                source = None
        if not path:
            skipped += 1
            continue
        sev = _sev(f)
        rule = f.get("rule", {}) or {}
        adapter = (f.get("scanner", {}) or {}).get("adapter", "sdt")
        key = _rule_key(adapter, str(rule.get("id", "unknown")))
        view = _vuln_view(f)
        if key not in rules:
            itype, quality, attr = _classify(f)
            cwe_s = _cwe(rule)
            desc = str(f.get("message", ""))[:500]
            if cwe_s:
                desc = f"{cwe_s}: {desc}"
            if view:
                desc = _vuln_description(str(f.get("message", "")))
            rules[key] = {
                "id": key,
                "name": _tail(str(rule.get("id", key)))[:200],
                "description": desc[:2000],
                "engineId": f"sdt-{adapter}",
                "cleanCodeAttribute": attr,
                "type": itype,
                "severity": SEV_RULE.get(sev, "INFO"),
                "impacts": [{"softwareQuality": quality, "severity": SEV_IMPACT.get(sev, "INFO")}],
                "tags": _tags(f, view),
            }
        loc = f.get("location") or {}
        tr: dict = {}
        sl = loc.get("startLine")
        el = loc.get("endLine")
        if isinstance(sl, int) and sl > 0:
            tr["startLine"] = sl
            if isinstance(el, int) and el >= sl:
                tr["endLine"] = el
        if tr and source is not None:
            if source not in line_counts:
                line_counts[source] = _line_count(source)
            tr = _clamp_range(tr, line_counts[source])
        primary: dict = {"message": _vuln_message(view) if view else str(f.get("message", ""))[:1000],
                         "filePath": path}
        if tr:
            primary["textRange"] = tr
        issues.append({"ruleId": key, "effortMinutes": DEPENDENCY_EFFORT if view else EFFORT.get(sev, 5),
                       "primaryLocation": primary})
    # deterministic order: rule id, then path, then line
    issues.sort(key=lambda i: (i["ruleId"], i["primaryLocation"]["filePath"],
                               i["primaryLocation"].get("textRange", {}).get("startLine", 0)))
    return ({"rules": [rules[k] for k in sorted(rules)], "issues": issues}, skipped)


def main() -> int:
    ap = argparse.ArgumentParser(description="SDT findings.json -> SonarQube generic-issue JSON (offline).")
    ap.add_argument("--from", dest="src", default="reports/findings.json")
    ap.add_argument("--out", default="reports/sonar-external.json")
    ap.add_argument("--repo-root", type=Path,
                    help="resolve findings against this checkout: skip absent files and clamp issue lines to the file")
    ap.add_argument("--skip-adapter", action="append", default=[], metavar="ADAPTER",
                    help="leave this scanner's findings out (repeatable), e.g. opengrep when "
                         "sonar-opengrep-plugin imports them as native rules")
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
    doc, left_out = without_adapters(doc, args.skip_adapter)
    doc, suppressed = without_suppressed(doc)
    try:
        payload, skipped = convert(doc, args.repo_root)
    except Exception as exc:
        print(f"sdt_to_sonar: convert failed: {exc}", file=sys.stderr)
        return 2
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"sdt_to_sonar: wrote {out} ({len(payload['issues'])} issues, "
          f"{len(payload['rules'])} rules, {skipped} skipped-no-path, {left_out} left to other importers, "
          f"{suppressed} suppressed by an exception)")
    return 0


def without_adapters(doc: dict, adapters: list[str]) -> tuple[dict, int]:
    """The findings document minus the given scanners' findings, and how many were removed."""
    skip = {adapter.lower() for adapter in adapters}
    if not skip:
        return doc, 0
    findings = doc.get("findings", [])
    kept = [f for f in findings if str((f.get("scanner", {}) or {}).get("adapter", "")).lower() not in skip]
    return {**doc, "findings": kept}, len(findings) - len(kept)


def without_suppressed(doc: dict) -> tuple[dict, int]:
    """The findings document minus findings an approved exception covers, and how many those were."""
    findings = doc.get("findings", [])
    kept = [f for f in findings if not f.get("suppression")]
    return {**doc, "findings": kept}, len(findings) - len(kept)


if __name__ == "__main__":
    sys.exit(main())
