"""OSV-Scanner adapter — dependency vulnerability scanning via Google OSV.

Scans lockfiles across many ecosystems (npm, pip, go, cargo, maven, etc.) and
reports known vulnerabilities, complementing Trivy's image/fs scanning. This is
the standard CI pipeline dependency scanner.
"""

from __future__ import annotations

import json
import re

from src.scanners.base import RawFinding, Scanner, normalize_severity
from src.scanners.errors import ScannerExecutionError, ScannerMalformedOutputError


class OsvScannerAdapter(Scanner):
    name = "osv-scanner"
    source_type = "sca"

    def _run(self) -> list[RawFinding]:
        # osv-scanner exits 0 when no vulnerabilities and 1 when found.
        # Run from the workdir so reported source paths are relative.
        proc = self._exec(
            ["--format", "json", "."],
            cwd=str(self.workdir),
            timeout=1800,
        )
        if proc.returncode not in (0, 1):
            raise ScannerExecutionError(
                self.name, f"osv-scanner exited {proc.returncode}: {(proc.stderr or '')[:300]}"
            )
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerMalformedOutputError(
                self.name, "osv-scanner returned invalid JSON output"
            ) from exc
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ScannerMalformedOutputError(
                self.name, "osv-scanner JSON is missing a results array"
            )

        findings: list[RawFinding] = []
        for result in data.get("results", []):
            source = result.get("source") or {}
            source_path = source.get("path", "")
            for pkg in result.get("packages") or []:
                vulns = pkg.get("vulnerabilities") or []
                pkg_info = pkg.get("package") or {}
                pkg_name = pkg_info.get("name", "")
                version = pkg_info.get("version", "")
                for v in vulns:
                    findings.append(
                        RawFinding(
                            tool=self.name,
                            source_type=self.source_type,
                            rule_id=_vuln_id(v),
                            severity=_severity(v),
                            file_path=source_path,
                            description=_summary(v, pkg_name, version),
                            remediation=_remediation(v, pkg_name),
                            raw=v,
                        )
                    )
        return findings


def _vuln_id(vuln: dict) -> str:
    return vuln.get("id") or (vuln.get("aliases") or [None])[0] or ""


def _severity(vuln: dict) -> str:
    """Map all OSV severity groups conservatively, using numeric CVSS first."""
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    values = []
    db = vuln.get("database_specific") or {}
    if db.get("severity"):
        values.append(normalize_severity(str(db["severity"])))
    for entry in vuln.get("severity") or []:
        raw = str(entry.get("score") or "")
        vector = _cvss3_vector_score(raw)
        if vector is not None:
            values.append(_band(vector))
            continue
        # OSV commonly supplies a numeric score, sometimes embedded in text.
        nums = _CVSS_NUM_RE.findall(raw)
        if nums:
            values.append(_band(float(nums[0])))
        elif raw:
            values.append(_word_or_impact(raw))
    return max(values, key=lambda x: rank[x]) if values else "medium"


def _word_or_impact(raw: str) -> str:
    # A bare severity word ("high") keeps its meaning; anything else that is
    # not a parseable vector/score floors at medium via the impact fallback.
    if "/" not in raw and " " not in raw:
        word = normalize_severity(raw)
        if word != "low" or raw.strip().lower() == "low":
            return word
    return _impact_fallback(raw)


# A bare decimal such as "3.1" (the CVSS *version* inside a vector) must not
# be mistaken for a score, so vectors are matched before this runs.
_CVSS_NUM_RE = re.compile(r"(?<![0-9])(?:10(?:\.0)?|[0-9](?:\.[0-9])?)(?![0-9])")

_CVSS3_VECTOR_RE = re.compile(
    r"^(?:CVSS:3\.[01]/)?AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$"
)

_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.646, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _band(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _cvss3_vector_score(raw: str) -> float | None:
    """Base score for a CVSS v3.0/v3.1 vector string (FIRST v3.1 formula);
    None when raw is not a complete vector."""
    vector = raw.strip()
    if ":" not in vector and "/" in vector:
        vector = "CVSS:3.1/" + vector
    if "/" not in vector or not _CVSS3_VECTOR_RE.match(vector):
        return None
    metrics = dict(part.split(":", 1) for part in vector.split("/") if ":" in part)
    av = _CVSS3_WEIGHTS["AV"][metrics["AV"]]
    ac = _CVSS3_WEIGHTS["AC"][metrics["AC"]]
    pr = _CVSS3_WEIGHTS["PR"][metrics["S"]][metrics["PR"]]
    ui = _CVSS3_WEIGHTS["UI"][metrics["UI"]]
    c, i, a = (_CVSS3_WEIGHTS["CIA"][metrics[k]] for k in ("C", "I", "A"))
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if metrics["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    score = impact + exploitability if metrics["S"] == "U" else 1.08 * (impact + exploitability)
    return _cvss3_roundup(min(score, 10.0))


def _cvss3_roundup(value: float) -> float:
    # CVSS 3.1 spec appendix A: smallest 1-decimal number >= value,
    # guarded against binary float error via 5-decimal quantization.
    quantized = round(value * 100000)
    if quantized % 10000 == 0:
        return quantized / 100000.0
    return (quantized // 10000 + 1) / 10.0


def _impact_fallback(raw: str) -> str:
    """Non-numeric, unparsable score (e.g. a CVSS 2.0 vector): derive a floor
    from the C/I/A impacts. Never below medium so malformed input cannot
    silently downgrade a vulnerability."""
    text = "/" + raw.strip().strip("/").upper() + "/"
    impacts = re.findall(r"/(?:C|I|A):([A-Z])", text)
    high = [x for x in impacts if x in ("H", "C")]  # H = high (v3), C = complete (v2)
    if len(high) >= 3:
        return "critical"
    if high:
        return "high"
    return "medium"


def _summary(vuln: dict, pkg_name: str, version: str) -> str:
    summary = vuln.get("summary") or vuln.get("details") or vuln.get("id") or ""
    return f"{pkg_name}@{version}: {summary}"[:1000]


def _remediation(vuln: dict, pkg_name: str) -> str:
    fixed = vuln.get("database_specific", {}).get("fixed_version") if isinstance(
        vuln.get("database_specific"), dict
    ) else ""
    base = f"Update {pkg_name}" if pkg_name else "Update the affected dependency"
    if fixed:
        base += f" to a fixed version"
    refs = vuln.get("references") or []
    if refs:
        base += f". See: {refs[0].get('url', '')}"
    return base
