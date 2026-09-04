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
        # OSV commonly supplies a numeric score, sometimes embedded in text.
        nums = re.findall(r"(?<![0-9])(?:10(?:\\.0)?|[0-9](?:\\.[0-9])?)(?![0-9])", raw)
        if nums:
            score = float(nums[0])
            values.append("critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low")
        elif raw:
            values.append("high" if "A:H" in raw else "medium")
    return max(values, key=lambda x: rank[x]) if values else "medium"


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
