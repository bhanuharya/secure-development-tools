from __future__ import annotations

import json
import os

from src.scanners.base import RawFinding, Scanner, normalize_severity
from src.scanners.errors import ScannerExecutionError, ScannerMalformedOutputError


class BanditAdapter(Scanner):
    name = "bandit"
    source_type = "sast"

    def _run(self) -> list[RawFinding]:
        args = ["-f", "json", "-q", "-r", str(self.workdir)]
        min_sev = (os.getenv("SCP_BANDIT_MIN_SEVERITY", "") or "").strip().lower()
        if min_sev in ("low", "medium", "high"):
            args.insert(0, "--severity-level")
            args.insert(1, min_sev)
        proc = self._exec(args, timeout=1800)
        if proc.returncode not in (0, 1):  # bandit returns 1 when issues found
            raise ScannerExecutionError(
                self.name, f"bandit exited {proc.returncode}: {(proc.stderr or '')[:300]}"
            )
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ScannerMalformedOutputError(
                self.name, "bandit returned invalid JSON output"
            ) from exc
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ScannerMalformedOutputError(self.name, "bandit JSON is missing a results array")
        findings: list[RawFinding] = []
        for item in data.get("results", []):
            cwes = item.get("issue_cwe", {})
            cwe = f"CWE-{cwes.get('id')}" if cwes and cwes.get("id") else ""
            code_lines = item.get("code", "")
            line_start = item.get("line_number")
            findings.append(
                RawFinding(
                    tool=self.name,
                    source_type=self.source_type,
                    rule_id=item.get("test_id", ""),
                    severity=normalize_severity(item.get("issue_severity")),
                    cwe=cwe,
                    file_path=item.get("filename", ""),
                    line_start=line_start,
                    line_end=line_start,
                    col_start=item.get("col_offset"),
                    col_end=item.get("end_col_offset"),
                    snippet=_extract_snippet(code_lines),
                    description=item.get("issue_text", ""),
                    remediation=item.get("more_info", ""),
                    raw=item,
                )
            )
        return findings


def _extract_snippet(code: str) -> str:
    """Bandit embeds source lines in its output; extract the actual lines."""
    lines: list[str] = []
    for ln in (code or "").splitlines():
        ln = ln.lstrip("0123456789")
        if ln.startswith(">>>") or ln.startswith("   "):
            lines.append(ln.strip())
    return "\n".join(lines)[:2000]
