from __future__ import annotations

import json
import os

from src.scanners.base import RawFinding, Scanner, normalize_severity


class BanditAdapter(Scanner):
    name = "bandit"
    source_type = "sast"

    def _run(self) -> list[RawFinding]:
        args = ["-f", "json", "-q", "-r", str(self.workdir)]
        min_sev = (os.getenv("SCP_BANDIT_MIN_SEVERITY", "") or "").strip().lower()
        sev_flag = {"low": "-lll", "medium": "-ll", "high": "-l"}.get(min_sev)
        if sev_flag:
            args.insert(0, sev_flag)
        proc = self._exec(args, timeout=1800)
        if proc.returncode not in (0, 1):  # bandit returns 1 when issues found
            return []
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []
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
