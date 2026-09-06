"""Checkov adapter — IaC misconfiguration scanning.

Runs ``checkov -d <workdir> --output json`` against Terraform, Kubernetes,
Dockerfile, CloudFormation and other Infrastructure-as-Code definitions, the
de-facto IaC scanner in CI/CD pipelines.
"""

from __future__ import annotations

import json

from src.scanners.base import RawFinding, Scanner, normalize_severity
from src.scanners.errors import ScannerExecutionError, ScannerMalformedOutputError


class CheckovAdapter(Scanner):
    name = "checkov"
    source_type = "iac"

    def _run(self) -> list[RawFinding]:
        # checkov exits 0 when no failures and 1 when failures are found.
        # Use the compact form to keep stdout parseable regardless of TTY.
        proc = self._exec(
            [
                "-d", str(self.workdir),
                "--output", "json",
                "--quiet",
                "--no-guide",
                "--compact",
            ],
            timeout=3600,
        )
        if proc.returncode not in (0, 1):
            raise ScannerExecutionError(
                self.name, f"checkov exited {proc.returncode}: {(proc.stderr or '')[:300]}"
            )
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ScannerMalformedOutputError(
                self.name, "checkov returned invalid JSON output"
            ) from exc
        if not isinstance(data, dict) or not isinstance(data.get("results"), dict):
            raise ScannerMalformedOutputError(
                self.name, "checkov JSON is missing a results object"
            )

        findings: list[RawFinding] = []
        failed = data["results"].get("failed_checks") or []
        if not isinstance(failed, list):
            raise ScannerMalformedOutputError(self.name, "checkov failed_checks must be an array")
        for item in failed:
            check_result = item.get("check_result") or {}
            if check_result.get("result") == "SKIPPED":
                continue
            line_range = item.get("file_line_range") or []
            start = line_range[0] if line_range else None
            end = line_range[1] if len(line_range) > 1 else start
            findings.append(
                RawFinding(
                    tool=self.name,
                    source_type=self.source_type,
                    rule_id=item.get("check_id", ""),
                    severity=normalize_severity(item.get("severity")),
                    file_path=item.get("file", ""),
                    line_start=start,
                    line_end=end,
                    snippet=_snippet(item),
                    description=_description(item),
                    remediation=item.get("guideline", ""),
                    raw=item,
                )
            )
        return findings


def _snippet(item: dict) -> str:
    snippet = item.get("code_block") or []
    if not isinstance(snippet, list):
        return ""
    lines = []
    for entry in snippet:
        if isinstance(entry, (list, tuple)) and len(entry) > 1:
            lines.append(str(entry[1]))
    return "\n".join(lines)[:2000]


def _description(item: dict) -> str:
    parts = []
    if item.get("check_name"):
        parts.append(item["check_name"])
    resource = item.get("resource")
    if resource:
        parts.append(f"resource: {resource}")
    file_path = item.get("file")
    if file_path:
        parts.append(f"file: {file_path}")
    return " — ".join(parts)[:1000]
