from __future__ import annotations

import json
import logging
import os
import tempfile

from src.scanners.base import RawFinding, Scanner
from src.scanners.errors import ScannerExecutionError, ScannerMalformedOutputError

log = logging.getLogger(__name__)


class GitleaksAdapter(Scanner):
    name = "gitleaks"
    source_type = "secrets"

    def _run(self) -> list[RawFinding]:
        fd, report_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            proc = self._exec(
                [
                    "dir",
                    str(self.workdir),
                    "--report-format", "json",
                    "--report-path", report_path,
                    "--redact",
                    "--no-banner",
                ],
                timeout=1800,
            )
            # gitleaks returns 1 when leaks are found, 0 when clean.
            if proc.returncode not in (0, 1):
                raise ScannerExecutionError(
                    self.name, f"gitleaks exited {proc.returncode}: {(proc.stderr or '')[:300]}"
                )
            try:
                with open(report_path) as fh:
                    data = json.load(fh)
            except (json.JSONDecodeError, OSError) as exc:
                raise ScannerMalformedOutputError(
                    self.name, "gitleaks produced an unreadable/malformed report"
                ) from exc
            if not isinstance(data, list):
                raise ScannerMalformedOutputError(self.name, "gitleaks report must be a JSON array")
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass

        findings: list[RawFinding] = []
        for item in data if isinstance(data, list) else []:
            secret = item.get("Secret", "") or ""
            # Scanner output can contain the live credential and full matched
            # source line. Keep neither in RawFinding.raw, which may be logged
            # or normalized later. A repr-hidden transient token is used only
            # for context redaction before persistence.
            safe_raw = {
                key: value for key, value in item.items()
                if key not in {"Secret", "secret", "Match", "match"}
            }
            findings.append(
                RawFinding(
                    tool=self.name,
                    source_type=self.source_type,
                    rule_id=item.get("RuleID", ""),
                    severity="high",
                    file_path=item.get("File", ""),
                    line_start=item.get("StartLine"),
                    line_end=item.get("EndLine"),
                    snippet=_redact((item.get("Match") or "")[:200], secret),
                    description=(item.get("Description") or "")[:1000],
                    remediation="Rotate the leaked secret and remove it from source. Use CI/CD secrets or a vault.",
                    raw=safe_raw,
                    redaction_tokens=[secret] if secret else [],
                )
            )
        return findings


def _redact(match: str, secret: str) -> str:
    """Never persist the actual secret material in snippets."""
    if secret and match:
        return match.replace(secret, "[REDACTED]")
    return match
