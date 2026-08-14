from __future__ import annotations

import json
import logging
import os
import tempfile

from src.scanners.base import RawFinding, Scanner

log = logging.getLogger(__name__)


class GitleaksAdapter(Scanner):
    name = "gitleaks"
    source_type = "secrets"

    def _run(self) -> list[RawFinding]:
        fd, report_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            self._exec(
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
            with open(report_path) as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("gitleaks parse failed: %s", exc)
            return []
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass

        findings: list[RawFinding] = []
        for item in data if isinstance(data, list) else []:
            secret = item.get("Secret", "") or ""
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
                    raw=item,
                )
            )
        return findings


def _redact(match: str, secret: str) -> str:
    """Never persist the actual secret material in snippets."""
    if secret and match:
        return match.replace(secret, "[REDACTED]")
    return match
