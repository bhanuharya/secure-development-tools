from __future__ import annotations

import json
import logging
import os
import tempfile

from src.config import parse_bool
from src.scanners.base import RawFinding, Scanner, normalize_severity
from src.scanners.errors import ScannerExecutionError, ScannerMalformedOutputError

log = logging.getLogger(__name__)


class TrivyAdapter(Scanner):
    name = "trivy"
    source_type = "sca"

    def _run(self) -> list[RawFinding]:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name
        args = [
            "fs",
            "--quiet",
            "--format", "json",
            "--scanners", "vuln",
            "--severity", os.getenv("SCP_TRIVY_SEVERITY", "CRITICAL,HIGH,MEDIUM"),
            "--no-progress",
            "--exit-code", "0",
            "--skip-dirs", ".git,node_modules,vendor,dist,build,.venv,venv,target,__pycache__",
            "--output", report_path,
            str(self.workdir),
        ]
        if parse_bool(os.getenv("SCP_TRIVY_IGNORE_UNFIXED", ""), name="SCP_TRIVY_IGNORE_UNFIXED"):
            args.insert(-1, "--ignore-unfixed")
        proc = self._exec(args, timeout=3600)
        if proc.returncode != 0:
            raise ScannerExecutionError(
                self.name, f"trivy exited {proc.returncode}: {(proc.stderr or '')[:300]}"
            )
        try:
            with open(report_path) as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            raise ScannerMalformedOutputError(
                self.name, "trivy produced an unreadable/malformed report"
            ) from exc
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("SchemaVersion"), int)
            or not isinstance(data.get("ArtifactName"), str)
        ):
            raise ScannerMalformedOutputError(self.name, "trivy JSON is missing required report metadata")
        results = data.get("Results", [])
        if results is None:
            results = []
        if not isinstance(results, list):
            raise ScannerMalformedOutputError(self.name, "trivy Results must be an array or null")

        findings: list[RawFinding] = []
        for target in results:
            vulns = target.get("Vulnerabilities", [])
            target_file = target.get("Target", "")
            for v in vulns:
                pkg = v.get("PkgName", "")
                installed = v.get("InstalledVersion", "")
                fixed = v.get("FixedVersion", "")
                desc = v.get("Description", "")
                rem = f"Upgrade {pkg} from {installed}"
                if fixed:
                    rem += f" to {fixed}"
                if v.get("References"):
                    rem += f". See: {v['References'][0]}"
                cwes = v.get("CweIDs", [])
                findings.append(
                    RawFinding(
                        tool=self.name,
                        source_type=self.source_type,
                        rule_id=v.get("VulnerabilityID", ""),
                        severity=normalize_severity(v.get("Severity")),
                        cwe=cwes[0] if cwes else "",
                        file_path=target_file,
                        description=(desc or "")[:1000],
                        remediation=rem,
                        raw=v,
                    )
                )
        return findings
