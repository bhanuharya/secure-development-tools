from __future__ import annotations

import json
import logging
import os
import tempfile

from src.scanners.base import RawFinding, Scanner, normalize_severity

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
        if os.getenv("SCP_TRIVY_IGNORE_UNFIXED"):
            args.insert(-1, "--ignore-unfixed")
        self._exec(args, timeout=3600)
        try:
            with open(report_path) as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return []
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass

        findings: list[RawFinding] = []
        for target in data.get("Results", []):
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
