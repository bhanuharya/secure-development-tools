from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

from src.config import ENGINE_BINARIES, RULES_PACK_DIR
from src.scanners.base import RawFinding, Scanner, normalize_severity

log = logging.getLogger(__name__)

_REGISTRY_RULES = ["p/owasp-top-ten", "p/security-audit"]


class OpengrepAdapter(Scanner):
    """Multi-language SAST engine.

    Preferred engine: opengrep (fully-open community fork). Falls back to the
    semgrep CLI when opengrep is absent. Loads a committed local rule pack under
    ``rules/opengrep-rules/``; registry packs are used only as a fallback when no
    local rules exist.
    """

    name = "opengrep"
    source_type = "sast"
    _probe_cache: dict[str, bool] = {}

    def __init__(self, workdir: Path, languages: list[str] | None = None) -> None:
        super().__init__(workdir)
        self.languages = languages or []
        self._binary = None
        self._is_opengrep = True

    @property
    def binary(self) -> str | None:
        if self._binary:
            return self._binary
        from src.scanners.base import which_in_path

        for name in ("opengrep", "semgrep"):
            configured = ENGINE_BINARIES.get(name, name)
            found = which_in_path(configured)
            if not found:
                continue
            if not self._probe(found):
                log.warning("engine binary %s present but not runnable; trying next", found)
                continue
            self._binary = found
            self._is_opengrep = name == "opengrep"
            return found
        return None

    @classmethod
    def _probe(cls, binary: str) -> bool:
        if binary in cls._probe_cache:
            return cls._probe_cache[binary]
        try:
            proc = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=30)
            ok = proc.returncode == 0
        except (subprocess.SubprocessError, OSError):
            ok = False
        cls._probe_cache[binary] = ok
        return ok

    def rule_files(self) -> list[Path]:
        """Deterministic list of local rule files applicable to this scan."""
        return _rule_files(self.languages)

    def _run(self) -> list[RawFinding]:
        rules = self.rule_files()
        if not rules and not os.getenv("SCP_OPENGREP_ALLOW_REGISTRY"):
            log.warning(
                "no local rules and SCP_OPENGREP_ALLOW_REGISTRY is not set — "
                "skipping %s (offline-safe)",
                self.name,
            )
            return []
        quiet = "-q" if self._is_opengrep else "--quiet"
        args = ["scan", "--json", quiet]
        if rules:
            for rule in rules:
                args += ["--config", str(rule)]
        else:
            for registry in _REGISTRY_RULES:
                args += ["--config", registry]
        if self._is_opengrep:
            args += ["--timeout", "60", "--max-target-bytes", "5000000"]
        args.append(str(self.workdir))
        proc = self._exec(args, timeout=3600)
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"{self.name} exited {proc.returncode}: {(proc.stderr or '')[:300]}")
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{self.name} returned invalid JSON") from exc

        findings: list[RawFinding] = []
        for r in data.get("results", []):
            extra = r.get("extra", {}) or {}
            meta = extra.get("metadata", {}) or {}
            severity = normalize_severity(extra.get("severity") or meta.get("severity") or "warning")
            if severity == "info" and meta.get("category") == "security":
                severity = "medium"
            start = (r.get("start") or {}).get("line")
            end = (r.get("end") or {}).get("line")
            findings.append(
                RawFinding(
                    tool=self.name,
                    source_type=self.source_type,
                    rule_id=_clean_rule_id(r.get("check_id", "")),
                    severity=severity,
                    cwe=_normalize_cwe(meta.get("cwe")),
                    file_path=r.get("path", ""),
                    line_start=start,
                    line_end=end,
                    snippet=_result_snippet(extra.get("lines") or "", self.workdir, r.get("path", ""), start, end),
                    description=extra.get("message", "") or "",
                    remediation=extra.get("fix", "") or "",
                    raw=r,
                )
            )
        return findings


def _result_snippet(lines: str, workdir: Path, path: str, start: int | None, end: int | None) -> str:
    """Semgrep often leaves `extra.lines` empty (or sets the placeholder
    'requires login') in JSON output, so fall back to reading the matched lines
    from the checkout on disk."""
    if lines and lines.strip() and lines.strip() != "requires login":
        return "\n".join(lines.splitlines()[:40])[:2000]
    return _read_lines(workdir, path, start, end)


def _read_lines(workdir: Path, path: str, start: int | None, end: int | None) -> str:
    if not path or start is None:
        return ""
    p = Path(path)
    if not p.is_absolute():
        p = workdir / p
    try:
        source = p.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    lo = max(1, start)
    hi = min(len(source), (end or start))
    if lo > len(source):
        return ""
    return "\n".join(source[lo - 1:hi])[:2000]


def _clean_rule_id(check_id: str) -> str:
    """Semgrep prefixes rule IDs with the config path when rules are loaded
    from local files. Keep the stable ``scp.*`` rule identifier only."""
    s = check_id or ""
    idx = s.find("scp.")
    return s[idx:] if idx != -1 else s


def _normalize_cwe(value) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        value = value.get("id") or value.get("name") or ""
    if isinstance(value, list):
        value = value[0] if value else ""
    if not value:
        return ""
    s = str(value).strip().upper()
    return s if s.startswith("CWE-") else f"CWE-{s}"


def _rule_files(languages: list[str]) -> list[Path]:
    """Collect applicable rule YAML files from the local pack.

    Always loads ``common/`` plus directories matching the detected languages,
    plus any vendored third-party rules. Ordering is deterministic (sorted).
    """
    pack = Path(os.getenv("SCP_RULES_PACK_DIR", str(RULES_PACK_DIR)))
    files: list[Path] = []
    if pack.is_dir():
        for sub in ["common", *(languages or [])]:
            d = pack / sub
            if d.is_dir():
                files.extend(sorted(d.glob("*.yaml")))
                files.extend(sorted(d.glob("*.yml")))
        vendor = pack / "vendor"
        if vendor.is_dir():
            files.extend(sorted(vendor.glob("**/*.yaml")))
            files.extend(sorted(vendor.glob("**/*.yml")))

    seen: set[str] = set()
    out: list[Path] = []
    for f in files:
        key = str(f.resolve())
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
