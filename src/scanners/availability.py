from __future__ import annotations

import subprocess
from pathlib import Path

from src.config import ENGINE_BINARIES, RULES_PACK_DIR
from src.scanners.base import which_in_path


def _version(binary: str) -> str:
    try:
        proc = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            line = (proc.stdout or proc.stderr or "").strip().splitlines()
            return line[0][:80] if line else ""
    except (subprocess.SubprocessError, OSError):
        pass
    return ""


def _local_rules_available() -> bool:
    pack = Path(RULES_PACK_DIR)
    if not pack.is_dir():
        return False
    return any(pack.rglob("*.yaml")) or any(pack.rglob("*.yml"))


def engine_statuses() -> dict:
    out: dict = {}
    for name in ("bandit", "trivy", "gitleaks"):
        configured = ENGINE_BINARIES.get(name, name)
        binpath = which_in_path(configured)
        out[name] = {
            "available": bool(binpath),
            "version": _version(binpath) if binpath else "",
        }

    from src.scanners.opengrep_adapter import OpengrepAdapter

    adapter = OpengrepAdapter(Path("."))
    out["opengrep"] = {
        "available": adapter.available(),
        "implementation": "opengrep" if (adapter.binary and adapter._is_opengrep) else "semgrep",
        "version": _version(adapter.binary) if adapter.binary else "",
        "rules": "local" if _local_rules_available() else "registry",
    }
    return out
