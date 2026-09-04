"""Central registry of scanner engines.

A single source of truth for engine identity, applicability, build and
status. Routers, the orchestrator and the /api/scanners/status endpoint all
derive their knowledge of engines from this module instead of maintaining
parallel hardcoded lists.

Registering a new engine = add one :class:`EngineSpec` to :data:`REGISTRY`
(plus its adapter under :mod:`src.scanners`). No other file needs editing.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from src.config import ENGINE_BINARIES
from src.scanners.base import Scanner, which_in_path
from src.scanners.opengrep_adapter import OpengrepAdapter

SOURCE_TYPES = ("sast", "sca", "secrets", "dast", "iac")


def _version(binary: str | None) -> str:
    if not binary:
        return ""
    try:
        proc = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            line = (proc.stdout or proc.stderr or "").strip().splitlines()
            return line[0][:80] if line else ""
    except (subprocess.SubprocessError, OSError):
        pass
    return ""


def _binary_status(name: str) -> dict:
    configured = ENGINE_BINARIES.get(name, name)
    binpath = which_in_path(configured)
    return {
        "available": bool(binpath),
        "version": _version(binpath),
    }


@dataclass(frozen=True)
class EngineContext:
    """Everything an engine factory needs to decide whether/how to run."""

    workdir: Path | None
    detected: list[str]
    # Scan inputs for engines that need them (currently only DAST/ZAP).
    scan_id: int | None = None
    dast_target: str | None = None
    # ZAP client provider; None when the platform has no ZAP configured.
    zap: "object | None" = None


@dataclass(frozen=True)
class EngineSpec:
    name: str
    source_type: str
    build: Callable[[EngineContext], Scanner | None]
    skip_reason: Callable[[EngineContext], str]
    status: Callable[[], dict]


# --------------------------------------------------------------------------- engines

def _skip_no_workdir(name: str) -> Callable[[EngineContext], str]:
    return lambda _ctx: f"{name} requires a local checkout"


def _skip_bandit(ctx: EngineContext) -> str:
    return "bandit is skipped: no Python files detected"


def _build_bandit(ctx: EngineContext) -> Scanner | None:
    if ctx.workdir is None or "python" not in ctx.detected:
        return None
    from src.scanners.bandit_adapter import BanditAdapter

    return BanditAdapter(ctx.workdir)


def _skip_opengrep(ctx: EngineContext) -> str:
    return "opengrep is skipped: no matching local rules for the detected languages"


def _build_opengrep(ctx: EngineContext) -> Scanner | None:
    if ctx.workdir is None:
        return None
    from src.config import parse_bool
    import os

    from src.util.language import opengrep_languages

    adapter = OpengrepAdapter(ctx.workdir, languages=opengrep_languages(ctx.detected))
    if adapter.rule_files():
        return adapter
    # Registry packs are only reachable when explicitly enabled.
    if parse_bool(os.getenv("SCP_OPENGREP_ALLOW_REGISTRY", ""), name="SCP_OPENGREP_ALLOW_REGISTRY"):
        return adapter
    return None


def _build_trivy(ctx: EngineContext) -> Scanner | None:
    if ctx.workdir is None:
        return None
    from src.scanners.trivy_adapter import TrivyAdapter

    return TrivyAdapter(ctx.workdir)


def _build_gitleaks(ctx: EngineContext) -> Scanner | None:
    if ctx.workdir is None:
        return None
    from src.scanners.gitleaks_adapter import GitleaksAdapter

    return GitleaksAdapter(ctx.workdir)


def _build_checkov(ctx: EngineContext) -> Scanner | None:
    if ctx.workdir is None:
        return None
    from src.scanners.checkov_adapter import CheckovAdapter

    return CheckovAdapter(ctx.workdir)


def _build_osv(ctx: EngineContext) -> Scanner | None:
    if ctx.workdir is None:
        return None
    from src.scanners.osv_adapter import OsvScannerAdapter

    return OsvScannerAdapter(ctx.workdir)


def _build_zap(ctx: EngineContext) -> Scanner | None:
    if ctx.zap is None:
        return None
    if not ctx.zap.available():
        return None
    from src.scanners.dast_scanner import DastScanner

    return DastScanner(zap=ctx.zap, scan_id=ctx.scan_id, dast_target=ctx.dast_target)


def _status_zap() -> dict:
    from src.dast.zap_client import ZapClient

    zap = ZapClient()
    return {
        "available": True,
        "reachable": zap.available(),
        "url": zap.base_url,
    }


def _status_opengrep() -> dict:
    import os

    from src.config import RULES_PACK_DIR

    adapter = OpengrepAdapter(Path("."))
    return {
        "available": adapter.available(),
        "implementation": "opengrep" if (adapter.binary and adapter._is_opengrep) else "semgrep",
        "version": _version(adapter.binary),
        "rules": "local" if _local_rules_available(RULES_PACK_DIR) else "registry",
    }


def _local_rules_available(pack: Path) -> bool:
    if not pack.is_dir():
        return False
    return any(pack.rglob("*.yaml")) or any(pack.rglob("*.yml"))


REGISTRY: dict[str, EngineSpec] = {
    "bandit": EngineSpec(
        name="bandit",
        source_type="sast",
        build=_build_bandit,
        skip_reason=_skip_bandit,
        status=lambda: _binary_status("bandit"),
    ),
    "opengrep": EngineSpec(
        name="opengrep",
        source_type="sast",
        build=_build_opengrep,
        skip_reason=_skip_opengrep,
        status=_status_opengrep,
    ),
    "trivy": EngineSpec(
        name="trivy",
        source_type="sca",
        build=_build_trivy,
        skip_reason=_skip_no_workdir("trivy"),
        status=lambda: _binary_status("trivy"),
    ),
    "gitleaks": EngineSpec(
        name="gitleaks",
        source_type="secrets",
        build=_build_gitleaks,
        skip_reason=_skip_no_workdir("gitleaks"),
        status=lambda: _binary_status("gitleaks"),
    ),
    "checkov": EngineSpec(
        name="checkov",
        source_type="iac",
        build=_build_checkov,
        skip_reason=_skip_no_workdir("checkov"),
        status=lambda: _binary_status("checkov"),
    ),
    "osv-scanner": EngineSpec(
        name="osv-scanner",
        source_type="sca",
        build=_build_osv,
        skip_reason=_skip_no_workdir("osv-scanner"),
        status=lambda: _binary_status("osv-scanner"),
    ),
    "zap": EngineSpec(
        name="zap",
        source_type="dast",
        build=_build_zap,
        skip_reason=lambda _ctx: "zap is not reachable (is ZAP running at the configured API URL?)",
        status=_status_zap,
    ),
}


# --------------------------------------------------------------------------- helpers

def all_engines() -> list[str]:
    """Every registered engine name (stable order)."""
    return list(REGISTRY)


def engine_source_types() -> dict[str, str]:
    """engine name -> source type."""
    return {name: spec.source_type for name, spec in REGISTRY.items()}


def source_types() -> tuple[str, ...]:
    """All source types that have at least one registered engine."""
    return tuple(sorted({spec.source_type for spec in REGISTRY.values()}))


def resolve_engines(scan) -> list[str]:
    """Resolve the engine list for a scan.

    Explicit per-scan engine selections are honored (filtered to known
    engines); otherwise the set is derived from the scan type via source_type.
    """
    if scan.engines:
        return [e for e in scan.engines.split(",") if e in REGISTRY]

    by_scan_type = {
        "sast": {"sast"},
        "sca": {"sca"},
        "secrets": {"secrets"},
        "dast": {"dast"},
        "iac": {"iac"},
    }
    if scan.scan_type == "full":
        targets = {"sast", "sca", "secrets", "iac"}
    else:
        targets = by_scan_type.get(scan.scan_type, {"sast"})
    return [name for name, spec in REGISTRY.items() if spec.source_type in targets]


def is_registered(name: str) -> bool:
    return name in REGISTRY
