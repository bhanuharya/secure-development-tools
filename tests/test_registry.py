import json

from src.scanners import availability
from src.scanners.registry import (
    REGISTRY,
    all_engines,
    engine_source_types,
    resolve_engines,
    source_types,
)


class FakeScan:
    def __init__(self, engines="", scan_type="sast"):
        self.engines = engines
        self.scan_type = scan_type


def test_every_engine_has_valid_source_type():
    for name, spec in REGISTRY.items():
        assert spec.name == name
        assert spec.source_type in {"sast", "sca", "secrets", "dast", "iac"}


def test_all_engines_stable_and_registered():
    assert set(all_engines()) == set(REGISTRY)
    assert all_engines() == sorted(all_engines(), key=all_engines().index)


def test_source_type_mapping_matches_registry():
    assert engine_source_types() == {n: s.source_type for n, s in REGISTRY.items()}


def test_every_source_type_reported():
    types = set(source_types())
    assert {"sast", "sca", "secrets", "dast", "iac"} <= types


def test_resolve_explicit_engines_filters_unknown():
    scan = FakeScan(engines="bandit,trivy,does-not-exist,zap")
    assert resolve_engines(scan) == ["bandit", "trivy", "zap"]


def test_resolve_scan_types_from_source_types():
    assert "bandit" in resolve_engines(FakeScan(scan_type="sast"))
    assert "opengrep" in resolve_engines(FakeScan(scan_type="sast"))
    assert "trivy" in resolve_engines(FakeScan(scan_type="sca"))
    assert "osv-scanner" in resolve_engines(FakeScan(scan_type="sca"))
    assert "gitleaks" in resolve_engines(FakeScan(scan_type="secrets"))
    assert "zap" in resolve_engines(FakeScan(scan_type="dast"))
    assert "checkov" in resolve_engines(FakeScan(scan_type="full"))


def test_resolve_iac_scan_type_runs_iac_engines_only():
    engines = resolve_engines(FakeScan(scan_type="iac"))
    assert "checkov" in engines
    # No SAST engines on an iac scan (regression: previously resolved to the
    # sast default set). trivy is registered as sca, so it is applied via the
    # upload preset (explicit engines), not via iac source-type resolution.
    assert "bandit" not in engines
    assert "opengrep" not in engines
    assert set(engines) <= {"checkov"}


def test_resolve_full_includes_sast_sca_secrets_not_dast():
    engines = resolve_engines(FakeScan(scan_type="full"))
    assert "zap" not in engines
    assert {"bandit", "opengrep", "trivy", "osv-scanner", "gitleaks", "checkov"} <= set(engines)


def test_status_shape_for_every_engine():
    statuses = availability.engine_statuses()
    assert set(statuses) == set(REGISTRY)
    for name, status in statuses.items():
        assert "available" in status
        if name == "zap":
            assert "reachable" in status
        else:
            assert "version" in status


def test_every_engine_has_skip_reason_and_build():
    from src.scanners.registry import EngineContext

    ctx = EngineContext(workdir=None, detected=[])
    for name, spec in REGISTRY.items():
        assert callable(spec.skip_reason)
        assert callable(spec.build)
        assert isinstance(spec.skip_reason(ctx), str)


def test_new_engines_present_in_scanners_status_endpoint():
    statuses = availability.engine_statuses()
    assert "checkov" in statuses
    assert "osv-scanner" in statuses
    assert "zap" in statuses
