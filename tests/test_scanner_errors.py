import subprocess

import pytest

from src.scanners.bandit_adapter import BanditAdapter
from src.scanners.errors import (
    ScannerExecutionError,
    ScannerMalformedOutputError,
    ScannerRuleError,
    ScannerTimeoutError,
)
from src.scanners.gitleaks_adapter import GitleaksAdapter
from src.scanners.opengrep_adapter import OpengrepAdapter
from src.scanners.trivy_adapter import TrivyAdapter


def _proc(returncode, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_bandit_malformed_output_raises(tmp_path, monkeypatch):
    def fake_exec(self, args, cwd=None, timeout=None):
        return _proc(0, stdout="not-json")

    monkeypatch.setattr(BanditAdapter, "_exec", fake_exec)
    with pytest.raises(ScannerMalformedOutputError):
        BanditAdapter(tmp_path)._run()


def test_bandit_bad_exit_code_raises(tmp_path, monkeypatch):
    def fake_exec(self, args, cwd=None, timeout=None):
        return _proc(2, stdout="{}", stderr="boom")

    monkeypatch.setattr(BanditAdapter, "_exec", fake_exec)
    with pytest.raises(ScannerExecutionError):
        BanditAdapter(tmp_path)._run()


def test_opengrep_malformed_output_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(OpengrepAdapter, "_exec", lambda self, *a, **k: _proc(0, stdout="nope"))
    # ensure some rule exists so we don't take the offline skip path
    (tmp_path / "common").mkdir()
    (tmp_path / "common" / "r.yaml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setenv("SCP_RULES_PACK_DIR", str(tmp_path))
    with pytest.raises(ScannerMalformedOutputError):
        OpengrepAdapter(tmp_path, languages=["python"])._run()


def test_opengrep_config_error_raises(tmp_path, monkeypatch):
    (tmp_path / "common").mkdir()
    (tmp_path / "common" / "r.yaml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setenv("SCP_RULES_PACK_DIR", str(tmp_path))
    monkeypatch.setattr(
        OpengrepAdapter, "_exec", lambda self, *a, **k: _proc(2, stdout="{}", stderr="invalid config")
    )
    with pytest.raises(ScannerRuleError):
        OpengrepAdapter(tmp_path, languages=["python"])._run()


def test_gitleaks_malformed_report_raises(tmp_path, monkeypatch):
    def fake_exec(self, args, cwd=None, timeout=None):
        idx = args.index("--report-path")
        with open(args[idx + 1], "w", encoding="utf-8") as fh:
            fh.write("not-json")
        return _proc(0)

    monkeypatch.setattr(GitleaksAdapter, "_exec", fake_exec)
    with pytest.raises(ScannerMalformedOutputError):
        GitleaksAdapter(tmp_path)._run()


def test_gitleaks_bad_exit_code_raises(tmp_path, monkeypatch):
    def fake_exec(self, args, cwd=None, timeout=None):
        idx = args.index("--report-path")
        with open(args[idx + 1], "w", encoding="utf-8") as fh:
            fh.write("[]")
        return _proc(2, stderr="gitleaks crashed")

    monkeypatch.setattr(GitleaksAdapter, "_exec", fake_exec)
    with pytest.raises(ScannerExecutionError):
        GitleaksAdapter(tmp_path)._run()


def test_gitleaks_raw_finding_does_not_retain_secret_or_match(tmp_path, monkeypatch):
    secret = "sk_live_1234567890abcdef"

    def fake_exec(self, args, cwd=None, timeout=None):
        import json

        idx = args.index("--report-path")
        with open(args[idx + 1], "w", encoding="utf-8") as fh:
            json.dump([{
                "RuleID": "stripe-access-token",
                "File": "app.py",
                "StartLine": 1,
                "EndLine": 1,
                "Secret": secret,
                "Match": f'api_key = "{secret}"',
                "Description": "Stripe token",
            }], fh)
        return _proc(1)

    monkeypatch.setattr(GitleaksAdapter, "_exec", fake_exec)
    finding = GitleaksAdapter(tmp_path)._run()[0]
    assert secret not in finding.snippet
    assert "Secret" not in finding.raw
    assert "Match" not in finding.raw
    assert secret not in repr(finding.raw)


def test_scanner_timeout_raises_typed_error(tmp_path, monkeypatch):
    def boom(cmd, cwd=None, capture_output=False, text=False, timeout=None):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout or 1)

    monkeypatch.setattr("src.scanners.base.subprocess.run", boom)
    with pytest.raises(ScannerTimeoutError):
        BanditAdapter(tmp_path)._run()


def test_scanners_reject_missing_required_json_schema(tmp_path, monkeypatch):
    monkeypatch.setattr(BanditAdapter, "_exec", lambda self, *a, **k: _proc(0, stdout="{}"))
    with pytest.raises(ScannerMalformedOutputError):
        BanditAdapter(tmp_path)._run()

    rules = tmp_path / "rules"
    (rules / "common").mkdir(parents=True)
    (rules / "common" / "r.yaml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setenv("SCP_RULES_PACK_DIR", str(rules))
    monkeypatch.setattr(OpengrepAdapter, "_exec", lambda self, *a, **k: _proc(0, stdout="{}"))
    with pytest.raises(ScannerMalformedOutputError):
        OpengrepAdapter(tmp_path, languages=["python"])._run()

    def write_report(adapter, args, cwd=None, timeout=None):
        marker = "--report-path" if "--report-path" in args else "--output"
        with open(args[args.index(marker) + 1], "w", encoding="utf-8") as fh:
            fh.write("{}")
        return _proc(0)

    monkeypatch.setattr(GitleaksAdapter, "_exec", write_report)
    with pytest.raises(ScannerMalformedOutputError):
        GitleaksAdapter(tmp_path)._run()
    monkeypatch.setattr(TrivyAdapter, "_exec", write_report)
    with pytest.raises(ScannerMalformedOutputError):
        TrivyAdapter(tmp_path)._run()


def test_trivy_valid_clean_report_without_results_is_accepted(tmp_path, monkeypatch):
    def clean_report(self, args, cwd=None, timeout=None):
        import json

        idx = args.index("--output")
        with open(args[idx + 1], "w", encoding="utf-8") as fh:
            json.dump({
                "SchemaVersion": 2,
                "CreatedAt": "2026-08-14T00:00:00Z",
                "ArtifactName": str(tmp_path),
                "ArtifactType": "filesystem",
                "Trivy": {"Version": "0.73.0"},
            }, fh)
        return _proc(0)

    monkeypatch.setattr(TrivyAdapter, "_exec", clean_report)
    assert TrivyAdapter(tmp_path)._run() == []


def test_trivy_maven_429_retries_once_offline_and_marks_degraded(tmp_path, monkeypatch):
    calls = []

    def rate_limited_then_offline(self, args, cwd=None, timeout=None):
        import json

        calls.append(list(args))
        if len(calls) == 1:
            return _proc(
                1,
                stderr=(
                    "FATAL Error remote Maven repository returned 429 Too Many Requests "
                    "for https://repo.maven.apache.org/example.pom. Retry-After: 1800."
                ),
            )
        idx = args.index("--output")
        with open(args[idx + 1], "w", encoding="utf-8") as fh:
            json.dump({"SchemaVersion": 2, "ArtifactName": str(tmp_path)}, fh)
        return _proc(0)

    monkeypatch.setattr(TrivyAdapter, "_exec", rate_limited_then_offline)
    adapter = TrivyAdapter(tmp_path)

    assert adapter._run() == []
    assert len(calls) == 2
    assert "--offline-scan" not in calls[0]
    assert "--offline-scan" in calls[1]
    assert "Retry-After: 1800" in adapter.degraded_reason
    assert "reduced dependency coverage" in adapter.degraded_reason


def test_trivy_non_maven_failure_is_not_retried_offline(tmp_path, monkeypatch):
    calls = []

    def crash(self, args, cwd=None, timeout=None):
        calls.append(list(args))
        return _proc(1, stderr="FATAL database is corrupt")

    monkeypatch.setattr(TrivyAdapter, "_exec", crash)
    with pytest.raises(ScannerExecutionError, match="database is corrupt"):
        TrivyAdapter(tmp_path)._run()
    assert len(calls) == 1


def test_trivy_failed_offline_fallback_preserves_maven_429_as_primary(tmp_path, monkeypatch):
    calls = []
    primary = (
        "FATAL Error remote Maven repository returned 429 Too Many Requests "
        "for https://repo.maven.apache.org/example.pom. Retry-After: 1800."
    )

    def both_fail(self, args, cwd=None, timeout=None):
        calls.append(list(args))
        if len(calls) == 1:
            return _proc(1, stderr=primary)
        return _proc(1, stderr="offline analyzer failed")

    monkeypatch.setattr(TrivyAdapter, "_exec", both_fail)
    with pytest.raises(ScannerExecutionError) as raised:
        TrivyAdapter(tmp_path)._run()
    assert len(calls) == 2
    assert "429 Too Many Requests" in raised.value.message
    assert "Retry-After: 1800" in raised.value.message
    assert "offline fallback also failed" in raised.value.message
