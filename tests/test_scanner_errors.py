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
