import subprocess

import pytest

from src.scanners.bandit_adapter import BanditAdapter
from src.scanners.base import RawFinding, normalize_severity
from src.scanners.opengrep_adapter import OpengrepAdapter, _read_lines
from src.scanners.orchestrator import _dedup, _rel_path
from src.scanners.trivy_adapter import TrivyAdapter


def _ok_proc():
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")


def test_normalize_severity_unknown_maps_to_info():
    assert normalize_severity("UNKNOWN") == "info"
    assert normalize_severity("unknown") == "info"
    # truly unrecognized values still fall back to low
    assert normalize_severity("gibberish") == "low"


def test_trivy_adapter_args(tmp_path, monkeypatch):
    captured = {}

    def fake_exec(self, args, cwd=None, timeout=None):
        captured["args"] = args
        idx = args.index("--output")
        with open(args[idx + 1], "w", encoding="utf-8") as fh:
            fh.write('{"Results": []}')
        return _ok_proc()

    monkeypatch.setattr(TrivyAdapter, "_exec", fake_exec)
    adapter = TrivyAdapter(tmp_path)
    adapter._run()

    args = captured["args"]
    assert "--scanners" in args
    assert "vuln" in args
    skip_idx = args.index("--skip-dirs")
    assert "node_modules" in args[skip_idx + 1]
    sev_idx = args.index("--severity")
    assert args[sev_idx + 1] == "CRITICAL,HIGH,MEDIUM"
    assert "--ignore-unfixed" not in args

    monkeypatch.setenv("SCP_TRIVY_SEVERITY", "HIGH")
    adapter._run()
    args = captured["args"]
    sev_idx = args.index("--severity")
    assert args[sev_idx + 1] == "HIGH"

    monkeypatch.setenv("SCP_TRIVY_IGNORE_UNFIXED", "1")
    adapter._run()
    assert "--ignore-unfixed" in captured["args"]


def test_opengrep_offline_skips_when_no_rules(tmp_path, monkeypatch):
    monkeypatch.delenv("SCP_OPENGREP_ALLOW_REGISTRY", raising=False)
    monkeypatch.setenv("SCP_RULES_PACK_DIR", str(tmp_path))

    def boom(self, args, cwd=None, timeout=None):
        raise AssertionError("_exec must not be called offline without rules")

    monkeypatch.setattr(OpengrepAdapter, "_exec", boom)
    adapter = OpengrepAdapter(tmp_path)
    assert adapter._run() == []


def test_opengrep_scans_gitignored_staging_workdir(tmp_path, monkeypatch):
    captured = {}
    rules = tmp_path / "rules"
    (rules / "python").mkdir(parents=True)
    (rules / "python" / "security.yaml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setenv("SCP_RULES_PACK_DIR", str(rules))

    def fake_exec(self, args, cwd=None, timeout=None):
        captured["args"] = args
        return subprocess.CompletedProcess(args=args, returncode=0, stdout='{"results": []}', stderr="")

    monkeypatch.setattr(OpengrepAdapter, "_exec", fake_exec)
    OpengrepAdapter(tmp_path, languages=["python"])._run()
    assert "--no-git-ignore" in captured["args"]


@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_bandit_min_severity_args(tmp_path, monkeypatch, level):
    captured = {}

    def fake_exec(self, args, cwd=None, timeout=None):
        captured["args"] = args
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='{"results": []}', stderr="")

    monkeypatch.setattr(BanditAdapter, "_exec", fake_exec)
    adapter = BanditAdapter(tmp_path)

    monkeypatch.setenv("SCP_BANDIT_MIN_SEVERITY", level)
    adapter._run()
    assert "--severity-level" in captured["args"]
    assert captured["args"][captured["args"].index("--severity-level") + 1] == level


def test_bandit_no_min_severity_omits_flag(tmp_path, monkeypatch):
    captured = {}

    def fake_exec(self, args, cwd=None, timeout=None):
        captured["args"] = args
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='{"results": []}', stderr="")

    monkeypatch.setattr(BanditAdapter, "_exec", fake_exec)
    adapter = BanditAdapter(tmp_path)

    monkeypatch.delenv("SCP_BANDIT_MIN_SEVERITY", raising=False)
    adapter._run()
    assert "--severity-level" not in captured["args"]


def test_orchestrator_dedup_after_path_normalization():
    workdir = "/workdir"
    f1 = RawFinding(
        tool="bandit", source_type="sast", rule_id="B101", severity="high",
        file_path=f"{workdir}/src/x.py", line_start=1,
    )
    f2 = RawFinding(
        tool="bandit", source_type="sast", rule_id="B101", severity="high",
        file_path="src/x.py", line_start=1,
    )
    normalized = []
    for f in (f1, f2):
        f.file_path = _rel_path(f.file_path, workdir)
        normalized.append(f)
    assert len(_dedup(normalized)) == 1


def test_opengrep_snippet_fallback_refuses_outside_workspace(tmp_path):
    outside = tmp_path.parent / "outside-sensitive.txt"
    outside.write_text("must-not-be-read\n", encoding="utf-8")
    workdir = tmp_path / "scan"
    workdir.mkdir()
    assert _read_lines(workdir, str(outside), 1, 1) == ""
    assert _rel_path(str(outside), workdir) == ""
    assert _rel_path("../outside-sensitive.txt", workdir) == ""
