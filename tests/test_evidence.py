import json
from pathlib import Path

from src.scanners.base import RawFinding
from src.scanners.evidence import (
    EVIDENCE_VERSION,
    MAX_CONTEXT_BYTES,
    MAX_CONTEXT_LINES,
    build_evidence,
    collect_context,
    redact_text,
)


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_collect_context_numbered_lines_and_vulnerable_flag(tmp_path):
    src = "\n".join(f"line{i}" for i in range(1, 21))
    _write(tmp_path, "app.py", src)

    ctx = collect_context(tmp_path, "app.py", 10, 10)
    assert [c["line"] for c in ctx] == list(range(6, 15))
    flags = {c["line"]: c["vulnerable"] for c in ctx}
    assert flags[10] is True
    assert flags[6] is False
    assert flags[14] is False


def test_collect_context_caps_lines(tmp_path):
    src = "\n".join(f"line{i}" for i in range(1, 200))
    _write(tmp_path, "app.py", src)

    ctx = collect_context(tmp_path, "app.py", 100, 100)
    assert len(ctx) <= MAX_CONTEXT_LINES


def test_collect_context_containment_check(tmp_path):
    _write(tmp_path, "app.py", "a\nb\nc\n")
    # path escaping the workdir yields no context
    assert collect_context(tmp_path, "../outside.py", 1, 1) == []
    assert collect_context(tmp_path, "/etc/passwd", 1, 1) == []


def test_collect_context_tolerates_invalid_encoding(tmp_path):
    p = tmp_path / "app.py"
    p.write_bytes(b"ok\n\xff\xfe bad bytes\nok2\n")
    ctx = collect_context(tmp_path, "app.py", 2, 2)
    assert ctx  # no crash; the offending line is replaced, not fatal
    assert ctx[1]["line"] == 2


def test_redact_text_replaces_secret_and_credential_values():
    text = "api_key = sk_live_1234567890abcdef\npassword = hunter2secret\n"
    out = redact_text(text, secrets=["sk_live_1234567890abcdef"])
    assert "sk_live_1234567890abcdef" not in out
    assert "[REDACTED]" in out


def test_build_evidence_schema_for_bandit(tmp_path):
    src = "\n".join(f"line{i}" for i in range(1, 20))
    _write(tmp_path, "app.py", src)

    rf = RawFinding(
        tool="bandit",
        source_type="sast",
        rule_id="B324",
        severity="high",
        file_path="app.py",
        line_start=10,
        line_end=10,
        col_start=5,
        col_end=20,
        snippet="line10",
        description="weak hash",
        remediation="https://bandit.readthedocs.io",
        raw={"issue_confidence": "HIGH", "more_info": "https://bandit.readthedocs.io"},
    )
    ev = build_evidence(rf, tmp_path)
    assert ev["version"] == EVIDENCE_VERSION
    assert ev["file"] == "app.py"
    assert ev["start"]["line"] == 10
    assert ev["start"]["column"] == 5
    assert ev["end"]["column"] == 20
    assert ev["context"]
    assert any(c["vulnerable"] for c in ev["context"])
    assert "confidence" in ev
    assert "rule" in ev


def test_build_evidence_redacts_secret_context(tmp_path):
    src = (
        "line1\n"
        "line2\n"
        'line3 api_key = "sk_live_2f7dNn3Ke8Qb0HkLm9XpRq1ZvYw3AtC5"\n'
        "line4\n"
        "line5\n"
    )
    _write(tmp_path, "app.py", src)

    rf = RawFinding(
        tool="gitleaks",
        source_type="secrets",
        rule_id="stripe-access-token",
        severity="high",
        file_path="app.py",
        line_start=3,
        line_end=3,
        raw={"Secret": "sk_live_2f7dNn3Ke8Qb0HkLm9XpRq1ZvYw3AtC5"},
    )
    ev = build_evidence(rf, tmp_path)
    dumped = json.dumps(ev)
    assert "sk_live_2f7dNn3Ke8Qb0HkLm9XpRq1ZvYw3AtC5" not in dumped
    assert "[REDACTED]" in dumped


def test_build_evidence_redacts_credentials_near_non_secret_finding(tmp_path):
    token = "sk_live_1234567890abcdef"
    _write(tmp_path, "app.py", f"dangerous()\napi_key = '{token}'\n")
    rf = RawFinding(
        tool="opengrep",
        source_type="sast",
        rule_id="scp.python.exec.eval",
        severity="high",
        file_path="app.py",
        line_start=1,
        line_end=1,
    )
    dumped = json.dumps(build_evidence(rf, tmp_path))
    assert token not in dumped
    assert "[REDACTED]" in dumped


def test_collect_context_does_not_use_unbounded_read_bytes(tmp_path, monkeypatch):
    source = _write(tmp_path, "large.py", "safe = 1\n" * 20000 + "danger = True\n")

    def forbidden(*args, **kwargs):
        raise AssertionError("read_bytes would load the entire attacker-controlled file")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    context = collect_context(tmp_path, str(source.relative_to(tmp_path)), 20001, 20001)
    assert context[-1]["text"] == "danger = True"
    assert len(json.dumps(context).encode()) <= MAX_CONTEXT_BYTES + 2048
