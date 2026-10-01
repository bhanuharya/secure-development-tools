import json
from pathlib import Path

import pytest

from src.scanners.base import RawFinding
from src.scanners.evidence import (
    EVIDENCE_VERSION,
    MAX_CONTEXT_BYTES,
    MAX_CONTEXT_LINES,
    build_evidence,
    collect_context,
    redact_text,
)


_SLACK_BOT_TOKEN = "xox" + "b-" + ("s" * 12)
_SLACK_WEBHOOK = (
    "https://" + "hooks" + ".slack.com/services/" + "T" + ("0" * 8) + "/B" + ("0" * 8) + "/" + ("X" * 24)
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


# ---------------------------------------------------------------- vendor tokens
@pytest.mark.parametrize(
    "raw_secret",
    [
        "AKIAIOSFODNN7EXAMPLE",                     # AWS long-term  # gitleaks:allow — synthetic redaction canary
        "ASIAIOSFODNN7EXAMPLE",                     # AWS temporary  # gitleaks:allow — synthetic redaction canary
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a", # GitHub classic PAT  # gitleaks:allow — synthetic redaction canary
        "github_pat_11AABBCC01234567890_aBcD",      # GitHub fine-grained  # gitleaks:allow — synthetic redaction canary
        _SLACK_BOT_TOKEN,  # Slack bot assembled at runtime; synthetic redaction canary
        _SLACK_WEBHOOK,  # Slack webhook assembled at runtime; synthetic redaction canary
        "AIzaSyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1v",  # Google API key  # gitleaks:allow — synthetic redaction canary
        "1//03abc-def_ghijklmnopqrstuvwxyz123456",  # Google refresh token  # gitleaks:allow — synthetic redaction canary
        "glpat-AbCdEfGhIjKlMnOpQrStUv",             # GitLab PAT  # gitleaks:allow — synthetic redaction canary
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",  # JWT  # gitleaks:allow — synthetic redaction canary
        "sk-ant-api03-abcdef0123456789abcdef",     # Anthropic  # gitleaks:allow — synthetic redaction canary
        "sk-proj-abcdefghij0123456789ABCDEFGH",     # OpenAI project  # gitleaks:allow — synthetic redaction canary
    ],
)
def test_redact_text_masks_known_vendor_tokens(raw_secret):
    out = redact_text(f"token = {raw_secret}\n")
    assert raw_secret not in out
    assert "[REDACTED]" in out


def test_redact_text_masks_authorization_headers():
    out = redact_text("Authorization: Bearer abcdef1234567890abcdef")
    assert "abcdef1234567890abcdef" not in out
    out = redact_text("Authorization: Basic dXNlcjpwYXNzd29yZA==")
    assert "dXNlcjpwYXNzd29yZA==" not in out


def test_redact_text_masks_composed_key_names():
    out = redact_text("aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'")
    assert "wJalrXUtnFEMI" not in out
    out = redact_text('CLIENT_TOKEN="8f3j2lk9sjd92lak3"')
    assert "8f3j2lk9sjd92lak3" not in out


def test_redact_text_keeps_ordinary_code():
    line = "keyboard_count = 42  # not a credential"
    assert redact_text(line) == line


def test_evidence_context_masks_flagged_tokens(tmp_path):
    secret = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"  # gitleaks:allow — synthetic redaction canary
    _write(tmp_path, "deploy.py", f"import os\nos.environ['GITHUB_TOKEN'] = '{secret}'\n")
    rf = RawFinding(
        tool="opengrep", source_type="sast", rule_id="scp.generic.env",
        severity="medium", file_path="deploy.py", line_start=2, line_end=2,
    )
    dumped = json.dumps(build_evidence(rf, tmp_path))
    assert secret not in dumped
