import socket

from src.scanners.evidence import redact_text
from src.scanners.osv_adapter import _severity
from src.util.dastgate import validate_dast_url
from src.util.secretbox import decrypt_secret


def test_private_key_redaction_removes_complete_multiline_block():
    text = "before\n-----BEGIN RSA PRIVATE KEY-----\nsecret-material\n-----END RSA PRIVATE KEY-----\nafter"
    result = redact_text(text)
    assert "secret-material" not in result
    assert "BEGIN RSA PRIVATE KEY" not in result
    assert result == "before\n[REDACTED]\nafter"


def test_osv_uses_max_numeric_cvss_group():
    vuln = {"severity": [{"score": "CVSS:3.1/AV:N 4.0"}, {"score": "9.8"}]}
    assert _severity(vuln) == "critical"


def test_legacy_plaintext_secret_is_not_loaded(monkeypatch):
    monkeypatch.setenv("SCP_SECRET_KEY", "test passphrase")
    assert decrypt_secret("old-plaintext-password") == ""


def test_dast_allowlist_and_private_resolution_fail_closed(monkeypatch):
    monkeypatch.setenv("SCP_DAST_ALLOWED_HOSTS", "example.test")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, 0, 0, "", ("127.0.0.1", 443))])
    try:
        validate_dast_url("https://example.test")
    except ValueError as exc:
        assert "prohibited" in str(exc)
    else:
        raise AssertionError("private destination accepted")
