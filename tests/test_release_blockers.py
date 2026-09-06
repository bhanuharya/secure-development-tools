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


def test_osv_scores_cvss_vectors_not_the_version_number():
    # The CVSS *version* (3.1) inside a vector must not be read as a score:
    # a 9.8-critical vector used to come out as "low".
    vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]}
    assert _severity(vuln) == "critical"


def test_osv_vector_scores_match_first_reference_values():
    from src.scanners.osv_adapter import _cvss3_vector_score

    assert _cvss3_vector_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert _cvss3_vector_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 7.5
    assert _cvss3_vector_score("not a vector") is None


def test_osv_plain_scores_and_words_keep_severity():
    assert _severity({"severity": [{"score": "9.8"}]}) == "critical"
    assert _severity({"severity": [{"score": "8.1"}]}) == "high"
    assert _severity({"severity": [{"score": "5.5"}]}) == "medium"
    assert _severity({"severity": [{"score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}]}) == "critical"
    assert _severity({"severity": [{"score": "high"}]}) == "high"
    assert _severity({"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}]}) == "low"


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
