from pathlib import Path

from src.scanners.gitleaks_adapter import _redact
from src.scanners.opengrep_adapter import _clean_rule_id, _normalize_cwe, _result_snippet


def test_redact_secret_from_snippet():
    assert _redact("api_key = sk_live_1234567890abcdef", "sk_live_1234567890abcdef") == \
        "api_key = [REDACTED]"
    assert _redact("no secret here", "") == "no secret here"


def test_clean_rule_id_keeps_scp_id():
    assert _clean_rule_id("home.user.rules.opengrep-rules.python.scp.python.exec.eval") == \
        "scp.python.exec.eval"
    assert _clean_rule_id("scp.python.exec.eval") == "scp.python.exec.eval"


def test_normalize_cwe_handles_forms():
    assert _normalize_cwe("89") == "CWE-89"
    assert _normalize_cwe("CWE-89") == "CWE-89"
    assert _normalize_cwe(["CWE-89"]) == "CWE-89"
    assert _normalize_cwe({"id": "89"}) == "CWE-89"
    assert _normalize_cwe(None) == ""


def test_result_snippet_reads_disk_when_lines_placeholder(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("line1\n    eval('x')\nline3\n", encoding="utf-8")
    # semgrep 1.172.0 sets extra.lines to the literal placeholder "requires login"
    snippet = _result_snippet("requires login", tmp_path, "app.py", 2, 2)
    assert snippet == "    eval('x')"
    # empty lines also trigger the disk fallback
    assert _result_snippet("", tmp_path, "app.py", 2, 2) == "    eval('x')"
    # a real lines payload is used as-is
    assert _result_snippet("real line", tmp_path, "app.py", 2, 2) == "real line"
    # missing file yields empty snippet rather than crashing
    assert _result_snippet("requires login", tmp_path, "nope.py", 2, 2) == ""
