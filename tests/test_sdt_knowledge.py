"""Tests for tools/sdt_knowledge.py (shared, stdlib-only reporting knowledge).

Run: .venv/bin/pytest tests/test_sdt_knowledge.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import sdt_knowledge as k  # noqa: E402


def finding(rule_id="", category="sast", cwe=None, path=None, start=None, end=None):
    f = {"category": category, "rule": {"id": rule_id}}
    if cwe is not None:
        f["rule"]["cwe"] = cwe
    if path is not None:
        f["location"] = {"path": path}
        if start is not None:
            f["location"]["startLine"] = start
        if end is not None:
            f["location"]["endLine"] = end
    return f


# --------------------------------------------------------------- knowledge
def test_private_key_rule_matches_secrets_guidance():
    kb = k.knowledge_for(finding("scp.common.secrets.private-key", "sast", ["CWE-798"]))
    assert kb["label"] == "Secrets"
    assert "vault" in kb["fix"].lower()


def test_vendored_rule_segment_matches():
    rid = ("home.wishnu.secure-development-tools.rules.opengrep-rules.vendor.semgrep."
           "java.lang.correctness.no-string-eqeq")
    kb = k.knowledge_for(finding(rid, "sast"))
    assert kb["label"] == "Reliability / Correctness"
    assert ".equals" in kb["compliant"]


def test_redos_rule_matches_dos_guidance():
    rid = ("home.wishnu.secure-development-tools.rules.opengrep-rules.vendor.semgrep."
           "java.lang.security.java-pattern-from-string-parameter")
    kb = k.knowledge_for(finding(rid, "sast", "CWE-1333: Inefficient Regular Expression Complexity"))
    assert kb["label"] == "Denial of Service"


def test_no_cross_segment_false_positive():
    # "ssl" must NOT match an unrelated segment that merely contains those
    # letters elsewhere; matching is per-segment.
    kb = k.knowledge_for(finding("vendor.rules.sslwraphelper.java", "sast"))
    # no segment equals/contains "ssl"/"tls" here ("sslwraphelper" is one segment)
    assert kb["label"] == "Code Weakness"  # category fallback, not TLS guidance


def test_cwe_fallback_when_no_segment_match():
    kb = k.knowledge_for(finding("some.generic.rule", "sast", ["CWE-89"]))
    assert kb["label"] == "Injection"


def test_category_fallback_for_unknown_rule():
    kb = k.knowledge_for(finding("totally.unknown.thing", "dependency-vulnerability"))
    assert kb["label"] == "Vulnerable Dependency"


def test_cve_rule_uses_dependency_category():
    kb = k.knowledge_for(finding("CVE-2022-0839", "dependency-vulnerability", ["CWE-611"]))
    assert kb["label"] == "Vulnerable Dependency"


# --------------------------------------------------------- sensitive_source
@pytest.mark.parametrize("f", [
    finding("x", "secret"),
    finding("scp.common.secrets.private-key", "sast"),
    finding("some.api-key", "sast"),
    finding("benign.rule", "sast", path="config/prd-wallet-private.pem"),
    finding("benign.rule", "sast", path="server.key"),
])
def test_sensitive_source_true(f):
    assert k.sensitive_source(f) is True


def test_sensitive_source_false_for_benign():
    assert k.sensitive_source(finding("java.lang.correctness.eqeq", "sast", path="Service.java")) is False


# ------------------------------------------------------------- read_snippet
def test_read_snippet_missing_and_empty(tmp_path):
    assert k.read_snippet(tmp_path, "", 1, 1) is None
    assert k.read_snippet(tmp_path, "nope.java", 1, 1) is None


def test_read_snippet_traversal_refused(tmp_path):
    secret = tmp_path / "outside.txt"
    secret.write_text("top secret\n")
    root = tmp_path / "root"
    root.mkdir()
    assert k.read_snippet(root, "../outside.txt", 1, 1) is None
    assert k.read_snippet(root, str(secret), 1, 1) is None  # absolute outside root


def test_read_snippet_symlink_escape_refused(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("top secret\n")
    root = tmp_path / "root"
    root.mkdir()
    link = root / "escape.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported")
    assert k.read_snippet(root, "escape.txt", 1, 1) is None


def test_read_snippet_scrubs_pem_armor(tmp_path):
    root = tmp_path
    # Assemble the armor marker at runtime so this test file itself contains no
    # contiguous PEM header (keeps the repo clean under a self-scan).
    begin = "-----BEGIN " + "PRIVATE KEY" + "-----"
    end = "-----END " + "PRIVATE KEY" + "-----"
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ"
    (root / "key.pem").write_text(f"{begin}\n{body}\n{end}\n")
    out = k.read_snippet(root, "key.pem", 1, 3)
    assert out is not None
    text = out[1]
    assert "PRIVATE KEY" not in text
    assert body not in text
    assert "redacted" in text


def test_read_snippet_scrubs_sensitive_assignment(tmp_path):
    root = tmp_path
    value = "should-not-appear-abcdef123456"
    (root / "cfg.yml").write_text(
        "username: admin\n"
        f"password: {value}\n"
        "other: fine\n"
    )
    out = k.read_snippet(root, "cfg.yml", 1, 1)
    assert out is not None
    assert value not in out[1]
    assert "redacted" in out[1]


def test_read_snippet_marks_flagged_lines(tmp_path):
    root = tmp_path
    (root / "a.java").write_text("line1\nline2\nline3\n")
    out = k.read_snippet(root, "a.java", 2, 2)
    assert out is not None
    assert out[0] == 1
    assert ">> " in out[1]
    assert "line2" in out[1]


def test_knowledge_version_present():
    assert isinstance(k.KNOWLEDGE_VERSION, str) and k.KNOWLEDGE_VERSION
