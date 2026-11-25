"""Impact class lookup and key normalisation for code rules (PLAN D1 and D2)."""

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import sdt_impact as impact  # noqa: E402
import sdt_priority as prio  # noqa: E402
import sdt_to_sonar  # noqa: E402


def _discover_scp_yaml_rules() -> set[str]:
    found: set[str] = set()
    rules_dir = ROOT / "rules" / "opengrep-rules"
    for path in sorted(rules_dir.rglob("*.yaml")):
        if "vendor" in path.parts or ".test." in path.name or path.name == "titles.yaml":
            continue
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"(?m)^\s*-\s+id:\s*([^\s#]+)", text):
            rule_id = match.group(1).strip("'\"")
            if rule_id.startswith("scp."):
                found.add(rule_id)
    return found


def _discover_endpoint_go_rules() -> set[str]:
    found: set[str] = set()
    endpoints_dir = ROOT / "internal" / "endpoints"
    for path in sorted(endpoints_dir.glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r'"(scp\.endpoints\.[^"]+)"', text):
            found.add(match.group(1))
    return found


def _discover_vendor_titles() -> set[str]:
    titles_path = ROOT / "rules" / "opengrep-rules" / "vendor" / "titles.yaml"
    found: set[str] = set()
    for line in titles_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        found.add(stripped.split(":", 1)[0].strip())
    return found


# ----------------------------------------------------------------------- table integrity
def test_every_scp_and_endpoint_rule_is_mapped_in_rules():
    yaml_rules = _discover_scp_yaml_rules()
    endpoint_rules = _discover_endpoint_go_rules()
    assert len(yaml_rules) >= 143
    assert len(endpoint_rules) >= 8

    expected = yaml_rules | endpoint_rules
    mapped = set(impact.RULES)
    missing = sorted(expected - mapped)
    extra = sorted(mapped - expected)
    assert not missing, f"scp.* rules missing from sdt_impact.RULES: {missing}"
    assert not extra, f"unknown rules in sdt_impact.RULES: {extra}"


def test_every_vendor_rule_exists_in_vendor_titles():
    known_vendor = _discover_vendor_titles()
    unknown = sorted(set(impact.VENDOR_RULES) - known_vendor)
    assert not unknown, f"unknown ids in sdt_impact.VENDOR_RULES: {unknown}"


def test_all_table_entries_have_valid_classes_labels_precision_and_reach():
    assert list(impact.CLASS_CEILING.values()) == list(range(len(prio.LEVELS)))
    for table_name, table in (
        ("RULES", impact.RULES),
        ("VENDOR_RULES", impact.VENDOR_RULES),
        ("SONAR_RULES", impact.SONAR_RULES),
        ("CWE", impact.CWE),
    ):
        assert table, f"{table_name} must not be empty"
        for key, entry in table.items():
            klass, label, precision, needs_reach = entry
            assert klass in impact.CLASS_CEILING, f"{table_name}[{key}]: bad class {klass!r}"
            assert label in impact.LABELS_BY_CLASS[klass], (
                f"{table_name}[{key}]: label {label!r} not valid for {klass}"
            )
            assert precision in ("high", "medium"), f"{table_name}[{key}]: bad precision {precision!r}"
            assert isinstance(needs_reach, bool), f"{table_name}[{key}]: needs_reach must be bool"
            if label in impact.NO_REACH_LABELS:
                assert needs_reach is False, (
                    f"{table_name}[{key}]: {label!r} must have needs_reach=False"
                )


# ----------------------------------------------------------------------- required examples and key forms
def test_required_examples_across_rule_key_forms():
    cred_change_id = "scp.java.authz.credential-change-by-request-id"
    cred_change_sonar_ext = f"external_sdt-opengrep:{sdt_to_sonar._rule_key('opengrep', cred_change_id)}"
    for key in (cred_change_id, f"external_opengrep:{cred_change_id}", cred_change_sonar_ext):
        got = impact.classify(key)
        assert got == impact.Impact("C1", "Account takeover", "high", True, "rule"), key

    srp_id = "scp.endpoints.sensitive-route-public"
    srp_real_ext = f"external_sdt-endpoints:{sdt_to_sonar._rule_key('endpoints', srp_id)}"
    srp_synth_ext = "external_sdt-endpoints:sdt-endpoints-sensitive-route-public-0123456789abcdef"
    for key in (srp_id, f"external_opengrep:{srp_id}", srp_real_ext, srp_synth_ext):
        got = impact.classify(key)
        assert got == impact.Impact("C1", "Authentication bypass", "high", True, "rule"), key

    bola_ext = f"external_sdt-endpoints:{sdt_to_sonar._rule_key('endpoints', 'scp.endpoints.bola-unscoped-object-access')}"
    for key in ("scp.endpoints.bola-unscoped-object-access", bola_ext):
        got = impact.classify(key)
        assert got == impact.Impact("C2", "Data exposure", "high", True, "rule"), key

    for rule_id in (
        "scp.java.authz.permitall-wildcard-prefix",
        "scp.java.authz.security-chain-without-default",
    ):
        for key in (rule_id, f"external_opengrep:{rule_id}"):
            got = impact.classify(key)
            assert got == impact.Impact("C1", "Authentication bypass", "high", True, "rule"), key

    prod_pw = impact.classify("scp.yaml.spring.prod-literal-password")
    assert prod_pw == impact.Impact("C1", "Credential exposure", "high", False, "rule")
    assert impact.classify("external_opengrep:scp.yaml.spring.prod-literal-password") == prod_pw

    s6437 = impact.classify("java:S6437", kind="Vulnerability")
    assert s6437 == impact.Impact("C1", "Credential exposure", "high", False, "sonar")

    rec_pw = impact.classify("scp.java.crypto.recoverable-password")
    assert rec_pw == impact.Impact("C2", "Weak credential storage", "high", False, "rule")

    assert impact.classify("java:S4507", kind="Security Hotspot") == impact.Impact(
        "C3", "Defence in depth", "medium", True, "sonar"
    )
    assert impact.classify("java:S1313", kind="Security Hotspot") == impact.Impact(
        "C4", "Hygiene", "medium", False, "sonar"
    )
    assert impact.classify("java:S2245", kind="Security Hotspot") == impact.Impact(
        "C3", "Defence in depth", "medium", False, "sonar"
    )

    for lang in ("go", "java", "javascript", "kotlin", "python"):
        rule_id = f"scp.{lang}.logic.weak-prng-otp-or-token"
        assert impact.classify(rule_id) == impact.Impact("C2", "Logic abuse", "high", False, "rule")


def test_vendored_rule_matches_both_raw_and_external_opengrep():
    vid = "vendor.semgrep.java.spring.security.injection.tainted-sql-string"
    expected = impact.Impact("C1", "Injection", "high", True, "rule")
    assert impact.classify(vid) == expected
    assert impact.classify(f"external_opengrep:{vid}") == expected


@pytest.mark.parametrize("rule,klass,label,needs_reach", [
    ("kotlin:S3649", "C1", "Injection", True),
    ("javascript:S5131", "C2", "Cross-site scripting", True),
    ("typescript:S4502", "C2", "Request forgery", False),
    ("python:S5144", "C2", "Request forgery", True),
    ("go:S2083", "C1", "Injection", True),
    ("dart:S4830", "C2", "Data exposure", False),
    ("docker:S6471", "C3", "Defence in depth", False),
    ("docker:S7031", "C1", "Credential exposure", False),
    ("java:S2755", "C1", "Injection", True),
    ("java:S5852", "C3", "Defence in depth", True),
])
def test_sonar_rules_cover_required_languages_and_families(rule, klass, label, needs_reach):
    got = impact.classify(rule)
    assert got is not None and got.source == "sonar"
    assert (got.klass, got.label, got.needs_reach) == (klass, label, needs_reach)


def test_refined_signal_to_noise_classifications():
    # Disabled cert validation enables active MITM capture: C2 high (P2), not C3 hardening.
    assert impact.classify("scp.dart.tls.disable-certificate-validation") == impact.Impact(
        "C2", "Data exposure", "high", False, "rule"
    )
    assert impact.classify("java:S4830") == impact.Impact("C2", "Data exposure", "high", False, "sonar")
    assert impact.classify("java:S5527") == impact.Impact("C2", "Data exposure", "high", False, "sonar")

    # CWE-532 log-call rules stay C2 medium (P3 until confirmed, P2 when real) to keep P1 clean.
    for rule_id in (
        "scp.go.logging.secret-in-log",
        "scp.java.logging.secret-in-log-call",
        "scp.java.logging.tostring-prints-secret",
        "scp.javascript.logging.secret-in-log",
        "scp.javascript.logging.secret-in-console",
        "scp.kotlin.logging.secret-in-log",
        "scp.python.logging.secret-in-log",
    ):
        assert impact.classify(rule_id) == impact.Impact("C2", "Data exposure", "medium", False, "rule"), rule_id

    # Low-confidence WebSocket interceptor check stays out of Fix First until confirmed.
    assert impact.classify("scp.java.websocket.handler-without-interceptor") == impact.Impact(
        "C2", "Logic abuse", "medium", True, "rule"
    )


def test_review_corrected_impact_classes():
    assert impact.classify("scp.java.authz.client-supplied-authorities") == impact.Impact(
        "C1", "Authentication bypass", "medium", True, "rule"
    )
    assert impact.classify("scp.yaml.spring.service-url-embedded-credentials") == impact.Impact(
        "C2", "Data exposure", "high", False, "rule"
    )
    assert impact.classify("scp.common.deploy.start-script-dev-server") == impact.Impact(
        "C2", "Data exposure", "medium", True, "rule"
    )
    assert impact.classify("scp.java.logic.float-for-currency") == impact.Impact(
        "C3", "Defence in depth", "medium", False, "rule"
    )


# ----------------------------------------------------------------------- CWE fallback and unknown rules
def test_cwe_fallback_and_highest_impact_selection():
    sqli = impact.classify(
        "custom:unknown-rule",
        cwe=("CWE-200: Exposure of Sensitive Information", "CWE-89: SQL Injection"),
        kind="Finding",
    )
    assert sqli == impact.Impact("C1", "Injection", "medium", True, "cwe")

    cred = impact.classify("custom:secret-rule", cwe=("798",), kind="Security Hotspot")
    assert cred == impact.Impact("C1", "Credential exposure", "medium", False, "cwe")


def test_unknown_rule_without_known_cwe_returns_none():
    assert impact.classify("java:S99999") is None
    assert impact.classify("custom:unknown", cwe=("CWE-99999",)) is None
    assert impact.classify("") is None


def test_bola_metadata_impact_overrides_across_key_forms():
    bola_ext = f"external_sdt-endpoints:{sdt_to_sonar._rule_key('endpoints', 'scp.endpoints.bola-unscoped-object-access')}"
    keys = (
        "scp.endpoints.bola-unscoped-object-access",
        "endpoints:scp.endpoints.bola-unscoped-object-access",
        bola_ext,
    )
    expected = {
        "account-takeover": impact.Impact("C1", "Account takeover", "high", True, "rule"),
        "logic-abuse": impact.Impact("C2", "Logic abuse", "high", True, "rule"),
        "data-exposure": impact.Impact("C2", "Data exposure", "high", True, "rule"),
        "": impact.Impact("C2", "Data exposure", "high", True, "rule"),
    }
    for key in keys:
        for hint, want in expected.items():
            assert impact.classify(key, impact=hint) == want, (key, hint)


def test_parse_impact_tag_extracts_and_strips_tag():
    assert impact.parse_impact_tag("PUT /api/users/{id}/pin [impact: account-takeover]") == (
        "account-takeover",
        "PUT /api/users/{id}/pin",
    )
    assert impact.parse_impact_tag("Plain finding message") == ("", "Plain finding message")
