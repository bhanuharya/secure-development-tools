"""Priority of a finding from its severity and what is known about the service (ADR 0009)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import sdt_priority as prio  # noqa: E402
from sdt_priority import Context  # noqa: E402

SQLI = ("javascript:S3649", "Database queries should not be vulnerable to injection attacks")
INTERNAL, INTERNET, UNKNOWN = Context("internal"), Context("internet"), Context()


# ----------------------------------------------------------------------------- code
def test_code_an_attacker_must_reach_is_one_step_lower_for_an_internal_service():
    assert prio.code(*SQLI, "High", "src/db.js", ctx=INTERNET).level == "P2"
    internal = prio.code(*SQLI, "High", "src/db.js", ctx=INTERNAL)
    assert internal.level == "P3" and internal.why == "High severity; internal service ↓"
    assert prio.code(*SQLI, "High", "src/db.js", ctx=Context("none")).why.endswith("not deployed as a service ↓")
    dev_server = prio.code("scp.common.deploy.dev-server-start", "dev server in a deployment", "High", "Dockerfile",
                           ctx=INTERNAL)
    assert dev_server.level == "P3"


def test_an_exposure_that_is_not_recorded_lowers_nothing():
    assert prio.code(*SQLI, "High", "src/db.js", ctx=UNKNOWN) == prio.code(*SQLI, "High", "src/db.js", ctx=INTERNET)
    assert prio.code(*SQLI, "High", "src/db.js").level == "P2"


@pytest.mark.parametrize("rule,name", [
    ("scp.javascript.secrets.env-fallback-literal", "secret with a literal fallback"),
    ("java:S2068", "Hard-coded passwords are security-sensitive"),
    ("java:S4790", "Using weak hashing algorithms is security-sensitive"),
    ("java:S4830", "Server certificates should be verified during SSL/TLS connections"),
    ("javascript:S4502", "Disabling CSRF protections is security-sensitive"),
])
def test_credentials_cryptography_and_csrf_are_not_lowered_for_an_internal_service(rule, name):
    assert prio.code(rule, name, "High", "src/app.js", ctx=INTERNAL).level == "P2"


def test_a_review_can_raise_a_finding_but_never_lower_it():
    real = prio.code(*SQLI, "High", "src/db.js", "likely_true_positive", "high")
    assert real.level == "P1" and "review judged it real ↑" in real.why
    assert prio.code(*SQLI, "High", "src/db.js", "likely_true_positive", "low").level == "P2"
    assert prio.code(*SQLI, "High", "src/db.js", "likely_false_positive", "high").level == "P2"


def test_criticality_high_cancels_the_internal_step_low_lowers_but_not_credentials():
    assert prio.code(*SQLI, "High", "src/db.js", ctx=Context("internal", "high")).level == "P2"
    assert prio.code(*SQLI, "High", "src/db.js", ctx=Context("internet", "low")).level == "P3"
    assert prio.code("java:S2068", "Hard-coded passwords", "High", "src/A.java", ctx=Context("internal", "low")).level == "P2"


def test_context_lowers_at_most_two_steps_and_says_which():
    p = prio.code(*SQLI, "Critical", "tests/db.test.js", ctx=Context("internal", "low"))
    assert p.level == "P3"
    assert [s.reason for s in p.steps] == ["test, example or documentation file", "internal service"]


# -------------------------------------------------------------------------- secrets
def test_a_working_credential_is_p1_in_history_and_for_an_internal_service():
    p = prio.secret("private-key", "deploy/id_rsa", ctx=INTERNAL)
    assert p.level == "P1" and p.why == "working credential by its format"
    assert prio.secret("aws-access-token", ["src/config.js"]).level == "P1"


def test_secrets_by_kind_and_place():
    assert prio.secret("generic-api-key", "src/api.js").level == "P2"
    served = prio.secret("generic-api-key", "public/js/app.js")
    assert served.level == "P1" and "in a file served to browsers ↑" in served.why
    assert prio.secret("generic-api-key", "tests/fixtures/keys.json").level == "P3"
    assert prio.secret("private-key", "test/certs/key.pem").level == "P2"
    client = prio.secret("gcp-api-key", "android/app/google-services.json", client_key=True)
    assert client.level == "P3" and "restrict" in client.why
    assert prio.secret("generic-api-key", "src/api.js", ctx=Context(visibility="public")).level == "P1"


# --------------------------------------------------------------------- dependencies
def test_dependencies_by_reachability_manifest_and_service():
    assert prio.dependency("Critical", "Yes", "package-lock.json").level == "P1"
    assert prio.dependency("Critical", "Yes/unknown", "package-lock.json", INTERNAL).level == "P2"
    unused = prio.dependency("Critical", "No", "package-lock.json", INTERNAL)
    assert unused.level == "P3" and unused.why == "Critical severity; not imported by the code ↓; internal service ↓"
    assert prio.dependency("High", "Unknown", "examples/demo/package-lock.json").level == "P3"
    assert prio.dependency("High", "Unknown", "package-lock.json", Context("internal", "high")).level == "P2"


def test_configuration_checks_are_not_lowered_for_an_internal_service():
    assert prio.configuration("High", "Dockerfile", INTERNAL).level == "P2"
    assert prio.configuration("High", "examples/Dockerfile").level == "P3"


@pytest.mark.parametrize("path,where", [
    ("src/app.js", "shipped"), ("lib/api.dart", "shipped"), ("tests/a.py", "not shipped"),
    ("src/__tests__/a.js", "not shipped"), ("src/a.spec.ts", "not shipped"), ("pkg/a_test.go", "not shipped"),
    ("test_api.py", "not shipped"), ("docs/setup.md", "not shipped"), ("public/index.html", "served"),
    ("static/js/main.js", "served"), ("templates/page.html", "served"), ("", "shipped"),
])
def test_place_of_a_path(path, where):
    assert prio.place(path) == where


# ------------------------------------------------------------------------ inventory
INVENTORY = """# repository inventory: one line per repository
repository\texposure\tcriticality\tvisibility\tnote
example/web-cms\tinternet\thigh\t\tpublic CMS
batch-jobs\tinternal
Docs-Site\tinternet\t\tpublic
typo\tintranet\tsometimes
"""


def test_inventory_lookup_by_workspace_and_slug_and_typos_count_as_not_recorded(tmp_path):
    path = tmp_path / "inventory.tsv"
    path.write_text(INVENTORY)
    warnings = []
    inventory = prio.load_inventory(path, warnings.append)
    assert prio.context(inventory, "example/web-cms") == Context("internet", "high", "private", "inventory")
    assert prio.context(inventory, "other-workspace/batch-jobs").exposure == "internal"
    assert prio.context(inventory, "ws/docs-site").visibility == "public"
    assert prio.context(inventory, "ws/typo") == Context("unknown", "normal", "private", "inventory")
    assert len(warnings) == 2 and "intranet" in warnings[0] and "inventory.tsv:6" in warnings[0]
    assert prio.context(inventory, "ws/missing") == Context()
    # A value given on the command line wins over the inventory.
    assert prio.context(inventory, "batch-jobs", exposure="internet").exposure == "internet"


def test_inventory_without_a_header_line_is_refused(tmp_path):
    path = tmp_path / "inventory.tsv"
    path.write_text("web-cms\tinternet\n")
    with pytest.raises(ValueError, match="name the columns"):
        prio.load_inventory(path)


def test_the_report_states_the_rules_with_the_facts_used():
    unknown = prio.rules_text(Context())
    assert "not recorded" in unknown[0] and "reachable from the internet" in unknown[0]
    known = prio.rules_text(Context("internal", "high", source="inventory"))
    assert known[0] == "Service exposure: internal network only; business criticality: high (from the inventory)."
    assert any("at most two steps" in line for line in known)


@pytest.mark.parametrize("match,level", [
    ("ADMIN_JWT_SECRET', '[REDACTED]'", "P1"), ("API_TOKEN_SALT', 'REDACTED'", "P1"),
    ('DATABASE_PASSWORD="REDACTED"', "P1"), ("SECRET_KEY = 'REDACTED'", "P1"), ("APP_KEYS=REDACTED", "P1"),
    ('api_key = "REDACTED"', "P2"), ("AWS_SECRET_KEY_ID=REDACTED", "P2"), ("auth_token: REDACTED", "P2"),
])
def test_a_generic_secret_named_as_a_signing_key_or_password_is_p1(match, level):
    p = prio.secret("generic-api-key", "config/admin.js", names=[match])
    assert p.level == level
    assert ("named as a signing key or password ↑" in p.why) == (level == "P1")


def test_a_name_does_not_change_a_client_key():
    assert prio.secret("gcp-api-key", "android/app/google-services.json", client_key=True,
                       names=["password REDACTED"]).level == "P3"
