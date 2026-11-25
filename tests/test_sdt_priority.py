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
    assert prio.code(*SQLI, "High", "src/db.js", ctx=INTERNET).level == "P1"
    internal = prio.code(*SQLI, "High", "src/db.js", ctx=INTERNAL)
    assert internal.level == "P2" and internal.why == "Injection (C1), high-precision rule; internal service ↓"
    assert prio.code(*SQLI, "High", "src/db.js", ctx=Context("none")).why.endswith("not deployed as a service ↓")
    dev_server = prio.code("scp.common.deploy.dev-server-start", "dev server in a deployment", "High", "Dockerfile",
                           ctx=INTERNAL)
    assert dev_server.level == "P3"


def test_an_exposure_that_is_not_recorded_lowers_nothing():
    assert prio.code(*SQLI, "High", "src/db.js", ctx=UNKNOWN) == prio.code(*SQLI, "High", "src/db.js", ctx=INTERNET)
    assert prio.code(*SQLI, "High", "src/db.js").level == "P1"


@pytest.mark.parametrize("rule,name,level", [
    ("scp.javascript.secrets.env-fallback-literal", "secret with a literal fallback", "P1"),
    ("java:S2068", "Hard-coded passwords are security-sensitive", "P2"),
    ("java:S4790", "Using weak hashing algorithms is security-sensitive", "P4"),
    ("java:S4830", "Server certificates should be verified during SSL/TLS connections", "P2"),
    ("javascript:S4502", "Disabling CSRF protections is security-sensitive", "P3"),
])
def test_credentials_cryptography_and_csrf_are_not_lowered_for_an_internal_service(rule, name, level):
    internal = prio.code(rule, name, "High", "src/app.js", ctx=INTERNAL)
    assert internal == prio.code(rule, name, "High", "src/app.js", ctx=INTERNET)
    assert internal.level == level


def test_a_review_can_raise_a_finding_but_never_lower_it():
    medium_sqli = ("java:S2077", "Formatting SQL queries is security-sensitive")
    real = prio.code(*medium_sqli, "High", "src/db.js", "likely_true_positive", "high")
    assert real.level == "P1" and "review judged it real ↑" in real.why
    assert prio.code(*medium_sqli, "High", "src/db.js", "likely_true_positive", "low").level == "P2"
    assert prio.code(*medium_sqli, "High", "src/db.js", "likely_false_positive", "high").level == "P2"


def test_criticality_high_cancels_the_internal_step_low_lowers_but_not_credentials():
    assert prio.code(*SQLI, "High", "src/db.js", ctx=Context("internal", "high")).level == "P1"
    assert prio.code(*SQLI, "High", "src/db.js", ctx=Context("internet", "low")).level == "P2"
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
    capped = prio.dependency("Critical", "Yes", "package-lock.json")
    assert capped.level == "P2" and "capped at P2: no known-exploited advisory" in capped.why
    assert prio.dependency("Critical", "Yes", "package-lock.json", known_exploited=True).level == "P1"
    assert prio.dependency("Critical", "Yes/unknown", "package-lock.json", INTERNAL).level == "P2"
    unused = prio.dependency("Critical", "No", "package-lock.json", INTERNAL)
    assert unused.level == "P3" and unused.why == "Critical severity; not imported by the code ↓; internal service ↓"
    assert prio.dependency("High", "Unknown", "examples/demo/package-lock.json").level == "P3"
    assert prio.dependency("High", "Unknown", "package-lock.json", Context("internal", "high")).level == "P2"


def test_dependency_kev_respects_internal_service_and_high_criticality():
    kev_unknown = prio.dependency("High", "Yes", "pom.xml", Context("unknown"),
                                  known_exploited=True, kev_ids=("CVE-2026-1001",))
    assert kev_unknown.level == "P1" and "on the known-exploited list: CVE-2026-1001" in kev_unknown.why

    kev_internal = prio.dependency("Critical", "Yes", "pom.xml", INTERNAL,
                                   known_exploited=True, kev_ids=("CVE-2026-1001",))
    assert kev_internal.level == "P2" and "internal service ↓" in kev_internal.why

    kev_internal_high = prio.dependency("Critical", "Yes", "pom.xml", Context("internal", "high"),
                                        known_exploited=True, kev_ids=("CVE-2026-1001",))
    assert kev_internal_high.level == "P1" and "on the known-exploited list: CVE-2026-1001" in kev_internal_high.why

    kev_unimported = prio.dependency("Critical", "No", "pom.xml", Context("unknown"),
                                     known_exploited=True, kev_ids=("CVE-2026-1001",))
    assert kev_unimported.level == "P2" and "not imported by the code ↓" in kev_unimported.why


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


@pytest.mark.parametrize("match,level", [
    ("CONTACT_FORM_RECAPTCHA_SECRET_KEY=[REDACTED]", "P2"), ("HCAPTCHA_SECRET_KEY=[REDACTED]", "P2"),
    ("TURNSTILE_SECRET_KEY: [REDACTED]", "P2"), ("STRIPE_SECRET_KEY=[REDACTED]", "P1"),
])
def test_a_bot_check_secret_key_is_not_raised_as_a_signing_key(match, level):
    # A reCAPTCHA, hCaptcha or Turnstile secret verifies answers with the provider; it forges nothing.
    assert prio.secret("generic-api-key", "src/config.ts", names=[match]).level == level


@pytest.mark.parametrize("match", [
    "NUXT_PUBLIC_RECAPTCHA_SITE_KEY=[REDACTED]", "STRIPE_PUBLISHABLE_KEY=[REDACTED]", "SUPABASE_ANON_KEY=[REDACTED]",
])
def test_a_generic_secret_named_as_public_by_design_is_one_step_lower(match):
    p = prio.secret("generic-api-key", "src/config.ts", names=[match])
    assert p.level == "P3" and "named as a key that is public by design ↓" in p.why


def test_a_public_key_beside_a_real_secret_lowers_nothing():
    names = ["SITE_KEY=[REDACTED]", "DATABASE_PASSWORD=[REDACTED]"]
    assert prio.secret("generic-api-key", "src/config.ts", names=names).level == "P1"
    assert prio.secret("generic-api-key", "src/config.ts", names=["SITE_KEY=[REDACTED]", "api_key=[REDACTED]"]).level == "P2"


@pytest.mark.parametrize("path,where", [
    (".env.example", "not shipped"), ("app/.env.sample", "not shipped"), ("config/settings.py.example", "not shipped"),
    ("example.env", "not shipped"), (".env", "shipped"), ("nginx/default.conf.template", "shipped"),
])
def test_example_and_sample_files_are_not_shipped(path, where):
    assert prio.place(path) == where


def test_a_template_env_file_with_a_bot_check_key_is_planned_not_urgent():
    names = ["NUXT_PUBLIC_CONTACT_FORM_RECAPTCHA_SITE_KEY=[REDACTED]", "CONTACT_FORM_RECAPTCHA_SECRET_KEY=[REDACTED]"]
    p = prio.secret("generic-api-key", ".env.example", names=names)
    assert p.level == "P3" and p.why == "generic key or token; test, example or documentation file ↓"


# ------------------------------------------------------------------ impact classes (N02)
def _legacy_code(rule: str, name: str, severity: str, path: str, verdict: str = "", confidence: str = "",
                 ctx: Context = Context()) -> prio.Priority:
    """Copy of pre-N02 severity-only code() to verify unclassified rules keep identical output."""
    start, base = prio._severity(severity)
    raises, lowers = [], []
    if verdict == "likely_true_positive" and str(confidence).lower() != "low":
        raises.append("review judged it real")
    if prio.place(path) == "not shipped":
        lowers.append("test, example or documentation file")
    text = f"{rule} {name}"
    if prio.CREDENTIAL_CODE.search(text):
        pass
    elif prio.REACH_NEEDED.search(text) and not prio.NO_ATTACKER_NEEDED.search(text):
        prio._service(ctx, lowers)
    elif ctx.criticality == "low":
        lowers.append("low business criticality")
    return prio.decide(start, base, raises, lowers)


def test_c1_high_precision_is_p1_without_review_for_internet_or_unknown_exposure():
    rule = "scp.java.authz.credential-change-by-request-id"
    for ctx in (INTERNET, UNKNOWN):
        p = prio.code(rule, "Credential change for an account named in the URL", "Medium",
                      "src/UserController.java", ctx=ctx)
        assert p.level == "P1"
        assert p.base == "Account takeover (C1), high-precision rule"
        assert p.why == "Account takeover (C1), high-precision rule"
        assert p.impact is not None and p.impact.klass == "C1" and p.impact.label == "Account takeover"


def test_c1_medium_precision_starts_at_p2_and_review_real_raises_to_p1():
    rule = "scp.java.authz.commented-out-rule"
    base = prio.code(rule, "Authorization rule commented out", "Medium", "src/SecurityConfig.java")
    assert base.level == "P2" and base.base == "Authentication bypass (C1), medium-precision rule"
    raised = prio.code(rule, "Authorization rule commented out", "Medium", "src/SecurityConfig.java",
                       verdict="likely_true_positive", confidence="high")
    assert raised.level == "P1" and "review judged it real ↑" in raised.why


def test_c2_high_precision_stays_at_p2_ceiling_with_review_real_and_records_no_raise():
    rule = "scp.endpoints.bola-unscoped-object-access"
    p = prio.code(rule, "Unscoped object access", "Medium", "src/OrderController.java",
                  verdict="likely_true_positive", confidence="high")
    assert p.level == "P2"
    assert p.why == "Data exposure (C2), high-precision rule"
    assert "review judged it real" not in p.why


def test_c2_medium_precision_starts_at_p3_and_review_real_raises_to_p2():
    rule = "scp.java.logic.mass-assignment-beanutils"
    base = prio.code(rule, "Mass assignment", "Medium", "src/UserService.java")
    assert base.level == "P3" and base.base == "Logic abuse (C2), medium-precision rule"
    raised = prio.code(rule, "Mass assignment", "Medium", "src/UserService.java",
                       verdict="likely_true_positive", confidence="medium")
    assert raised.level == "P2" and "review judged it real ↑" in raised.why


def test_c3_medium_debug_hotspot_starts_at_p4_and_review_real_caps_at_p3():
    base = prio.code("java:S4507", "Delivering code in production with debug features activated", "High",
                     "src/App.java", kind="Security Hotspot")
    assert base.level == "P4" and base.base == "Defence in depth (C3), medium-precision rule"
    raised = prio.code("java:S4507", "Delivering code in production with debug features activated", "High",
                       "src/App.java", verdict="likely_true_positive", confidence="high", kind="Security Hotspot")
    assert raised.level == "P3" and "review judged it real ↑" in raised.why


def test_internal_service_lowers_account_takeover_but_not_credential_exposure():
    ato = prio.code("scp.java.authz.credential-change-by-request-id", "Credential change", "Medium",
                    "src/UserController.java", ctx=INTERNAL)
    assert ato.level == "P2" and "internal service ↓" in ato.why

    cred_yaml = prio.code("scp.yaml.spring.prod-literal-password", "Literal password", "High",
                          "src/main/resources/application-prod.yml", ctx=Context("internal", "low"))
    assert cred_yaml.level == "P1" and cred_yaml.steps == ()

    cred_sonar = prio.code("java:S6437", "Revoke and change this password", "Critical",
                           "src/Auth.java", ctx=Context("internal", "low"), kind="Vulnerability")
    assert cred_sonar.level == "P1" and cred_sonar.steps == ()


def test_impact_class_lowers_at_most_two_steps_with_three_facts():
    p = prio.code("scp.java.authz.credential-change-by-request-id", "Credential change", "Medium",
                  "tests/UserControllerTest.java", ctx=Context("internal", "low"))
    assert p.level == "P3"
    assert [s.reason for s in p.steps] == ["test, example or documentation file", "internal service"]


def test_likely_false_positive_never_lowers_classified_findings():
    assert prio.code("scp.java.authz.credential-change-by-request-id", "Credential change", "Medium",
                     "src/UserController.java", verdict="likely_false_positive", confidence="high").level == "P1"
    assert prio.code("scp.java.authz.commented-out-rule", "Commented rule", "Medium",
                     "src/SecurityConfig.java", verdict="likely_false_positive", confidence="high").level == "P2"
    assert prio.code("scp.java.crypto.recoverable-password", "Recoverable password", "Medium",
                     "src/User.java", verdict="likely_false_positive", confidence="high").level == "P2"


@pytest.mark.parametrize("rule,name,severity,path,verdict,confidence,ctx", [
    ("custom:unclassified-sql", "Unclassified SQL check", "High", "src/db.py", "", "", INTERNET),
    ("custom:unclassified-sql", "Unclassified SQL check", "High", "src/db.py", "", "", INTERNAL),
    ("custom:unclassified-rule", "General finding", "Medium", "tests/unit_test.py", "likely_true_positive", "high", INTERNET),
    ("custom:unclassified-rule", "General finding", "Critical", "src/app.py", "likely_false_positive", "high", Context("internal", "low")),
    ("custom:unclassified-rule", "General finding", "Low", "src/app.py", "", "", UNKNOWN),
])
def test_unclassified_rule_matches_legacy_priority_exactly(rule, name, severity, path, verdict, confidence, ctx):
    got = prio.code(rule, name, severity, path, verdict, confidence, ctx)
    want = _legacy_code(rule, name, severity, path, verdict, confidence, ctx)
    assert got == want and got.impact is None


def test_rules_text_explains_impact_classes_ceilings_and_review_rule():
    lines = prio.rules_text(Context())
    joined = " ".join(lines)
    assert "C1 Direct compromise (P1)" in joined
    assert "class ceiling" in joined
    assert "never above its class ceiling" in joined
    assert "never lowers" in joined


def test_bola_per_finding_impact_ranks_account_takeover_p1_and_others_p2():
    rule = "scp.endpoints.bola-unscoped-object-access"
    ato = prio.code(rule, "Unscoped object access", "High", "src/UserController.java", impact="account-takeover")
    assert ato.level == "P1" and ato.base == "Account takeover (C1), high-precision rule"

    logic = prio.code(rule, "Unscoped object access", "High", "src/OrderController.java", impact="logic-abuse")
    assert logic.level == "P2" and logic.base == "Logic abuse (C2), high-precision rule"

    read = prio.code(rule, "Unscoped object access", "Medium", "src/OrderController.java", impact="data-exposure")
    assert read.level == "P2" and read.base == "Data exposure (C2), high-precision rule"

