"""Contract tests for cross-repository reporting and Sonar identity."""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from xml.etree import ElementTree

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import sdt_fleet  # noqa: E402
import sdt_fleet_report  # noqa: E402
import sdt_repo_manifest  # noqa: E402
import sdt_to_docx  # noqa: E402
import sdt_sonar_sync  # noqa: E402
import sdt_rule_precision  # noqa: E402
import sdt_triage_codex  # noqa: E402
import sdt_to_sonar  # noqa: E402


@pytest.fixture(autouse=True)
def clean_fleet_environment(monkeypatch):
    """Flag defaults read SDT_FLEET_*, so an operator's own config must not steer a test."""
    for name in [key for key in os.environ if key.startswith("SDT_FLEET_")]:
        monkeypatch.delenv(name)


def test_sonar_rule_identity_and_path_safety():
    def finding(rule_id, path):
        return {"scanner": {"adapter": "opengrep"}, "category": "sast",
                "rule": {"id": rule_id}, "severity": {"canonical": "high"},
                "location": {"path": path, "startLine": 3}, "message": "review"}

    report, skipped = sdt_to_sonar.convert({"findings": [
        finding("vendor.alpha.same", "src/a.py"),
        finding("vendor.beta.same", "src/b.py"),
        finding("vendor.escape", "../private.py"),
    ]})
    assert len(report["rules"]) == 2
    assert len(report["issues"]) == 2
    assert skipped == 1
    assert report["rules"][0]["id"] != report["rules"][1]["id"]


def test_sonar_only_imports_files_in_checkout(tmp_path):
    (tmp_path / "main.go").write_text("package main\n")
    base = {"scanner": {"adapter": "opengrep"}, "category": "sast",
            "rule": {"id": "test"}, "severity": {"canonical": "high"}, "message": "review"}
    findings = [{**base, "location": {"path": path}} for path in ("main.go", "deleted.go", "/etc/passwd")]
    report, skipped = sdt_to_sonar.convert({"findings": findings}, tmp_path)
    assert len(report["issues"]) == 1
    assert skipped == 2


def test_sonar_clamps_lines_past_end_of_file(tmp_path):
    """One out-of-range pointer fails the whole SonarQube import, so clamp it to the file."""
    (tmp_path / "app.py").write_text("one\ntwo\nthree\n")
    (tmp_path / "empty.py").write_text("")
    base = {"scanner": {"adapter": "opengrep"}, "category": "sast", "rule": {"id": "test"},
            "severity": {"canonical": "high"}, "message": "review"}
    findings = [
        {**base, "location": {"path": "app.py", "startLine": 351, "endLine": 356}},
        {**base, "location": {"path": "app.py", "startLine": 2, "endLine": 3}},
        {**base, "location": {"path": "app.py", "startLine": 351}},
        {**base, "location": {"path": "empty.py", "startLine": 12}},
        {**base, "location": {"path": "gone.py", "startLine": 351}},
    ]
    report, skipped = sdt_to_sonar.convert({"findings": findings}, tmp_path)
    assert skipped == 1
    ranges = [issue["primaryLocation"].get("textRange", {}) for issue in report["issues"]]
    assert ranges == [{"startLine": 2, "endLine": 3}, {"startLine": 3, "endLine": 3}, {"startLine": 3}, {}]


def test_sonar_only_clamps_when_a_repo_root_is_given():
    finding = {"scanner": {"adapter": "opengrep"}, "category": "sast", "rule": {"id": "test"},
               "severity": {"canonical": "high"}, "message": "review",
               "location": {"path": "app.py", "startLine": 351, "endLine": 356}}
    report, skipped = sdt_to_sonar.convert({"findings": [finding]})
    assert skipped == 0
    assert report["issues"][0]["primaryLocation"]["textRange"] == {"startLine": 351, "endLine": 356}


def test_sonar_leaves_skipped_adapters_to_their_own_importer():
    findings = [{"scanner": {"adapter": "opengrep"}, "rule": {"id": "a"}},
                {"scanner": {"adapter": "gitleaks"}, "rule": {"id": "b"}},
                {"scanner": {"adapter": "OpenGrep"}, "rule": {"id": "c"}}]
    doc, left_out = sdt_to_sonar.without_adapters({"findings": findings, "runId": "r1"}, ["opengrep"])
    assert left_out == 2
    assert [f["rule"]["id"] for f in doc["findings"]] == ["b"]
    assert doc["runId"] == "r1"
    assert sdt_to_sonar.without_adapters({"findings": findings}, [])[1] == 0


def test_sonar_respects_scanner_correctness_classification():
    finding = {"scanner": {"adapter": "opengrep"}, "category": "sast",
               "rule": {"id": "scp.example.logic"}, "metadata": {"classification": "correctness"},
               "severity": {"canonical": "medium"}, "location": {"path": "src/x.py"}, "message": "logic"}
    report, skipped = sdt_to_sonar.convert({"findings": [finding]})
    assert skipped == 0
    assert report["rules"][0]["type"] == "BUG"


def test_extract_vuln_fields_reads_prior_to_version_advisories():
    parsed = sdt_to_sonar.extract_vuln_fields(
        "Requests is a HTTP library. Prior to version 2.33.0, the extract_zipped_paths() utility "
        "function uses a predictable filename when extracting files into the system temp directory "
        "(CVE-2026-25645).")
    assert parsed["cve"] == "CVE-2026-25645"
    assert parsed["package"] == "Requests"
    assert parsed["fix"] == "2.33.0"
    assert parsed["version"] == ""
    assert parsed["title"] == "Requests is a HTTP library"


def test_extract_vuln_fields_reads_fixed_in_version_advisories():
    parsed = sdt_to_sonar.extract_vuln_fields(
        "OpenSSL is a cryptography library. This issue was fixed in version 3.0.1 by restricting "
        "the default cipher list.")
    assert parsed["package"] == "OpenSSL"
    assert parsed["fix"] == "3.0.1"
    assert parsed["cve"] == ""


def test_extract_vuln_fields_handles_messages_without_dependency_metadata():
    assert sdt_to_sonar.extract_vuln_fields("Runs as root user") == {
        "package": "", "version": "", "fix": "", "cve": "", "title": "Runs as root user"}


def test_extract_vuln_fields_splits_on_sentences_not_decimals():
    parsed = sdt_to_sonar.extract_vuln_fields(
        "PyYAML 5.1 through 5.1.2 has insufficient restrictions on the load function because of a "
        "class deserialization issue, e.g., Popen is a class in the subprocess module. "
        "NOTE: this is an incomplete fix.")
    assert parsed["package"] == "PyYAML"
    assert parsed["version"] == "5.1"
    assert parsed["title"] == ("PyYAML 5.1 through 5.1.2 has insufficient restrictions on the load "
                               "function because of a class deserialization issue")
    assert len(parsed["title"]) <= 120


def dependency_finding(message: str, **artifact: str) -> dict:
    finding = {"scanner": {"adapter": "trivy-fs"}, "category": "dependency-vulnerability",
               "rule": {"id": "CVE-2026-25645", "cwe": ["CWE-200"]},
               "severity": {"canonical": "critical"},
               "location": {"path": "package-lock.json"}, "message": message}
    if artifact:
        finding["artifact"] = artifact
    return finding


def test_sonar_dependency_issue_is_one_bounded_line():
    advisory = "Requests is a HTTP library. " + "Detail of the advisory here. " * 60
    report, skipped = sdt_to_sonar.convert({"findings": [dependency_finding(
        advisory, package="requests", installedVersion="2.12.0", fixedVersion="2.33.0",
        target="package-lock.json")]})
    assert skipped == 0
    issue = report["issues"][0]
    message = issue["primaryLocation"]["message"]
    assert len(message) <= 200
    assert message == "requests@2.12.0 — CVE-2026-25645 Requests is a HTTP library. Fixed in 2.33.0."
    assert issue["effortMinutes"] == 10
    rule = report["rules"][0]
    assert rule["tags"] == ["sdt", "dependency", "npm", "cwe"]
    assert rule["description"].endswith(" Full advisory in the SDT report (fleet-findings.xlsx).")
    assert len(rule["description"]) <= 400


def test_sonar_dependency_issue_states_a_missing_fix():
    report, _ = sdt_to_sonar.convert({"findings": [dependency_finding(
        "A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is "
        "susceptible to arbitrary code execution when it processes untrusted YAML files.",
        package="pyyaml", installedVersion="5.1", target="requirements.txt")]})
    message = report["issues"][0]["primaryLocation"]["message"]
    assert len(message) <= 200
    assert message.startswith("pyyaml@5.1 — CVE-2026-25645 A vulnerability was discovered in the "
                              "PyYAML library")
    assert message.endswith("Fixed in 5.4.")


def test_sonar_dependency_issue_says_when_nothing_is_fixed():
    report, _ = sdt_to_sonar.convert({"findings": [dependency_finding(
        "Flask is a lightweight WSGI web application framework. Responses intended for one client "
        "may be cached by a proxy.", package="flask", installedVersion="1.1.2",
        target="requirements.txt")]})
    assert report["issues"][0]["primaryLocation"]["message"] == (
        "flask@1.1.2 — CVE-2026-25645 Flask is a lightweight WSGI web application framework. "
        "No fix available.")


def test_sonar_dependency_message_falls_back_to_the_advisory_text():
    """A flattened report carries no artifact fields, so the prose is the only source."""
    finding = dependency_finding("lodash@4.17.15 Prototype Pollution in handleProto "
                                 "(CVE-2021-23337) is fixed in version 4.17.21.")
    finding["rule"] = {"id": "CVE-2021-23337"}
    report, _ = sdt_to_sonar.convert({"findings": [finding]})
    message = report["issues"][0]["primaryLocation"]["message"]
    assert message.startswith("lodash@4.17.15 — CVE-2021-23337 Prototype Pollution")
    assert message.endswith("Fixed in 4.17.21.")


def test_sonar_tags_name_the_ecosystem_of_each_dependency() -> None:
    findings = []
    for number, target in enumerate(("package-lock.json", "requirements.txt", "pom.xml",
                                     "go.mod", "Makefile"), start=1):
        finding = dependency_finding("Something is unsafe in this release.",
                                     package="p", installedVersion="1", fixedVersion="2", target=target)
        finding["rule"] = {"id": f"CVE-2026-000{number}"}
        finding["location"] = {"path": target}
        findings.append(finding)
    report, _ = sdt_to_sonar.convert({"findings": findings})
    by_rule = {rule["name"]: rule["tags"] for rule in report["rules"]}
    assert by_rule == {
        "CVE-2026-0001": ["sdt", "dependency", "npm"],
        "CVE-2026-0002": ["sdt", "dependency", "pypi"],
        "CVE-2026-0003": ["sdt", "dependency", "maven"],
        "CVE-2026-0004": ["sdt", "dependency", "golang"],
        "CVE-2026-0005": ["sdt", "dependency"],
    }
    for tags in by_rule.values():
        assert len(tags) <= 5
        assert all(tag == tag.lower() and len(tag) <= 20 and tag.isalnum() for tag in tags)


def test_sonar_leaves_non_dependency_findings_exactly_as_they_were():
    advisory = "Detect the use of insecure hash functions. " + "More text. " * 40
    finding = {"scanner": {"adapter": "opengrep"}, "category": "sast",
               "rule": {"id": "insecure-hash", "cwe": ["CWE-327"]},
               "severity": {"canonical": "high"},
               "location": {"path": "src/app.py", "startLine": 2}, "message": advisory}
    report, _ = sdt_to_sonar.convert({"findings": [finding]})
    issue = report["issues"][0]
    assert issue["primaryLocation"]["message"] == advisory[:1000]
    assert issue["effortMinutes"] == sdt_to_sonar.EFFORT["high"]
    rule = report["rules"][0]
    assert rule["tags"] == ["sdt", "cwe"]
    assert rule["description"] == f"CWE-327: {advisory[:500]}"


def test_fleet_register_includes_failure_and_formula_safe_cells(tmp_path):
    root = tmp_path / "run"
    repo_dir = root / "repositories" / "app"
    repo_dir.mkdir(parents=True)
    (repo_dir / "findings.json").write_text(json.dumps({"findings": [{
        "category": "sast", "severity": {"canonical": "high"},
        "rule": {"id": "injection"}, "location": {"path": "src/app.py", "startLine": 8},
        "message": '=HYPERLINK("unsafe")', "fingerprint": {"value": "sha256:123"},
    }]}))
    manifest = {"runId": "pilot", "workspace": "example", "repositories": [
        {"repository": "app", "branch": "main", "commit": "abc", "status": "passed", "findings": 1},
        {"repository": "failed", "branch": "main", "status": "execution_failed", "findings": 0, "error": "clone_failed"},
    ]}
    findings, coverage, totals = sdt_fleet_report.build_rows(manifest, root)
    assert len(findings) == 2
    assert len(coverage) == 3
    assert totals["high"] == 1
    assert totals["repositories_without_report"] == 1
    assert findings[1][13] == "unreviewed"
    book = root / "fleet-findings.xlsx"
    sdt_fleet_report.write_xlsx(book, [("Findings", findings), ("Coverage", coverage)])
    with zipfile.ZipFile(book) as archive:
        for name in archive.namelist():
            if name.endswith(".xml") or name.endswith(".rels"):
                ElementTree.fromstring(archive.read(name))
        sheet = archive.read("xl/worksheets/sheet1.xml").decode()
        assert '=HYPERLINK(&quot;unsafe&quot;)' in sheet
        assert '<f>' not in sheet


def fleet_run(tmp_path, findings: list[dict]) -> tuple[dict, Path]:
    """A one-repository fleet run directory that build_rows can read."""
    run = tmp_path / "run"
    repo = run / "repositories" / "app"
    repo.mkdir(parents=True)
    (repo / "findings.json").write_text(json.dumps({"findings": findings}))
    manifest = {"runId": "pilot", "workspace": "example", "repositories": [
        {"repository": "app", "branch": "main", "commit": "abc", "status": "passed", "findings": len(findings)}]}
    return manifest, run


def advisory(rule_id: str, severity: str, message: str, **artifact: str) -> dict:
    finding = {"scanner": {"adapter": "trivy-fs"}, "category": "dependency-vulnerability",
               "rule": {"id": rule_id}, "severity": {"canonical": severity}, "message": message}
    if artifact:
        finding["artifact"] = artifact
    return finding


def test_hide_unfixed_drops_advisories_that_show_no_fix(tmp_path):
    with_artifact_fix = advisory("CVE-2026-0001", "high", "lodash is a utility library.",
                                 package="lodash", installedVersion="4.17.15", fixedVersion="4.17.21")
    fix_in_prose = advisory("CVE-2026-0002", "critical",
                            "PyYAML 5.1 through 5.1.2 allows code execution, fixed in version 5.4.")
    no_fix = advisory("CVE-2026-0003", "critical",
                      "Flask is a lightweight WSGI web application framework. Responses intended "
                      "for one client may be cached by a proxy.")
    unreadable = advisory("CVE-2026-0004", "medium", "A vulnerability was reported upstream.")
    sast = {"scanner": {"adapter": "opengrep"}, "category": "sast", "rule": {"id": "injection"},
            "severity": {"canonical": "high"}, "location": {"path": "src/app.py", "startLine": 3},
            "message": "Requests is a HTTP library."}
    manifest, run = fleet_run(tmp_path, [with_artifact_fix, fix_in_prose, no_fix, unreadable, sast])

    kept, _, totals = sdt_fleet_report.build_rows(manifest, run)
    assert [row[5] for row in kept[1:]] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003",
                                            "CVE-2026-0004", "injection"]
    assert "hidden_unfixed" not in totals and totals["critical"] == 2

    hidden, _, totals = sdt_fleet_report.build_rows(manifest, run, hide_unfixed=True)
    assert [row[5] for row in hidden[1:]] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0004", "injection"]
    assert totals["hidden_unfixed"] == 1
    assert totals["critical"] == 1  # the hidden row leaves the severity tally too

    empty, _, totals = sdt_fleet_report.build_rows({"repositories": []}, run, hide_unfixed=True)
    assert totals["hidden_unfixed"] == 0  # an applied filter is stated even when it hides nothing


def test_hide_unfixed_uses_structured_identity_over_prose():
    structured_unfixed = {"category": "dependency-vulnerability",
                          "artifact": {"package": "nanotar", "installedVersion": "0.2.0"},
                          "message": "nanotar through 0.2.0 has a path traversal vulnerability."}
    assert sdt_fleet_report.unfixed_advisory(structured_unfixed) is True
    structured_fixed = {**structured_unfixed,
                        "artifact": {"package": "nanotar", "installedVersion": "0.2.0",
                                     "fixedVersion": "0.2.1"}}
    assert sdt_fleet_report.unfixed_advisory(structured_fixed) is False
    flat_unparseable = {"category": "dependency-vulnerability", "message": "weird prose only"}
    assert sdt_fleet_report.unfixed_advisory(flat_unparseable) is False


def test_fleet_report_accepts_the_hide_unfixed_flag(tmp_path, monkeypatch):
    manifest, run = fleet_run(tmp_path, [advisory("CVE-2026-0003", "critical",
                                                  "Flask is a lightweight WSGI web application framework.")])
    source = run / "fleet-manifest.json"
    source.write_text(json.dumps(manifest))
    monkeypatch.setattr(sys, "argv", ["sdt_fleet_report.py", "--from", str(source), "--hide-unfixed"])
    assert sdt_fleet_report.main() == 0
    assert (run / "fleet-summary.pdf").read_bytes().startswith(b"%PDF")
    with zipfile.ZipFile(run / "fleet-findings.xlsx") as book:
        assert b"CVE-2026-0003" not in book.read("xl/worksheets/sheet1.xml")


def test_triage_precision_is_based_only_on_reviewed_findings(tmp_path):
    ledger = tmp_path / "triage.csv"
    ledger.write_text("repository,fingerprint,verdict,reviewer,reason,reviewed_at\n"
                      "app,sha256:123,true_positive,alice,confirmed flow,2026-09-28\n")
    triage = sdt_fleet_report.load_triage(ledger)
    assert triage[("app", "sha256:123")]["verdict"] == "true_positive"
    rows = [sdt_fleet_report.FINDING_COLUMNS,
            ("app", "", "", "sast", "high", "injection", "", "", "", "", "sha256:123", "", "", "true_positive", "", "", "", ""),
            ("app", "", "", "sast", "high", "injection", "", "", "", "", "sha256:456", "", "", "unreviewed", "", "", "", "")]
    quality = sdt_fleet_report.rule_quality_rows(rows)
    assert quality[1][-1] == "100.0%"
    assert quality[1][4] == 1


def test_fleet_export_writes_readable_pdf_and_workbook(tmp_path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir()
    manifest = {"runId": "pilot", "workspace": "example", "repositories": [
        {"repository": "failed", "branch": "main", "status": "execution_failed", "findings": 0,
         "error": "clone_failed"}]}
    source = run / "fleet-manifest.json"
    source.write_text(json.dumps(manifest))
    monkeypatch.setattr(sys, "argv", ["sdt_fleet_report.py", "--from", str(source)])
    assert sdt_fleet_report.main() == 0
    assert (run / "fleet-summary.pdf").read_bytes().startswith(b"%PDF")
    with zipfile.ZipFile(run / "fleet-findings.xlsx") as book:
        assert "xl/worksheets/sheet3.xml" in book.namelist()


def test_pdf_totals_paragraph_reports_the_hidden_count(tmp_path, monkeypatch):
    no_fix = advisory("CVE-2026-0003", "critical",
                      "Flask is a lightweight WSGI web application framework. Responses intended "
                      "for one client may be cached by a proxy.")
    manifest, run = fleet_run(tmp_path, [no_fix])
    stories: list[list] = []

    class RecordingDoc:
        def __init__(self, path, **kwargs):
            pass

        def build(self, story):
            stories.append(story)

    monkeypatch.setattr(sdt_fleet_report, "SimpleDocTemplate", RecordingDoc)

    def totals_for(hide: bool) -> Counter:
        _, coverage, totals = sdt_fleet_report.build_rows(manifest, run, hide_unfixed=hide)
        sdt_fleet_report.write_pdf(run / "out.pdf", manifest, coverage, totals)
        return " | ".join(str(getattr(part, "text", "")) for part in stories[-1])

    assert "Hidden unfixed: 1" in totals_for(True)
    assert "Hidden unfixed" not in totals_for(False)


def test_git_auth_token_is_not_in_helper_script(tmp_path):
    sdt_fleet.git_environment("example-secret", tmp_path)
    assert "example-secret" not in (tmp_path / "askpass.sh").read_text()
    assert (tmp_path / "bitbucket-token").read_text() == "example-secret"
    assert (tmp_path / "bitbucket-token").stat().st_mode & 0o077 == 0


def test_repo_list_skips_comments_and_rejects_bad_slugs(tmp_path):
    listing = tmp_path / "repos.txt"
    listing.write_text("# fleet pilot\n\n  app-one \napp.two_x-3\n")
    assert sdt_fleet.parse_repo_list(listing) == [
        {"slug": "app-one", "branch": "", "name": "app-one", "explicit": False},
        {"slug": "app.two_x-3", "branch": "", "name": "app.two_x-3", "explicit": False}]

    def reject(text: str) -> None:
        listing.write_text(text)
        with pytest.raises(ValueError):
            sdt_fleet.parse_repo_list(listing)

    reject("app-one\napp-one\n")
    reject("app one\n")
    reject("../../etc/passwd\n")


def test_clone_request_differs_by_transport():
    assert sdt_fleet.repository_url("token", "example", "app") == "https://bitbucket.org/example/app.git"
    assert sdt_fleet.repository_url("ssh", "example", "app") == "git@bitbucket.org:example/app.git"
    pinned = sdt_fleet.clone_arguments("token", "example", "app", "main", Path("/tmp/source"))
    assert pinned[pinned.index("--branch") + 1] == "main"
    assert pinned[-2:] == ["https://bitbucket.org/example/app.git", "/tmp/source"]
    default_branch = sdt_fleet.clone_arguments("ssh", "example", "app", "", Path("/tmp/source"))
    assert "--branch" not in default_branch
    assert default_branch[-2:] == ["git@bitbucket.org:example/app.git", "/tmp/source"]


def test_ssh_environment_never_carries_the_token(tmp_path, monkeypatch):
    monkeypatch.setenv("BITBUCKET_ACCESS_TOKEN", "must-not-leak")
    key = tmp_path / "id_ed25519"
    env = sdt_fleet.ssh_environment(key)
    assert env["GIT_SSH_COMMAND"] == f"ssh -i {key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert "GIT_ASKPASS" not in env
    assert not any("must-not-leak" in value for value in env.values())


def test_ssh_key_must_exist_and_stay_private(tmp_path):
    key = tmp_path / "id_ed25519"
    assert not sdt_fleet.ssh_key_is_private(key)
    key.write_text("private key material")
    key.chmod(0o644)
    assert not sdt_fleet.ssh_key_is_private(key)
    key.chmod(0o600)
    assert sdt_fleet.ssh_key_is_private(key)


CE_TASK_ID = "0f8e2a5c-3f1d-4b6a-9c7e-1d2e3f4a5b6c"
CE_TASK_LINE = ("More about the report processing at "
                f"http://localhost:9000/api/ce/task?id={CE_TASK_ID}\n")


def test_ce_task_id_is_parsed_from_scanner_output():
    assert sdt_fleet.parse_ce_task_id(CE_TASK_LINE) == CE_TASK_ID
    assert sdt_fleet.parse_ce_task_id("SonarQube server is up\n" + CE_TASK_LINE) == CE_TASK_ID
    assert sdt_fleet.parse_ce_task_id("Task not found.") == ""
    assert sdt_fleet.parse_ce_task_id("") == ""


def test_poll_sonar_task_waits_for_a_successful_import():
    pages = iter([{"task": {"status": "PENDING"}}, {"task": {"status": "IN_PROGRESS"}}, {"task": {"status": "SUCCESS"}}])
    asked: list[tuple[str, str]] = []

    def fake_fetch(sonar_url, task_id, token):
        asked.append((sonar_url, task_id))
        return next(pages)

    state, reason = sdt_fleet.poll_sonar_task("http://localhost:9000", "task-1", "analysis-token",
                                              timeout=60, interval=5, sleep=lambda seconds: None, fetch=fake_fetch)
    assert (state, reason) == ("imported", "")
    assert asked == [("http://localhost:9000", "task-1")] * 3


def test_poll_sonar_task_reports_a_failed_or_canceled_import():
    def failing(sonar_url, task_id, token):
        return {"task": {"status": "FAILED", "errorMessage": "cannot parse\nsonar-external.json"}}

    assert sdt_fleet.poll_sonar_task("http://localhost:9000", "task-1", "analysis-token",
                                     timeout=60, sleep=lambda seconds: None,
                                     fetch=failing) == ("import_failed", "cannot parse sonar-external.json")

    def canceled(sonar_url, task_id, token):
        return {"task": {"status": "CANCELED"}}

    assert sdt_fleet.poll_sonar_task("http://localhost:9000", "task-1", "analysis-token",
                                     timeout=60, sleep=lambda seconds: None,
                                     fetch=canceled) == ("import_failed", "CANCELED")


def test_poll_sonar_task_gives_up_at_the_deadline():
    def never(sonar_url, task_id, token):
        raise AssertionError("an expired deadline must not call the API")

    state, reason = sdt_fleet.poll_sonar_task("http://localhost:9000", "task-1", "analysis-token",
                                              timeout=0, sleep=lambda seconds: None, fetch=never)
    assert (state, reason) == ("import_unconfirmed", "deadline_expired")


def test_poll_sonar_task_bounds_and_sanitizes_the_reason():
    def noisy(sonar_url, task_id, token):
        return {"task": {"status": "FAILED", "errorMessage": f"boom {token} " + "x" * 400}}

    state, reason = sdt_fleet.poll_sonar_task("http://localhost:9000", "task-1", "analysis-token",
                                              timeout=60, sleep=lambda seconds: None, fetch=noisy)
    assert state == "import_failed"
    assert len(reason) <= 300
    assert "analysis-token" not in reason


def test_token_transport_still_requires_a_bitbucket_token(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("BITBUCKET_ACCESS_TOKEN", raising=False)
    listing = tmp_path / "repos.txt"
    listing.write_text("app\n")
    monkeypatch.setattr(sys, "argv", ["sdt_fleet.py", "--workspace", "example",
                                      "--repo-list", str(listing), "--list"])
    with pytest.raises(SystemExit) as refused:
        sdt_fleet.main()
    assert refused.value.code == 2
    assert "BITBUCKET_ACCESS_TOKEN" in capsys.readouterr().err


def test_ssh_transport_with_repo_list_never_reads_the_api(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("BITBUCKET_ACCESS_TOKEN", raising=False)

    def unexpected(*args, **kwargs):
        raise AssertionError("ssh transport must not call the Bitbucket inventory")

    monkeypatch.setattr(sdt_fleet, "repository_inventory", unexpected)
    key = tmp_path / "id_ed25519"
    key.write_text("private key material")
    key.chmod(0o600)
    listing = tmp_path / "repos.txt"
    listing.write_text("# pilot only\n\napp-one\n")
    monkeypatch.setattr(sys, "argv", ["sdt_fleet.py", "--workspace", "example", "--transport", "ssh",
                                      "--ssh-key", str(key), "--repo-list", str(listing), "--list"])
    assert sdt_fleet.main() == 0
    assert capsys.readouterr().out == "app-one\t\n"


def test_ssh_transport_refuses_a_world_readable_key(tmp_path, monkeypatch):
    key = tmp_path / "id_ed25519"
    key.write_text("private key material")
    key.chmod(0o604)
    monkeypatch.setattr(sys, "argv", ["sdt_fleet.py", "--workspace", "example", "--transport", "ssh",
                                      "--ssh-key", str(key), "--repo-list", str(tmp_path / "absent.txt"), "--list"])
    with pytest.raises(SystemExit) as refused:
        sdt_fleet.main()
    assert refused.value.code == 2


def test_repo_list_scan_follows_and_records_the_remote_default_branch(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    key = tmp_path / "id_ed25519"
    key.write_text("private key material")
    key.chmod(0o600)
    args = argparse.Namespace(transport="ssh", ssh_key=key, workspace="example", work_dir=work,
                              clone_timeout=30, scan_timeout=30, rules=tmp_path, sdt=tmp_path / "sdt",
                              scan_config=tmp_path, sonar=False, sonar_scanner=tmp_path / "scanner",
                              sonar_url="http://localhost:9000", sonar_timeout=30)
    calls: list[tuple[list[str], dict[str, str]]] = []

    def fake_run_command(command, *, cwd, env, timeout):
        calls.append((command, env))
        stdout = "main" if "--abbrev-ref" in command else "abc123"
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(sdt_fleet, "run_command", fake_run_command)
    monkeypatch.setattr(sdt_fleet, "git_environment",
                        lambda *args, **kwargs: pytest.fail("ssh transport must not write a token file"))
    record = sdt_fleet.scan_repository({"slug": "app", "branch": "", "name": "app"}, args, "", tmp_path / "run", "")
    assert record["branch"] == "main"
    assert record["commit"] == "abc123"
    clone, clone_env = calls[0]
    assert "--branch" not in clone and clone[-2] == "git@bitbucket.org:example/app.git"
    assert clone_env["GIT_SSH_COMMAND"] == f"ssh -i {key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes"
    resolved = [command for command, _ in calls if command[:3] == ["git", "rev-parse", "--abbrev-ref"]]
    assert resolved and resolved[0][-1] == "HEAD"


def scanned_envs(tmp_path, monkeypatch) -> dict[str, dict[str, str]]:
    """Run scan_repository over two pilots with a fake run_command; keep each scan env."""
    work = tmp_path / "work"
    work.mkdir()
    key = tmp_path / "id_ed25519"
    key.write_text("private key material")
    key.chmod(0o600)
    args = argparse.Namespace(transport="ssh", ssh_key=key, workspace="example", work_dir=work,
                              clone_timeout=30, scan_timeout=30, rules=tmp_path, sdt=tmp_path / "sdt",
                              scan_config=tmp_path, sonar=False, sonar_scanner=tmp_path / "scanner",
                              sonar_url="http://localhost:9000", sonar_timeout=30,
                              sonar_classes=tmp_path / "classes")
    envs: dict[str, dict[str, str]] = {}

    def fake_run_command(command, *, cwd, env, timeout):
        if command[:2] == ["git", "rev-parse"]:
            return subprocess.CompletedProcess(command, 0, stdout="abc123", stderr="")
        if command[0] == str(args.sdt):
            report = Path(command[command.index("--output") + 1])
            envs[report.name] = env
            report.mkdir(parents=True, exist_ok=True)
            (report / "findings.json").write_text(json.dumps({"status": "passed", "findings": []}))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(sdt_fleet, "run_command", fake_run_command)
    for slug in ("app-one", "app-two"):
        sdt_fleet.scan_repository({"slug": slug, "branch": "main", "name": slug}, args, "",
                                  tmp_path / "run", "")
    return envs


def test_scan_environment_never_carries_a_trivy_ignorefile(tmp_path, monkeypatch):
    """Suppression is report-side: the scanner is never handed an ignore file."""
    monkeypatch.delenv("SDT_TRIVY_IGNOREFILE", raising=False)
    envs = scanned_envs(tmp_path, monkeypatch)
    assert sorted(envs) == ["app-one", "app-two"]
    assert all("SDT_TRIVY_IGNOREFILE" not in env for env in envs.values())


def test_flag_defaults_follow_the_environment(tmp_path, monkeypatch):
    for name, value in {"SDT_FLEET_SDT_BIN": "bin/sdt", "SDT_FLEET_RULES": "pack",
                        "SDT_FLEET_SCAN_CONFIG": "scan.yaml", "SDT_FLEET_SONAR_SCANNER": "bin/sonar-scanner",
                        "SDT_FLEET_SONAR_TOKEN_FILE": ".sonar-token", "SDT_FLEET_SONAR_CLASSES": "classes",
                        "SDT_FLEET_OUTPUT": "out",
                        "SDT_FLEET_WORK": "work"}.items():
        monkeypatch.setenv(name, str(tmp_path / value))
    args = sdt_fleet.build_parser().parse_args(["--workspace", "example"])
    assert (args.sdt, args.rules, args.scan_config) == (tmp_path / "bin/sdt", tmp_path / "pack",
                                                        tmp_path / "scan.yaml")
    assert (args.sonar_scanner, args.sonar_token_file, args.sonar_classes) == (tmp_path / "bin/sonar-scanner",
                                                                              tmp_path / ".sonar-token",
                                                                              tmp_path / "classes")
    assert (args.output, args.work_dir) == (tmp_path / "out", tmp_path / "work")
    monkeypatch.setenv("SDT_FLEET_WORK", "   ")
    assert sdt_fleet.build_parser().parse_args(["--workspace", "example"]).work_dir == Path(tempfile.gettempdir())


def test_unset_flag_defaults_keep_the_local_paths(monkeypatch):
    for name in ("SDT_FLEET_SDT_BIN", "SDT_FLEET_RULES", "SDT_FLEET_SCAN_CONFIG", "SDT_FLEET_SONAR_SCANNER",
                 "SDT_FLEET_SONAR_TOKEN_FILE", "SDT_FLEET_SONAR_CLASSES",
                 "SDT_FLEET_OUTPUT", "SDT_FLEET_WORK"):
        monkeypatch.delenv(name, raising=False)
    args = sdt_fleet.build_parser().parse_args(["--workspace", "example"])
    assert args.sdt == sdt_fleet.ROOT / "sdt"
    assert args.rules == sdt_fleet.ROOT / "rules" / "opengrep-rules"
    assert args.scan_config == sdt_fleet.ROOT / "examples" / "fleet" / "scan-config.yaml"
    assert str(args.sonar_scanner).startswith("/home/wishnu/sd-lab/")
    assert str(args.sonar_token_file).startswith("/home/wishnu/sd-lab/")
    assert str(args.sonar_classes).startswith("/home/wishnu/sdt-fleet/")
    assert args.output == sdt_fleet.ROOT / "reports" / "fleet"


@pytest.mark.parametrize("returncode, stdout, stderr, state, reason, polled", [
    (0, CE_TASK_LINE, "", "imported", "", True),
    (0, "", CE_TASK_LINE, "imported", "", True),
    (0, "Nothing about task processing.\n", "", "import_unconfirmed", "no_ce_task_id", False),
    (1, CE_TASK_LINE, "Error: SonarQube server not available", "failed",
     " ".join(f"Error: SonarQube server not available\n{CE_TASK_LINE}".split()), False),
])
def test_scan_repository_records_the_ce_import_verdict(tmp_path, monkeypatch, returncode, stdout, stderr, state, reason, polled):
    work = tmp_path / "work"
    work.mkdir()
    key = tmp_path / "id_ed25519"
    key.write_text("private key material")
    key.chmod(0o600)
    args = argparse.Namespace(transport="ssh", ssh_key=key, workspace="example", work_dir=work,
                              clone_timeout=30, scan_timeout=30, rules=tmp_path, sdt=tmp_path / "sdt",
                              scan_config=tmp_path, sonar=True, sonar_scanner=tmp_path / "scanner",
                              sonar_url="http://localhost:9000", sonar_timeout=30, sonar_poll_timeout=60,
                              sonar_branch=False,
                              sonar_classes=tmp_path / "classes")
    asked: list[tuple[str, str, int]] = []
    submitted: list[list[str]] = []

    def fake_poll(sonar_url, task_id, token, *, timeout):
        asked.append((sonar_url, task_id, timeout))
        return "imported", ""

    def fake_run_command(command, *, cwd, env, timeout):
        if command[:2] == ["git", "rev-parse"]:
            landed = "main" if "--abbrev-ref" in command else "abc123"
            return subprocess.CompletedProcess(command, 0, stdout=landed, stderr="")
        if command[0] == str(args.sonar_scanner):
            submitted.append(command)
            return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)
        if "--output" in command:
            report = Path(command[command.index("--output") + 1])
            (report / "findings.json").write_text(json.dumps({"status": "passed", "findings": []}))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(sdt_fleet, "poll_sonar_task", fake_poll)
    monkeypatch.setattr(sdt_fleet, "run_command", fake_run_command)
    record = sdt_fleet.scan_repository({"slug": "app", "branch": "main", "name": "app"}, args, "",
                                       tmp_path / "run", "analysis-token")
    assert record["sonar"] == state
    assert record.get("sonarError", "") == reason
    assert asked == ([("http://localhost:9000", CE_TASK_ID, 60)] if polled else [])
    assert not any("analysis-token" in argument for argument in submitted[0])


def test_repo_list_accepts_slug_branch_pairs(tmp_path):
    listing = tmp_path / "repos.txt"
    listing.write_text("# comment\n\napp-one\napp-two:feature/NGNH-123\n")
    repos = sdt_fleet.parse_repo_list(listing)
    assert repos == [{"slug": "app-one", "branch": "", "name": "app-one", "explicit": False},
                     {"slug": "app-two", "branch": "feature/NGNH-123", "name": "app-two", "explicit": True}]

    bad = tmp_path / "bad.txt"
    bad.write_text("app-one:two words\n")
    with pytest.raises(ValueError):
        sdt_fleet.parse_repo_list(bad)

    dup = tmp_path / "dup.txt"
    dup.write_text("app-one\napp-one:main\n")
    with pytest.raises(ValueError):
        sdt_fleet.parse_repo_list(dup)


def test_sonar_branch_name_is_passed_only_when_requested(tmp_path):
    checkout = tmp_path / "source"
    checkout.mkdir()
    report = tmp_path / "sonar-external.json"

    def argv(branch: str) -> list[str]:
        return sdt_fleet.sonar_scan_arguments(Path("sonar-scanner"), "http://localhost:9000", "sdt_example_app",
                                              "example/app", report, checkout, tmp_path / "missing-classes",
                                              branch=branch)

    assert not any(argument.startswith("-Dsonar.branch.name") for argument in argv(""))
    assert "-Dsonar.branch.name=feature/x" in argv("feature/x")


def test_sonar_argv_widens_test_scope_and_compiled_sensors(tmp_path):
    checkout = tmp_path / "source"
    (checkout / "src" / "main" / "java").mkdir(parents=True)
    classes = tmp_path / "classes"
    report = tmp_path / "sonar-external.json"

    def argv(classes_dir: Path = classes) -> list[str]:
        return sdt_fleet.sonar_scan_arguments(Path("sonar-scanner"), "http://localhost:9000", "sdt_example_app",
                                              "example/app", report, checkout, classes_dir)

    def binaries(command: list[str]) -> list[str]:
        return [argument for argument in command if "binaries" in argument]
    assert argv()[:1] == ["sonar-scanner"]
    assert argv().count("-Dsonar.tests=") == 1 and not binaries(argv())

    (checkout / "src" / "main" / "java" / "App.java").write_text("class App {}\n")
    classes.mkdir()
    assert argv() == ["sonar-scanner", "-Dsonar.host.url=http://localhost:9000",
                      "-Dsonar.projectKey=sdt_example_app", "-Dsonar.projectName=example/app",
                      "-Dsonar.sources=.", "-Dsonar.tests=", f"-Dsonar.externalIssuesReportPaths={report}",
                      f"-Dsonar.java.binaries={classes}"]

    (checkout / "App.kt").write_text("class App\n")
    assert argv()[-2:] == [f"-Dsonar.java.binaries={classes}", f"-Dsonar.kotlin.binaries={classes}"]

    assert binaries(argv(tmp_path / "absent-classes")) == []


def test_source_file_probe_is_bounded(tmp_path):
    (tmp_path / "deep").mkdir()
    (tmp_path / "deep" / "App.java").write_text("class App {}\n")
    assert sdt_fleet.has_source_file(tmp_path, ".java")
    assert not sdt_fleet.has_source_file(tmp_path, ".kt")
    assert not sdt_fleet.has_source_file(tmp_path / "nowhere", ".java")


def test_scanner_failure_reason_keeps_the_tail_and_never_the_token():
    reason = sdt_fleet.scanner_failure_reason(stdout="INFO: uploading",
                                              stderr="ERROR: head-marker " + "x" * 400 + " analysis-token",
                                              secret="analysis-token")
    assert len(reason) <= 300
    assert "analysis-token" not in reason
    assert "head-marker" not in reason
    assert "[redacted]" in reason
    assert reason.endswith("INFO: uploading")


def test_fleet_driver_keeps_manifest_and_exports(tmp_path, monkeypatch):
    monkeypatch.setenv("BITBUCKET_ACCESS_TOKEN", "test-token")
    monkeypatch.setattr(sdt_fleet, "repository_inventory", lambda workspace, token: [
        {"slug": "demo", "branch": "main", "name": "Demo"}])

    def fake_scan(repo, args, token, run_dir, sonar_token):
        artifact = run_dir / "repositories" / "demo"
        artifact.mkdir(parents=True)
        (artifact / "findings.json").write_text(json.dumps({"findings": []}))
        return {"repository": "demo", "branch": "main", "status": "passed", "findings": 0,
                "pdf": "ready", "sonar": "not_run"}

    monkeypatch.setattr(sdt_fleet, "scan_repository", fake_scan)
    monkeypatch.setattr(sys, "argv", ["sdt_fleet.py", "--workspace", "example", "--output", str(tmp_path)])
    assert sdt_fleet.main() == 0
    runs = list(tmp_path.glob("*/fleet-manifest.json"))
    assert len(runs) == 1
    manifest = json.loads(runs[0].read_text())
    assert manifest["selectedRepositories"] == 1
    assert manifest["repositories"][0]["repository"] == "demo"
    assert (runs[0].parent / "fleet-findings.xlsx").is_file()
    assert (runs[0].parent / "fleet-summary.pdf").is_file()


def single_repo_run(tmp_path) -> tuple[Path, Path, Path, Path]:
    """A one-repository Jenkins workspace laid out the way sdt_fleet_report reads a fleet run."""
    run = tmp_path / "run"
    repo = run / "repositories" / "app"
    repo.mkdir(parents=True)
    findings_path = repo / "findings.json"
    native = repo / "run-manifest.json"
    native.write_text(json.dumps({"tasks": [{"adapter": "opengrep", "state": "ok"}], "exitCode": 1}))
    return run, findings_path, native, run / "fleet-manifest.json"


def test_repo_manifest_describes_one_scan(tmp_path, monkeypatch, capsys):
    run, findings_path, native, out = single_repo_run(tmp_path)
    findings_path.write_text(json.dumps({"status": "policy_failed", "runId": "20260929T101010Z-deadbeef",
                                         "findings": [{"category": "sast"}, {"category": "secret"}]}))
    monkeypatch.setattr(sys, "argv", ["sdt_repo_manifest.py", "--findings", str(findings_path),
                                      "--run-manifest", str(native), "--slug", "app", "--branch", "main",
                                      "--workspace", "example", "--commit", "abc123", "--out", str(out)])
    assert sdt_repo_manifest.main() == 0
    manifest = json.loads(out.read_text())
    assert (manifest["schemaVersion"], manifest["runId"], manifest["workspace"]) == (
        "sdt/fleet/v1", "20260929T101010Z-deadbeef", "example")
    assert (manifest["selectedRepositories"], manifest["repositoryCount"]) == (1, 1)
    record = manifest["repositories"][0]
    assert {key: value for key, value in record.items() if key != "completedAt"} == {
        "repository": "app", "branch": "main", "commit": "abc123", "status": "policy_failed",
        "sonar": "imported", "pdf": "ready", "findings": 2, "runId": "20260929T101010Z-deadbeef",
        "sonarProjectKey": "sdt_example_app_1c0e2a3341", "sdtExitCode": 1}
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", record["completedAt"])
    assert out.read_text().endswith("}\n")
    assert capsys.readouterr().out == f"fleet manifest: {out} (repo=app status=policy_failed findings=2)\n"


def test_repo_manifest_round_trips_through_the_fleet_report(tmp_path, monkeypatch):
    """A report over one scan is the report tool's own contract: same layout, same rows."""
    run, findings_path, native, out = single_repo_run(tmp_path)
    findings_path.write_text(json.dumps({"status": "passed", "findings": [
        {"scanner": {"adapter": "opengrep"}, "category": "sast", "rule": {"id": "injection"},
         "severity": {"canonical": "high"}, "location": {"path": "src/app.py", "startLine": 8},
         "message": "untrusted input reaches a shell", "fingerprint": {"value": "sha256:123"}}]}))
    monkeypatch.setattr(sys, "argv", ["sdt_repo_manifest.py", "--findings", str(findings_path),
                                      "--run-manifest", str(native), "--slug", "app", "--branch", "main",
                                      "--workspace", "example", "--commit", "abc123",
                                      "--sonar-status", "import_unconfirmed", "--out", str(out)])
    assert sdt_repo_manifest.main() == 0
    findings, coverage, totals = sdt_fleet_report.build_rows(json.loads(out.read_text()), run)
    assert len(findings) == 2 and findings[1][0] == "app" and findings[1][2] == "passed"
    assert totals["high"] == 1 and totals["repositories_without_report"] == 0
    # the coverage row joins the record to the adapter states in that scan's run-manifest.json
    assert coverage[1] == ("app", "main", "abc123", "passed", 1, 1, "ok", "not_run", "not_run",
                           "import_unconfirmed", "ready", "")


def test_repo_manifest_refuses_a_bad_slug_or_a_missing_input(tmp_path, monkeypatch, capsys):
    run, findings_path, native, out = single_repo_run(tmp_path)
    findings_path.write_text(json.dumps({"status": "passed", "findings": []}))

    def invoke(slug: str, manifest: Path = native) -> int:
        monkeypatch.setattr(sys, "argv", ["sdt_repo_manifest.py", "--findings", str(findings_path),
                                          "--run-manifest", str(manifest), "--slug", slug,
                                          "--branch", "main", "--workspace", "example", "--out", str(out)])
        return sdt_repo_manifest.main()

    assert invoke("../../etc/passwd") == 2
    assert invoke("app", run / "absent-run-manifest.json") == 2
    assert not out.exists() and not list(out.parent.glob("*.tmp"))
    assert "../../etc/passwd" in capsys.readouterr().err


def test_review_packet_excludes_secret_and_caps_work(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("password = sensitivevalue123\nexecute(user_input)\n")
    findings = [
        {"category": "secret", "rule": {"id": "secret"}, "message": "token"},
        {"category": "sast", "rule": {"id": "command-injection"},
         "severity": {"canonical": "high"}, "location": {"path": "app.py", "startLine": 2},
         "fingerprint": {"value": "sha256:abc"}, "message": "untrusted shell"},
    ]
    output = tmp_path / "codex-review.md"
    assert sdt_fleet.write_review_packet(output, findings, source, limit=1) == 1
    packet = output.read_text()
    assert "sensitivevalue123" not in packet
    assert "token" not in packet
    assert "[redacted]" in packet


# ------------------------------------------------------------------ DOCX report
W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

DOCX_FINDINGS = {"findings": [
    {"scanner": {"adapter": "opengrep"}, "category": "sast", "rule": {"id": "scp.dart.tls.bad-cert"},
     "severity": {"canonical": "high"}, "message": "certificate validation disabled",
     "location": {"path": "lib/api.dart", "startLine": 3}, "remediation": {"guidance": "Remove it. Pin instead."}},
    {"scanner": {"adapter": "opengrep"}, "category": "sast", "rule": {"id": "scp.dart.tls.bad-cert"},
     "severity": {"canonical": "high"}, "message": "certificate validation disabled",
     "location": {"path": "test/api_test.dart", "startLine": 1}},
    {"scanner": {"adapter": "gitleaks"}, "category": "secret", "rule": {"id": "generic-api-key"},
     "severity": {"canonical": "high"}, "message": "Detected a key", "location": {"path": "lib/api.dart", "startLine": 2},
     "evidence": {"text": "key = \"[REDACTED]\""}, "metadata": {"commit": "a1b2c3d4e5f6a7b8"}},
    {"scanner": {"adapter": "gitleaks"}, "category": "secret", "rule": {"id": "gcp-api-key"},
     "severity": {"canonical": "high"}, "message": "Detected a key", "location": {"path": "env/.env", "startLine": 1},
     "metadata": {"commit": "0f0f0f0f0f0f0f0f"}},
    {"scanner": {"adapter": "trivy-fs"}, "category": "dependency-vulnerability", "rule": {"id": "CVE-2026-1"},
     "severity": {"canonical": "critical"}, "location": None, "reachability": {"state": "reachable"},
     "artifact": {"package": "dio", "installedVersion": "4.0.0", "fixedVersion": "5.0.0, 4.2.1", "target": "pubspec.lock"}},
    {"scanner": {"adapter": "trivy-fs"}, "category": "dependency-vulnerability", "rule": {"id": "CVE-2026-2"},
     "severity": {"canonical": "medium"}, "location": None,
     "artifact": {"package": "dio", "installedVersion": "4.0.0", "fixedVersion": "4.3.0", "target": "pubspec.lock"}},
    {"scanner": {"adapter": "trivy-fs"}, "category": "misconfiguration", "rule": {"id": "DS-0002"},
     "severity": {"canonical": "high"}, "message": "Image user should not be 'root'",
     "location": {"path": "Dockerfile", "startLine": 1}},
]}


def _checkout(tmp_path):
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "api.dart").write_text("a\nkey = \"placeholder\"\nclient.badCertificateCallback = (c, h, p) => true;\nd\n")
    return tmp_path


def _docx(path):
    with zipfile.ZipFile(path) as z:
        document = z.read("word/document.xml").decode()
        footer = z.read("word/footer1.xml").decode()
        rels = z.read("word/_rels/document.xml.rels").decode()
    root = ElementTree.fromstring(document)  # well-formed, or this raises
    return "".join(t.text or "" for t in root.iter(W_NS + "t")), document, footer, rels


def _png(path):
    """A 2x1 PNG, so the logo tests do not depend on a brand file in the repository."""
    import struct
    import zlib

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    raw = zlib.compress(b"\x00" + b"\x00\x3f\x7e" * 2)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 1, 8, 2, 0, 0, 0))
                     + chunk(b"IDAT", raw) + chunk(b"IEND", b""))
    return path


def _write_report(tmp_path, found, scope_url="https://example.test/pr/1", src_root=None, logo=None):
    found = dict(found)
    found["dependency"] = sdt_to_docx.consolidate(found["dependency"])
    report = sdt_to_docx.Report("app", "ws/app", "pull request 1", scope_url, "abc1234", "SDT", found["code"],
                                found["secret"], found["dependency"], found["config"], sdt_to_docx.date(2026, 9, 30))
    out = tmp_path / "r.docx"
    sdt_to_docx.write_docx(report, src_root, out, logo=logo)
    return _docx(out)


def test_docx_report_leads_with_code_security_then_secrets_then_dependencies(tmp_path):
    root = _checkout(tmp_path)
    found = sdt_to_docx.merge(sdt_to_docx.from_findings(DOCX_FINDINGS, root), None)
    text, document, footer, rels = _write_report(tmp_path, found, src_root=root)
    order = [text.index(title) for title in ("1. Code Security", "2. Secret Leaks",
                                             "3. Dependencies & Configuration (Trivy)", "Review Notes")]
    assert order == sorted(order)
    assert "<!--" not in document + footer + rels
    assert "SAST Report - app | 30 September 2026" in footer
    assert 'Target="https://example.test/pr/1"' in rels and 'r:id="rIdScope"' in document
    assert "badCertificateCallback" in text  # the code excerpt for the occurrence
    assert "in test code" in text


def test_docx_many_findings_are_grouped_by_file_without_losing_any(tmp_path):
    root = _checkout(tmp_path)
    for i in range(25):
        (root / "lib" / f"f{i:02}.dart").write_text("a\nb\nrisky()\nd\ne\nf\ng\nh\ni\nj\nk\nl\nrisky()\n")
    group = sdt_to_docx.Group("r", "Rule", "Security Hotspot", "High")
    group.occurrences = [sdt_to_docx.Occurrence(f"lib/f{i:02}.dart", 3, f"m{i}", "To review", "") for i in range(25)]
    group.occurrences += [sdt_to_docx.Occurrence("lib/f00.dart", line, "m-extra", "To review", "") for line in (4, 13)]
    text, document, _, _ = _write_report(tmp_path, {"code": [group], "secret": [], "dependency": [], "config": []},
                                         src_root=root)
    assert "Occurrences - 27 findings in 25 files" in text
    assert "1.1.1 lib/f00.dart" in text and "1.1.25 lib/f24.dart" in text  # every file, no cap
    for i in range(25):
        assert f"m{i}" in text  # every finding's details are listed
    # f00: lines 3, 4 and 13 are close enough to share one excerpt; 24 other files one each.
    assert document.count('w:fill="F3F4F6"/><w:spacing w:before="60"') == 25
    assert "// lib/f00.dart:3, 4, 13" in text


def test_few_findings_keep_one_excerpt_and_advisory_each(tmp_path):
    root = _checkout(tmp_path)
    group = sdt_to_docx.Group("r", "Rule", "Security Hotspot", "High")
    group.occurrences = [sdt_to_docx.Occurrence("lib/api.dart", line, f"m{line}", "To review", "") for line in (1, 3)]
    text, document, _, _ = _write_report(tmp_path, {"code": [group], "secret": [], "dependency": [], "config": []},
                                         src_root=root)
    assert "Occurrences - 2 findings" in text and "findings in" not in text
    assert document.count('w:fill="F3F4F6"/><w:spacing w:before="60"') == 2


def test_generic_rule_based_check_is_printed_once_per_rule(tmp_path):
    root = _checkout(tmp_path)
    note = {"verdict": "needs_context", "confidence": "rule-based", "reason": "r", "check": "Find the URL.",
            "suggested_fix": "x", "source": "rules"}
    group = sdt_to_docx.Group("r", "Rule", "Security Hotspot", "High")
    group.occurrences = [sdt_to_docx.Occurrence("lib/api.dart", line, "m", "To review", "", ai=dict(note))
                         for line in range(1, 13)]
    text, *_ = _write_report(tmp_path, {"code": [group], "secret": [], "dependency": [], "config": []}, src_root=root)
    assert text.count("Find the URL.") == 1 and "Applies to 12 occurrences" in text
    assert text.count("manual check as described for this rule above") == 12  # each finding still listed


def test_docx_secret_rows_say_where_the_secret_is_and_never_its_value(tmp_path):
    root = _checkout(tmp_path)
    secrets = {r.path: r for r in sdt_to_docx.from_findings(DOCX_FINDINGS, root)["secret"]}
    assert secrets["lib/api.dart"].where == "Current code"  # 'key = "[REDACTED]"' still matches line 2
    assert secrets["env/.env"].where == "Git history only"
    assert secrets["env/.env"].commit == "0f0f0f0f0f0f"
    text, *_ = _write_report(tmp_path, sdt_to_docx.merge(sdt_to_docx.from_findings(DOCX_FINDINGS, root), None))
    assert "REDACTED" not in text and "[REDACTED]" not in text


def test_docx_dependencies_are_one_row_per_package_with_one_upgrade_target():
    rows = sdt_to_docx.consolidate(sdt_to_docx.from_findings(DOCX_FINDINGS)["dependency"])
    assert len(rows) == 1
    dio = rows[0]
    assert set(dio.advisories) == {"CVE-2026-1", "CVE-2026-2"}
    assert dio.severity == "Critical" and dio.reachable == "Yes"
    # CVE-1 is fixed in 4.2.1 on this line (5.0.0 on the next), CVE-2 in 4.3.0: both need 4.3.0.
    assert sdt_to_docx.upgrade_to(dio) == "4.3.0"
    assert [c.check for c in sdt_to_docx.from_findings(DOCX_FINDINGS)["config"]] == ["DS-0002"]


def test_docx_sonar_rule_keys_are_sorted_into_the_right_section():
    category = sdt_to_docx.category
    assert category("typescript:S6299") == "code"
    assert category("opengrep-dart:scp.dart.tls.bad-cert") == "code"
    assert category("external_sdt-opengrep:sdt-opengrep-x-0123456789abcdef") == "code"
    assert category("secrets:S6334") == "secret"
    assert category("sdt:secret-in-history") == "secret"
    assert category("external_sdt-gitleaks:sdt-gitleaks-gcp-api-key-0123456789abcdef") == "secret"
    assert category("sdt:vulnerable-dependency-unreachable") == "dependency"
    assert category("external_sdt-trivy-fs:sdt-trivy-fs-CVE-2026-1-0123456789abcdef") == "dependency"
    assert category("external_sdt-trivy-fs:sdt-trivy-fs-DS-0002-0123456789abcdef") == "config"
    assert sdt_to_docx.external_id("external_sdt-gitleaks:sdt-gitleaks-gcp-api-key-0123456789abcdef") == "gcp-api-key"


def test_docx_a_secret_found_by_gitleaks_and_by_sonar_is_listed_once(tmp_path):
    root = _checkout(tmp_path)
    sdt = sdt_to_docx.from_findings(DOCX_FINDINGS, root)
    sonar = {"code": [], "dependency": [], "config": [], "secret": [
        sdt_to_docx.SecretRow("Google API keys", "env/.env", 1, "", "Current code", "High", "Safe"),
        sdt_to_docx.SecretRow("Slack token", "lib/other.dart", 9, "", "Current code", "High", "Open")]}
    merged = sdt_to_docx.merge(sonar, sdt)
    assert [(r.path, r.line) for r in merged["secret"]].count(("env/.env", 1)) == 1
    assert next(r for r in merged["secret"] if r.path == "env/.env").status == "Safe"  # Sonar's review wins
    assert any(r.path == "lib/other.dart" for r in merged["secret"])  # found only by Sonar: kept


def test_docx_report_without_a_scope_link_has_no_dangling_relationship(tmp_path):
    text, document, _, rels = _write_report(tmp_path, {"code": [], "secret": [], "dependency": [], "config": []},
                                            scope_url="")
    assert "rIdScope" not in document + rels
    assert "No open findings in this scope." in text


def test_docx_code_excerpt_never_leaves_the_checkout(tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("do not quote me\n")
    root = tmp_path / "repo"
    root.mkdir()
    assert sdt_to_docx.snippet(root, sdt_to_docx.Occurrence("../secret.txt", 1, "m", "Open", "")) == []


def test_docx_rule_text_keeps_sentences_not_headings_links_or_citations():
    rule = {"descriptionSections": [
        {"key": "root_cause", "content": "<p>Rendering raw HTML allows XSS.</p><h3>Ask Yourself Whether</h3>"},
        {"key": "how_to_fix", "content": "<h2>Recommended Secure Coding Practices</h2><ul><li>Avoid v-html.</li>"
                                         "<li>Vue.js - Security - Injecting HTML</li>"
                                         "<li>OWASP - Top 10 2021 Category A3 - Injection</li></ul>"
                                         "<h2>Compliant Solution</h2><pre>&lt;div&gt;{{ x }}&lt;/div&gt;</pre>"}]}
    assert sdt_to_docx.rule_texts(rule) == (["Rendering raw HTML allows XSS."], ["Avoid v-html."])
    plugin_rule = {"htmlDesc": "<p>Bad cert.</p><h2>How to fix it</h2><p>Pin it.</p><h2>Standards</h2><ul><li>CWE-295</li></ul>"}
    assert sdt_to_docx.rule_texts(plugin_rule) == (["Bad cert."], ["Pin it."])


def test_docx_plurals_read_naturally():
    assert sdt_to_docx.plural(2, "vulnerability") == "2 vulnerabilities"
    assert sdt_to_docx.plural(1, "security hotspot") == "1 security hotspot"
    assert sdt_to_docx.plural(3, "key") == "3 keys"


def test_sonar_sync_maps_only_decided_hotspots_and_issues():
    hotspots = [{"key": "H1", "ruleKey": "opengrep-dart:x", "component": "p:lib/a.dart", "line": 4,
                 "status": "REVIEWED", "resolution": "SAFE", "assignee": "ann"},
                {"key": "H2", "ruleKey": "opengrep-dart:x", "component": "p:lib/a.dart", "line": 9,
                 "status": "TO_REVIEW"}]
    issues = [{"key": "I1", "rule": "sdt:secret-in-history", "component": "p", "resolution": "WONTFIX",
               "message": "Secret (generic-api-key) in git history: env/.env:3 at commit abc. Rotate it."},
              {"key": "I2", "rule": "opengrep-dart:y", "component": "p:lib/b.dart", "line": 2, "status": "OPEN"}]
    decisions = sdt_sonar_sync.decisions_from_sonar(hotspots, issues)
    assert [(d["key"], d["verdict"], d["path"], d["line"]) for d in decisions] == [
        ("H1", "false_positive", "lib/a.dart", 4), ("I1", "accepted_risk", "env/.env", 3)]


def test_rule_precision_recommends_only_with_enough_evidence():
    rec = sdt_rule_precision.recommend
    assert rec(0, 0, 5) == (None, "no reviews yet")
    assert rec(1, 1, 5)[1] == "collect more reviews (2/5)"
    assert rec(9, 1, 5) == (0.9, "keep")
    assert rec(3, 3, 5) == (0.5, "demote to Security Hotspot")
    assert rec(1, 4, 5)[1].startswith("disable")


def test_rule_precision_lists_the_noisiest_rules_first():
    pairs = [("opengrep", "good", "true_positive")] * 6 + [("opengrep", "noisy", "false_positive")] * 5 + \
            [("opengrep", "noisy", "true_positive"), ("opengrep", "new", "unreviewed")]
    rows = sdt_rule_precision.rows_from(pairs, 5)
    assert [r["rule"] for r in rows] == ["noisy", "good", "new"]
    assert rows[0]["precision"] == "0.17" and rows[0]["recommendation"].startswith("disable")


def test_docx_a_secret_is_current_only_if_its_line_still_exists(tmp_path):
    (tmp_path / "cfg.json").write_text('{\n  "other": 1,\n  "api_key": "AIzaNEW"\n}\n')
    where = sdt_to_docx._where
    # First committed at line 2; the file changed, but the key line is still there (moved).
    assert where(tmp_path, "cfg.json", 2, '"api_key": "[REDACTED]"') == "Current code"
    # The line number exists, but that secret line is gone: history only.
    assert where(tmp_path, "cfg.json", 2, '"password": "[REDACTED]"') == "Git history only"
    assert where(tmp_path, "gone.json", 1, '"x": "[REDACTED]"') == "Git history only"


# ------------------------------------------------------------------ AI triage (advisory)
def _triage_groups(tmp_path):
    root = _checkout(tmp_path)
    return root, sdt_to_docx.from_findings(DOCX_FINDINGS, root)["code"]


def _run_triage(root, groups, call, **limits):
    options = dict(per_call_timeout=30, budget=600, max_rules=15, max_per_rule=6, max_failures=2)
    options.update(limits)
    return sdt_triage_codex.triage(groups, root, "codex", "gpt-6-luna", call=call, **options)


def test_triage_records_only_well_formed_answers_for_the_ids_asked(tmp_path):
    root, groups = _triage_groups(tmp_path)
    prompts = []

    def call(codex, model, prompt, timeout):
        prompts.append(prompt)
        return {"results": [
            {"id": "o1", "verdict": "likely_false_positive", "confidence": "high", "reason": "pinned elsewhere",
             "check": "confirm pinning", "suggested_fix": ""},
            {"id": "o9", "verdict": "likely_true_positive", "confidence": "high", "reason": "not asked", "suggested_fix": ""},
            {"id": "o1", "verdict": "likely_true_positive", "confidence": "low", "reason": "duplicate", "suggested_fix": ""},
            {"id": "o2", "verdict": "definitely", "confidence": "high", "reason": "bad enum", "suggested_fix": ""}]}

    report = _run_triage(root, groups, call)
    assert report["advisory"] is True and report["model"] == "gpt-6-luna"
    assert [(r["path"], r["line"], r["verdict"]) for r in report["results"]] == [
        ("lib/api.dart", 3, "likely_false_positive")]
    assert "badCertificateCallback" in prompts[0] and "scp.dart.tls.bad-cert" in prompts[0]


def test_triage_stops_after_consecutive_failures_instead_of_spending_more(tmp_path):
    root, groups = _triage_groups(tmp_path)
    many = [sdt_to_docx.Group(f"r{i}", "n", "Finding", "High", occurrences=list(groups[0].occurrences)) for i in range(5)]
    calls = []

    def call(codex, model, prompt, timeout):
        calls.append(timeout)
        raise subprocess.TimeoutExpired("codex", timeout)

    report = _run_triage(root, many, call, max_failures=2)
    assert len(calls) == 2 and report["failed_calls"] == 2 and report["results"] == []
    assert report["stopped"].startswith("2 consecutive failed calls")


def test_triage_respects_the_time_budget(tmp_path):
    root, groups = _triage_groups(tmp_path)
    many = [sdt_to_docx.Group(f"r{i}", "n", "Finding", "High", occurrences=list(groups[0].occurrences)) for i in range(5)]
    now = iter([0, 0, 50, 95, 200, 300])
    report = _run_triage(root, many, lambda *a: {"results": []}, budget=100, clock=lambda: next(now))
    assert report["stopped"] == "time budget spent" and report["calls"] < 5


def test_triage_never_sends_secret_values(tmp_path):
    stripe = "sk_" + "live_" + "0123456789abcdefghij"  # built at runtime: no key-shaped literal in the source
    code = f'const apiKey = "{stripe}";\nfinal google = "AIza' + "B" * 35 + '";\npassword: "hunter22x"'
    redacted = sdt_triage_codex.redact(code)
    assert stripe not in redacted and "AIzaB" not in redacted and "hunter22x" not in redacted
    assert redacted.count("[REDACTED]") == 3


def test_without_codex_the_triage_step_is_a_no_op(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))  # no codex anywhere
    monkeypatch.delenv("SDT_CODEX_BIN", raising=False)
    out = tmp_path / "triage.json"
    result = subprocess.run([sys.executable, str(Path(sdt_triage_codex.__file__)), "--out", str(out),
                             "--findings", str(tmp_path / "missing.json"), "--src-root", str(tmp_path)],
                            capture_output=True, text=True)
    assert result.returncode == 0 and not out.exists()
    assert "normal report" in result.stdout


def test_report_shows_review_recommendations_without_ai_wording(tmp_path):
    root = _checkout(tmp_path)
    found = sdt_to_docx.merge(sdt_to_docx.from_findings(DOCX_FINDINGS, root), None)
    rule = found["code"][0].rule
    matched = sdt_to_docx.apply_triage(found["code"], {"results": [
        {"rule": rule, "path": "lib/api.dart", "line": 3, "verdict": "likely_true_positive", "confidence": "high",
         "reason": "Line 3 accepts every certificate.", "check": "Confirm the client at line 3 is used in release builds.",
         "suggested_fix": "Remove the callback."}]})
    assert matched == 1
    found["dependency"] = sdt_to_docx.consolidate(found["dependency"])
    report = sdt_to_docx.Report("app", "ws/app", "branch main", "", "abc", "SDT", found["code"], found["secret"],
                                found["dependency"], found["config"], sdt_to_docx.date(2026, 9, 30),
                                {"engine": "codex", "model": "gpt-6-luna", "stopped": ""})
    out = tmp_path / "ai.docx"
    sdt_to_docx.write_docx(report, root, out)
    text, *_ = _docx(out)
    for line in ("Assessment: Real issue - fix required (certainty: High)",
                 "Evidence: Line 3 accepts every certificate.",
                 "Confirm impact: Confirm the client at line 3 is used in release builds.",
                 "Fix: Remove the callback."):
        assert line in text, line
    assert "Advisory review of 1 of 2 code findings: 0 false positives (can be marked Safe after the listed check), 1 real issue" in text
    assert 'w:color w:val="6B21A8"' in _docx(out)[1]  # the advisory block is purple
    # The report reads as a review, not as machine output.
    for word in ("AI", "Codex", "gpt", "model"):
        assert not re.search(rf"\\b{word}\\b", text, re.I), word
    assert "Fix First" in text and "Remove the callback." in text  # a confirmed real issue is priority 1
    plain, *_ = _write_report(tmp_path, sdt_to_docx.merge(sdt_to_docx.from_findings(DOCX_FINDINGS, root), None))
    assert "Advisory review" not in plain


def test_report_pages_have_header_page_numbers_logo_and_repeating_table_headers(tmp_path):
    root = _checkout(tmp_path)
    found = sdt_to_docx.merge(sdt_to_docx.from_findings(DOCX_FINDINGS, root), None)
    text, document, footer, rels = _write_report(tmp_path, found, src_root=root, logo=_png(tmp_path / "logo.png"))
    with zipfile.ZipFile(tmp_path / "r.docx") as z:
        header = z.read("word/header1.xml").decode()
        names = z.namelist()
        types = z.read("[Content_Types].xml").decode()
    assert "SAST Report - app" in header and 'r:embed="rIdHdrLogo"' in header
    assert 'w:instr=" PAGE "' in footer and 'w:instr=" NUMPAGES "' in footer
    assert "word/media/logo.png" in names and 'Extension="png"' in types and 'r:embed="rIdLogo"' in document
    assert "<w:tblHeader/>" in document and "<w:cantSplit/>" in document
    assert document.count("<w:pageBreakBefore/>") == 4  # Fix First, 1., 2., 3.
    assert "<w:titlePg/>" in document  # no header on the cover
    for anchor in ("sec_fix_first", "sec_code", "sec_secrets", "sec_dependencies", "sec_notes"):
        assert f'w:anchor="{anchor}"' in document and f'w:name="{anchor}"' in document
    assert "Scanners" in text


def test_report_without_a_logo_has_no_picture(tmp_path):
    root = _checkout(tmp_path)
    found = sdt_to_docx.merge(sdt_to_docx.from_findings(DOCX_FINDINGS, root), None)
    text, document, footer, rels = _write_report(tmp_path, found, src_root=root)
    with zipfile.ZipFile(tmp_path / "r.docx") as z:
        header = z.read("word/header1.xml").decode()
        names = z.namelist()
    assert "SAST Report - app" in header and "rIdHdrLogo" not in header
    assert not any(n.startswith("word/media/") for n in names) and "rIdLogo" not in document + rels


def test_review_wording_is_fixed_per_outcome():
    fp = sdt_to_docx.review_lines({"verdict": "likely_false_positive", "confidence": "high", "reason": "Constant URL at line 9.",
                                   "check": "Confirm URL stays constant.", "suggested_fix": "constant URL, no user input"})
    assert fp == [("Assessment", "False positive - can be marked Safe (certainty: High)"),
                  ("Evidence", "Constant URL at line 9."), ("Before marking Safe, confirm", "Confirm URL stays constant."),
                  ("Record in SonarQube", "constant URL, no user input")]
    manual = sdt_to_docx.review_lines({"verdict": "needs_context", "confidence": "medium", "reason": "r", "check": "c"})
    assert [name for name, _ in manual] == ["Assessment", "Evidence", "Check"]


# ------------------------------------------------------------ deterministic report parts
import sdt_advisory  # noqa: E402


def _src(tmp_path, name, text):
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    return tmp_path


def test_rule_based_advisory_is_deterministic_and_only_concludes_on_strong_signals(tmp_path):
    root = _src(tmp_path, "lib/pin.dart", 'debugPrint("PIN: ${_controller.pinInput}");\n'
                                          'print("Initializing OoaCredential");\n'
                                          'final ns = "http://www.w3.org/2000/svg";\n'
                                          'final n = Random().nextInt(9); // skeleton placeholder count\n'
                                          'webView.loadRequest(Uri.parse(url));\n')
    assess = sdt_advisory.assess
    real = assess("opengrep-dart:scp.flutter.logging.sensitive-data", "lib/pin.dart", 1, root)
    assert real["verdict"] == "likely_true_positive" and "pinInput" in real["reason"]
    static = assess("opengrep-dart:scp.flutter.logging.sensitive-data", "lib/pin.dart", 2, root)
    assert static["verdict"] == "likely_false_positive"
    assert assess("opengrep-dart:scp.flutter.network.cleartext-http", "lib/pin.dart", 3, root)["verdict"] == \
        "likely_false_positive"
    assert assess("opengrep-dart:scp.dart.random.insecure", "lib/pin.dart", 4, root)["verdict"] == "likely_false_positive"
    manual = assess("opengrep-dart:scp.dart.webview.javascript-unrestricted", "lib/pin.dart", 5, root)
    assert manual["verdict"] == "needs_context" and "loadRequest" in manual["check"]
    assert assess("any:rule", "test/api_test.dart", 1, root)["verdict"] == "likely_false_positive"
    # Same input, same output: no model, no randomness.
    assert manual == assess("opengrep-dart:scp.dart.webview.javascript-unrestricted", "lib/pin.dart", 5, root)
    assert manual["confidence"] == "rule-based"


def test_secrets_group_by_type_and_file_and_client_keys_are_restricted_not_rotated():
    Row = sdt_to_docx.SecretRow
    rows = [Row("gcp-api-key", "android/app/google-services.json", 23, "aaa", "Current code", "High"),
            Row("gcp-api-key", "android/app/google-services.json", 59, "bbb", "Git history only", "High"),
            Row("Google API keys should not be disclosed", "android/app/google-services.json", 65, "", "Current code",
                "High", "To review"),
            Row("generic-api-key", "lib/api.dart", 8, "ccc", "Current code", "High"),
            Row("generic-api-key", "env/.env", 1, "ddd", "Git history only", "High")]
    groups = sdt_to_docx.group_secrets(rows)
    assert [(g.kind, g.path, g.count) for g in groups] == [
        ("generic-api-key", "lib/api.dart", 1), ("generic-api-key", "env/.env", 1),
        ("gcp-api-key", "android/app/google-services.json", 3)]
    firebase = groups[-1]
    assert firebase.client_key and firebase.where == "Code and history" and "rotation not required" in firebase.action
    assert groups[0].action.startswith("Rotate, then remove")


def test_trend_counts_new_fixed_and_open_by_fingerprint():
    def doc(*items):
        return {"findings": [{"fingerprint": {"value": v}, "category": c} for v, c in items]}
    now = doc(("a", "sast"), ("b", "sast"), ("s1", "secret"))
    before = doc(("a", "sast"), ("c", "sast"), ("s1", "secret"), ("s2", "secret"))
    assert sdt_to_docx.compare(now, before) == {"code": (1, 1, 1), "secret": (0, 1, 1), "dependency": (0, 0, 0)}


def test_coverage_gaps_come_from_the_pipeline_and_the_run_manifest(tmp_path):
    (tmp_path / "coverage.txt").write_text("Dart lint skipped: dependencies did not resolve\n\n")
    (tmp_path / "findings.json").write_text("{}")
    (tmp_path / "run-manifest.json").write_text(json.dumps({"tasks": [{"adapter": "opengrep", "state": "completed"},
                                                                       {"adapter": "trivy-fs", "state": "failed"}]}))
    gaps = sdt_to_docx.coverage_gaps(tmp_path / "coverage.txt", tmp_path / "findings.json")
    assert gaps == ["Dart lint skipped: dependencies did not resolve",
                    "Scanner trivy-fs did not complete (failed): its findings may be missing."]


def test_review_context_is_the_enclosing_function_not_the_if_body():
    code = ['class Page extends StatelessWidget {', '  final String url = "https://x";',
            '  Widget build(BuildContext c) {', '    if (ready) {', '      controller.loadRequest(Uri.parse(url));',
            '    }', '    return Text("{ not a brace }");', '  }', '  void other() {}', '}']
    assert sdt_triage_codex.enclosing_block(code, 4) == (2, 7)


def test_report_has_a_word_table_of_contents_and_a_coverage_section(tmp_path):
    root = _checkout(tmp_path)
    found = sdt_to_docx.merge(sdt_to_docx.from_findings(DOCX_FINDINGS, root), None)
    text, document, *_ = _write_report(tmp_path, found, src_root=root)
    assert 'TOC \\o "1-2" \\h \\z \\u' in document and 'w:fldCharType="end"' in document
    assert "Coverage" in text and "no coverage gaps" in text


def test_report_uses_modern_fonts_brand_headers_and_purple_advisory_columns(tmp_path):
    root = _checkout(tmp_path)
    found = sdt_to_docx.merge(sdt_to_docx.from_findings(DOCX_FINDINGS, root), None)
    for group in found["code"]:
        for occurrence in group.occurrences:
            occurrence.ai = sdt_advisory.assess(group.rule, occurrence.path, occurrence.line, root)
    _, document, *_ = _write_report(tmp_path, found, src_root=root)
    with zipfile.ZipFile(tmp_path / "r.docx") as z:
        styles, theme = z.read("word/styles.xml").decode(), z.read("word/theme/theme1.xml").decode()
    assert set(re.findall(r'w:ascii="([^"]+)"', styles)) == {"Segoe UI", "Segoe UI Semibold"}
    assert "asciiTheme" not in styles and 'typeface="Segoe UI"' in theme
    assert 'w:fill="003F7E"' in document  # navy table header rows
    # Purple marks the advisory's heading and bold labels only; its normal text stays black.
    label = re.search(r'<w:r><w:rPr><w:b/><w:color w:val="6B21A8"/>[^<]*<w:sz w:val="\d+"/></w:rPr>'
                      r'<w:t xml:space="preserve">Assessment: </w:t></w:r><w:r><w:rPr>(.*?)</w:rPr>', document)
    assert label and "6B21A8" not in label.group(1)


def test_excerpt_includes_lines_the_advisory_cites_and_redacts_secrets(tmp_path):
    lines = [f"line{i}" for i in range(1, 101)]
    lines[79] = "    _dio.options.headers.addAll({"
    key = "k3yV4lue" + "0123456789abcdef"  # built at runtime: no key-shaped literal in the source
    lines[91] = f"      'x-api-key': '{key}',"
    lines[92] = '      "password": "hunter22xyz",'
    root = _src(tmp_path, "lib/http_helper.dart", "\n".join(lines) + "\n")
    note = {"verdict": "likely_true_positive", "confidence": "high",
            "reason": "At line 92, setupAuditTrail adds the hardcoded x-api-key header.", "check": "", "suggested_fix": ""}
    assert sdt_to_docx.cited_lines(note, 80) == [92]
    blocks = sdt_to_docx.snippet_blocks(root, "lib/http_helper.dart", [80], cited=sdt_to_docx.cited_lines(note, 80))
    text = "\n".join("\n".join(b) for b in blocks)
    assert len(blocks) == 1 and ">   80" in text and "*   92" in text  # one continuous excerpt, 80 through 92
    assert "(* cited: 92)" in text
    assert key not in text and "hunter22xyz" not in text and "[REDACTED]" in text


def test_no_secret_value_reaches_any_part_of_the_report(tmp_path):
    secret = "k3yV4lue" + "0123456789abcdef"  # built at runtime: no key-shaped literal in the source
    root = _src(tmp_path, "lib/api.dart", f"a\nb\nfinal headers = {{'x-api-key': '{secret}'}};\nd\n"
                                          f'const apiKey = "{secret}";\n')
    group = sdt_to_docx.Group("opengrep-dart:scp.flutter.secrets.hardcoded-api-key", "Hardcoded key",
                              "Vulnerability", "High")
    group.occurrences = [sdt_to_docx.Occurrence("lib/api.dart", n, f"key at {n}", "Open", "") for n in (3, 5)]
    for occurrence in group.occurrences:  # rule-based evidence quotes the flagged line
        occurrence.ai = sdt_advisory.assess(group.rule, occurrence.path, occurrence.line, root)
    _, document, footer, rels = _write_report(tmp_path, {"code": [group], "secret": [], "dependency": [], "config": []},
                                              src_root=root)
    with zipfile.ZipFile(tmp_path / "r.docx") as z:
        everything = "".join(z.read(name).decode("utf-8", "ignore") for name in z.namelist() if name.endswith(".xml"))
    assert secret not in everything
    assert "[REDACTED]" in document


def test_file_links_open_bitbucket_at_the_scanned_commit_with_the_lines_highlighted(tmp_path):
    base = sdt_to_docx.bitbucket_base("mirae-asset-id/app", "2d50829cc3b8")
    assert base == "https://bitbucket.org/mirae-asset-id/app/src/2d50829cc3b8"
    assert sdt_to_docx.code_url(base, "lib/a b.dart", [80]) == \
        "https://bitbucket.org/mirae-asset-id/app/src/2d50829cc3b8/lib/a%20b.dart#lines-80"
    assert sdt_to_docx.code_url(base, "lib/a.dart", [92, 80, 85]).endswith("/lib/a.dart#lines-80:92")
    assert "/src/0f0f0f0f/" in sdt_to_docx.code_url(base, "env/.env", [1], commit="0f0f0f0f")  # history secret
    root = _checkout(tmp_path)
    found = sdt_to_docx.merge(sdt_to_docx.from_findings(DOCX_FINDINGS, root), None)
    found["dependency"] = sdt_to_docx.consolidate(found["dependency"])
    report = sdt_to_docx.Report("app", "mirae-asset-id/app", "branch main", "", "2d50829cc3b8", "SDT", found["code"],
                                found["secret"], found["dependency"], found["config"], sdt_to_docx.date(2026, 9, 30),
                                source_base=base)
    out = tmp_path / "links.docx"
    sdt_to_docx.write_docx(report, root, out)
    text, _, _, rels = _docx(out)
    assert "File (opens Bitbucket)" in text
    assert 'Target="https://bitbucket.org/mirae-asset-id/app/src/2d50829cc3b8/lib/api.dart#lines-3"' in rels
    assert "localhost" not in rels
