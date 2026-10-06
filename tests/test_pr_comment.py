"""The pull-request comment the Jenkins integration posts to Bitbucket Cloud."""

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "integrations" / "jenkins" / "resources" / "sdt" / "pr_comment.py"
TOKEN = "tok-do-not-print"
REPO = "/2.0/repositories/ws/shop"


class FakeBitbucket:
    def __init__(self, private=True, comments=(), fail_comment=False):
        self.private, self.comments, self.fail_comment = private, list(comments), fail_comment
        self.requests = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def answer(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def handle_any(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                fake.requests.append((self.command, self.path, self.headers.get("Authorization"), body))
                path = self.path.split("?")[0]
                if self.command == "GET" and path == REPO:
                    return self.answer(200, {"is_private": fake.private})
                if self.command == "POST" and path == f"{REPO}/downloads":
                    return self.answer(201, {})
                if self.command == "GET" and path.endswith("/comments"):
                    return self.answer(200, {"values": fake.comments})
                if fake.fail_comment:
                    return self.answer(403, {"error": {"message": "no pull request write scope"}})
                return self.answer(201, {"id": 7})

            do_GET = do_POST = do_PUT = handle_any

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.api = f"http://127.0.0.1:{self.server.server_port}/2.0"

    def sent(self, method):
        return [r for r in self.requests if r[0] == method]

    def uploads(self):
        return [r for r in self.sent("POST") if r[1].endswith("/downloads")]

    def comment_text(self, method):
        return json.loads(self.sent(method)[-1][3])["content"]["raw"]


def finding(category, level, rule, path, line):
    return {"category": category, "severity": {"canonical": level}, "rule": {"id": rule},
            "location": {"path": path, "startLine": line}}


@pytest.fixture
def out(tmp_path):
    (tmp_path / "sdt").mkdir()
    (tmp_path / "sdt" / "findings-new.json").write_text(json.dumps({"findings": [
        finding("sast", "medium", "pack.dart.insecure-random", "lib/a.dart", 12),
        finding("secret", "critical", "generic-api-key", "lib/config.dart", 3),
    ]}))
    (tmp_path / "quality-gate.txt").write_text("OK\n")
    (tmp_path / "sonar-project-key").write_text("sdt_ws_shop_abc\n")
    (tmp_path / "SAST Report - shop.docx").write_bytes(b"PK-docx-bytes")
    (tmp_path / "security-report.pdf").write_bytes(b"%PDF-bytes")
    return tmp_path


def run(fake, out, **extra):
    env = {"PATH": os.environ["PATH"], "OUT": str(out), "REPO_SLUG": "shop", "WORKSPACE_NAME": "ws", "PR_ID": "42",
           "BITBUCKET_TOKEN": TOKEN, "BITBUCKET_API": fake.api, "BUILD_URL": "https://ci.example/job/x/9/",
           "SONAR_HOST_URL": "https://sonar.example", **extra}
    done = subprocess.run([sys.executable, str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60)
    assert TOKEN not in done.stdout + done.stderr
    return done


def test_pass_posts_comment_with_findings_and_uploaded_report(out):
    fake = FakeBitbucket()
    done = run(fake, out)
    assert done.returncode == 0, done.stdout + done.stderr
    text = fake.comment_text("POST")
    assert text.startswith("### SDT security scan: PASSED")
    assert "adds **2** new security findings (1 code, 1 secret)" in text
    # most severe first; the rule is shown by its last segment
    assert text.index("generic-api-key") < text.index("insecure-random")
    assert "`lib/config.dart:3`" in text and "pack.dart" not in text
    assert "https://bitbucket.org/ws/shop/downloads/SAST%20Report%20-%20shop%20-%20PR%2042.docx" in text
    assert "https://sonar.example/dashboard?id=sdt_ws_shop_abc&pullRequest=42" in text
    upload = fake.uploads()[0]
    assert b"PK-docx-bytes" in upload[3] and b'filename="SAST Report - shop - PR 42.docx"' in upload[3]
    assert all(r[2] == f"Bearer {TOKEN}" for r in fake.requests)


def test_failed_gate_says_failed_with_conditions(out):
    (out / "quality-gate.txt").write_text("ERROR\n   new_vulnerabilities ERROR 1\n")
    fake = FakeBitbucket()
    assert run(fake, out).returncode == 0
    text = fake.comment_text("POST")
    assert text.startswith("### SDT security scan: FAILED")
    assert "Why it failed: 1 new vulnerability." in text


def test_scan_that_never_reached_the_gate_is_not_a_pass(out):
    (out / "quality-gate.txt").unlink()
    fake = FakeBitbucket()
    assert run(fake, out).returncode == 0
    text = fake.comment_text("POST")
    assert text.startswith("### SDT security scan: NOT COMPLETED") and "not a pass" in text


def test_second_scan_updates_the_earlier_comment(out):
    fake = FakeBitbucket(comments=[
        {"id": 3, "content": {"raw": "looks good to me"}},
        {"id": 5, "content": {"raw": "### SDT security scan: FAILED\n\nold"}},
    ])
    assert run(fake, out).returncode == 0
    assert fake.sent("PUT")[-1][1] == f"{REPO}/pullrequests/42/comments/5"
    assert not [r for r in fake.sent("POST") if r[1].endswith("/comments")]


def test_public_repository_gets_no_upload_and_links_the_build_artifact(out):
    fake = FakeBitbucket(private=False)
    assert run(fake, out).returncode == 0
    assert not fake.uploads()
    assert "https://ci.example/job/x/9/artifact/out/SAST%20Report%20-%20shop.docx" in fake.comment_text("POST")


def test_no_new_findings_and_basic_auth_with_a_user(out):
    (out / "sdt" / "findings-new.json").write_text(json.dumps({"findings": []}))
    fake = FakeBitbucket()
    assert run(fake, out, BITBUCKET_USER="bot@example.com", SDT_PR_REPORT_UPLOAD="0").returncode == 0
    assert "adds no new security findings" in fake.comment_text("POST")
    assert all(r[2].startswith("Basic ") for r in fake.requests)
    assert not fake.uploads()


def test_refused_comment_fails_without_printing_the_token(out):
    fake = FakeBitbucket(fail_comment=True)
    done = run(fake, out)
    assert done.returncode == 1
    assert "403" in done.stdout and "no pull request write scope" in done.stdout


# ------------------------------------------------------------------ reports repository
PUBLISH = SCRIPT.with_name("publish_report.py")


def bare(reports):
    return reports / "ws" / "security-reports.git"


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout


@pytest.fixture
def reports(tmp_path_factory):
    root = tmp_path_factory.mktemp("bitbucket")
    (root / "ws").mkdir()
    git("init", "--quiet", "--bare", "--initial-branch=main", str(bare(root)))
    return root


def publish(out, reports, **extra):
    env = {"PATH": os.environ["PATH"], "HOME": str(out), "OUT": str(out), "REPO_SLUG": "shop", "WORKSPACE_NAME": "ws",
           "BITBUCKET_TOKEN": TOKEN, "SDT_REPORTS_REPO": "security-reports", "BITBUCKET_GIT": f"file://{reports}",
           "SCOPE_URL": "https://bitbucket.org/ws/shop/pull-requests/42", **extra}
    done = subprocess.run([sys.executable, str(PUBLISH)], env=env, capture_output=True, text=True, timeout=120)
    assert TOKEN not in done.stdout + done.stderr
    return done


def published(reports, path):
    return git("--git-dir", str(bare(reports)), "show", f"main:{path}")


def test_pull_request_report_is_committed_and_its_address_handed_to_the_comment(out, reports):
    (out / "quality-gate.txt").write_text("ERROR\n")
    done = publish(out, reports, PR_ID="42")
    assert done.returncode == 0, done.stdout + done.stderr
    text = published(reports, "shop/pull-requests/42/report.md")
    assert "**FAILED**" in text and "[pull request #42](https://bitbucket.org/ws/shop/pull-requests/42)" in text
    assert "| Critical | Secret | generic-api-key | `lib/config.dart:3` |  |" in text
    assert git("--git-dir", str(bare(reports)), "ls-tree", "--name-only", "main",
               "shop/pull-requests/42/").count("SAST Report.docx") == 1
    assert published(reports, "shop/pull-requests/42/security-report.pdf") == "%PDF-bytes"
    url = (out / "report-url.txt").read_text().strip()
    assert url == "https://bitbucket.org/ws/security-reports/src/main/shop/pull-requests/42/report.md"

    fake = FakeBitbucket()
    assert run(fake, out).returncode == 0
    text = fake.comment_text("POST")
    assert f"[Report]({url})" in text and "security-report.pdf" not in text
    assert f"[Word (.docx)]({url[:-len('report.md')]}SAST%20Report.docx)" in text
    assert not fake.uploads()


def test_branch_report_goes_under_branches_and_a_rescan_without_changes_adds_no_commit(out, reports):
    (out / "sdt" / "findings-report.json").write_text(json.dumps({"findings": [
        finding("sast", "high", "x.eval", "src/a.js", 8),
        finding("dependency-vulnerability", "low", "CVE-2020-1", "package-lock.json", 4),
        dict(finding("sast", "low", "x.covered", "src/b.js", 1), suppression={"reason": "reviewed"}),
    ]}))
    assert publish(out, reports, BRANCH="release/1.0").returncode == 0
    text = published(reports, "shop/branches/release_1.0/report.md")
    assert "**PASSED**" in text and "`src/a.js:8`" in text and "covered" not in text
    assert "| Low | Dependency | CVE-2020-1 |" in text  # the same type names as the pull-request comment
    assert publish(out, reports, BRANCH="release/1.0").returncode == 0
    assert git("--git-dir", str(bare(reports)), "rev-list", "--count", "main").strip() == "1"


def test_two_scans_publish_to_the_same_repository(out, reports):
    assert publish(out, reports, PR_ID="42").returncode == 0
    assert publish(out, reports, PR_ID="43").returncode == 0
    assert "pull request #43" in published(reports, "shop/pull-requests/43/report.md")
    assert "pull request #42" in published(reports, "shop/pull-requests/42/report.md")


def test_unreachable_reports_repository_fails_quietly(out, reports):
    done = publish(out, reports, PR_ID="42", SDT_REPORTS_REPO="missing")
    assert done.returncode == 1 and "report not published" in done.stdout
    assert not (out / "report-url.txt").exists()


# ------------------------------------------------------------------ what the comment lists
@pytest.fixture(scope="module")
def pc():
    import importlib.util
    sys.path.insert(0, str(SCRIPT.parent))  # as when the script is run: its own folder holds sdt_common.py
    try:
        spec = importlib.util.spec_from_file_location("pr_comment", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT.parent))
    return module


def test_one_row_per_package_and_per_flagged_line(pc):
    rows = [
        pc.row("critical", "Dependency", "CVE-2017-5941 in node-serialize 0.0.4 (no fixed version published yet).", "package-lock.json:28", "dep"),
        pc.row("high", "Dependency", "NSWG-ECO-311 in node-serialize 0.0.4: upgrade.", "package-lock.json:28", "dep"),
        pc.row("high", "Code", "Command built from a request", "app/export.js:29", "exec"),
        pc.row("high", "To review", "Make sure that executing this OS command is safe here.", "app/export.js:29", "S4721"),
        pc.row("critical", "Secret", "Make sure this key gets revoked", "app/a.js:4", "S6290"),
        pc.row("high", "Secret", "Possible access key", "app/a.js:4", "aws"),
        pc.row("low", "To review", "Weak hash", "app/export.js:39", "S4790"),
    ]
    text = pc.body("FAILED", ["2 new vulnerabilities"], rows, [], [], "", "main")
    assert "adds **4** new security findings (1 code, 1 dependency, 1 secret, 1 to review)" in text
    assert "| Critical | Dependency | node-serialize 0.0.4: CVE-2017-5941, NSWG-ECO-311 | `package-lock.json:28` |" in text
    assert "executing this OS command" not in text and "Possible access key" not in text
    assert "Why it failed: 2 new vulnerabilities." in text


def test_fixed_counts_only_code_in_files_the_pull_request_touches(pc, tmp_path):
    def item(category, rule, path, value):
        return {"category": category, "rule": {"id": rule}, "location": {"path": path, "startLine": 3},
                "fingerprint": {"value": value}}
    (tmp_path / "base").mkdir()
    (tmp_path / "sdt").mkdir()
    (tmp_path / "base" / "findings.json").write_text(json.dumps({"findings": [
        item("sast", "x.eval", "app/form.js", "a"), item("sast", "x.exec", "app/other.js", "b"),
        item("secret", "aws-key", "app/form.js", "c"), item("sast", "x.kept", "app/form.js", "d")]}))
    (tmp_path / "sdt" / "findings.json").write_text(json.dumps({"findings": [item("sast", "x.kept", "app/form.js", "d")]}))
    assert pc.fixed(str(tmp_path), {"app/form.js"}) == ["eval at `app/form.js:3`"]
    assert pc.fixed(str(tmp_path), None) == []


def test_messages_never_carry_a_key_like_value(pc):
    assert "wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzKEY12345" not in pc.safe("leaked wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzKEY12345 here")
    assert pc.condition("new_security_rating ERROR 5") == "security rating of the new code is E (must be A)"


def test_findings_without_a_line_and_packages_in_one_manifest_each_keep_their_row(pc):
    rows = [
        pc.row("high", "Dependency", "CVE-2023-1 in requests 2.0.0", "requirements.txt", "dep"),
        pc.row("critical", "Dependency", "CVE-2022-2 in flask 0.5", "requirements.txt", "dep"),
        pc.row("high", "Code", "Debug mode on", "settings.py", "debug"),
        pc.row("medium", "Code", "CSRF check off", "settings.py", "csrf"),
    ]
    text = pc.body("FAILED", [], rows, [], [], "", "main")
    assert "adds **4** new security findings (2 code, 2 dependency)" in text
    assert "requests 2.0.0: CVE-2023-1" in text and "flask 0.5: CVE-2022-2" in text and "CSRF check off" in text


def test_a_rule_about_tokens_is_code_and_a_rule_that_finds_one_is_a_secret(pc):
    assert pc.kind_of_rule("pack.js.jwt-token-not-verified") == "Code"
    assert pc.kind_of_rule("pack.go.weak-password-hash") == "Code"
    assert pc.kind_of_rule("external_opengrep:scp.common.secrets.aws-access-key-id") == "Secret"
    assert pc.kind_of_rule("secrets:S6290") == "Secret" and pc.kind_of_rule("sdt:vulnerable-dependency") == "Dependency"


def test_dependency_keeps_the_advisory_severity_and_its_package_name(pc, tmp_path):
    (tmp_path / "sdt").mkdir()
    package = "golang.org/x/crypto/ssh_agent_forwarding_v2"
    (tmp_path / "sdt" / "findings-new.json").write_text(json.dumps({"findings": [
        {"category": "dependency-vulnerability", "severity": {"canonical": "critical"}, "rule": {"id": "CVE-2017-5941"},
         "message": "An issue was discovered.", "artifact": {"package": package, "installedVersion": "0.1.0", "target": "go.mod"}}]}))
    # the scanners' own list: one row from the finding's fields, the long package name not taken for a key
    text = pc.body("FAILED", [], pc.from_sdt(str(tmp_path)), [], [], "", "main")
    assert f"| Critical | Dependency | {package} 0.1.0: CVE-2017-5941 | `go.mod` |" in text
    # SonarQube files a dependency the code does not reach as a low hotspot
    pc.get_json = lambda url, authorization: {"issues": [], "hotspots": [
        {"ruleKey": "sdt:vulnerable-dependency-unreachable", "vulnerabilityProbability": "LOW", "component": "key:go.mod", "line": 4,
         "message": f"CVE-2017-5941 in {package} 0.1.0 (no fixed version published yet)."}]}
    text = pc.body("FAILED", [], pc.from_sonar(str(tmp_path), "http://sonar", "t", "key", "7"), [], [], "", "main")
    assert f"| Critical | Dependency | {package} 0.1.0: CVE-2017-5941 | `go.mod:4` |" in text
