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

    def comment_text(self, method):
        return json.loads(self.sent(method)[-1][3])["content"]["raw"]


def finding(category, level, rule, path, line, state="new"):
    return {"category": category, "severity": {"canonical": level}, "rule": {"id": rule},
            "location": {"path": path, "startLine": line}, "baselineState": state}


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
    upload = [r for r in fake.sent("POST") if r[1].endswith("/downloads")][0]
    assert b"PK-docx-bytes" in upload[3] and b'filename="SAST Report - shop - PR 42.docx"' in upload[3]
    assert all(r[2] == f"Bearer {TOKEN}" for r in fake.requests)


def test_failed_gate_says_failed_with_conditions(out):
    (out / "quality-gate.txt").write_text("ERROR\n   new_vulnerabilities ERROR 1\n")
    fake = FakeBitbucket()
    assert run(fake, out).returncode == 0
    text = fake.comment_text("POST")
    assert text.startswith("### SDT security scan: FAILED")
    assert "new_vulnerabilities ERROR 1" in text


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
    assert not [r for r in fake.sent("POST") if r[1].endswith("/downloads")]
    assert "https://ci.example/job/x/9/artifact/out/SAST%20Report%20-%20shop.docx" in fake.comment_text("POST")


def test_no_new_findings_and_basic_auth_with_a_user(out):
    (out / "sdt" / "findings-new.json").write_text(json.dumps({"findings": []}))
    fake = FakeBitbucket()
    assert run(fake, out, BITBUCKET_USER="bot@example.com", SDT_PR_REPORT_UPLOAD="0").returncode == 0
    assert "adds no new security findings" in fake.comment_text("POST")
    assert all(r[2].startswith("Basic ") for r in fake.requests)
    assert not [r for r in fake.sent("POST") if r[1].endswith("/downloads")]


def test_refused_comment_fails_without_printing_the_token(out):
    fake = FakeBitbucket(fail_comment=True)
    done = run(fake, out)
    assert done.returncode == 1
    assert "403" in done.stdout and "no pull request write scope" in done.stdout
