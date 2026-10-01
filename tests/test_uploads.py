import io
import json
import socket
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from src.api.database import Project, Scan, Target, engine
from src.api.main import app
from src.config import SCAN_WORK_DIR
from src.util.secretbox import decrypt_secret


@pytest.fixture()
def client():
    return TestClient(app)


def _make_zip(*members: tuple[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _noop_runner(monkeypatch):
    calls = []

    class FakeRunner:
        def __init__(self):
            pass

        def run_scan(self, scan_id):
            calls.append(scan_id)

    monkeypatch.setattr("src.api.routers.uploads.ScanRunner", FakeRunner)
    from src.scanners.executor import SyncScanExecutor

    monkeypatch.setattr("src.api.routers.uploads.get_executor", lambda: SyncScanExecutor())
    return calls


def _allow_test_dast_hosts(monkeypatch):
    monkeypatch.setenv("SCP_DAST_ALLOWED_HOSTS", "staging.example.com,*.internal.corp")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )


def _dast_auth(monkeypatch):
    """Enable control-plane auth for DAST endpoints (required)."""
    monkeypatch.setenv("SCP_API_TOKEN", "test-dast-token")
    return {"Authorization": "Bearer test-dast-token"}


def test_upload_repo_scan_rejects_non_zip(client):
    resp = client.post("/api/uploads/scan", files={"file": ("repo.txt", b"not a zip", "text/plain")})
    assert resp.status_code == 400
    assert "zip" in resp.json()["detail"]


def test_upload_repo_scan_rejects_invalid_zip(client):
    resp = client.post(
        "/api/uploads/scan",
        files={"file": ("repo.zip", b"PK\x03\x04 not really a zip", "application/zip")},
    )
    assert resp.status_code == 400
    assert "zip" in resp.json()["detail"]


def test_upload_repo_scan_rejects_bad_scan_type(client):
    resp = client.post(
        "/api/uploads/scan",
        files={"file": ("repo.zip", _make_zip(("app.py", "x = 1")), "application/zip")},
        data={"scan_type": "banana"},
    )
    assert resp.status_code == 400


def test_upload_repo_scan_rejects_zap_engine(client):
    resp = client.post(
        "/api/uploads/scan",
        files={"file": ("repo.zip", _make_zip(("app.py", "x = 1")), "application/zip")},
        data={"scan_type": "sast", "engines": "zap"},
    )
    assert resp.status_code == 400


def test_upload_repo_scan_creates_standalone_scan(client, monkeypatch):
    calls = _noop_runner(monkeypatch)
    zip_bytes = _make_zip(
        ("app.py", "import pickle\n"),
        ("requirements.txt", "requests==2.31.0\n"),
    )

    resp = client.post(
        "/api/uploads/scan",
        files={"file": ("vulnapp.zip", zip_bytes, "application/zip")},
        data={"name": "Manually Uploaded", "scan_type": "sca", "language_override": "python"},
    )
    assert resp.status_code == 200, resp.text
    scan = resp.json()
    assert scan["scan_type"] == "sca"
    assert scan["ref_type"] == "upload"
    assert scan["ref_name"] == "Manually Uploaded"
    assert scan["engines"] == "trivy,osv-scanner"  # defaulted from scan_type
    assert calls == [scan["id"]]

    with Session(engine) as session:
        saved = session.get(Scan, scan["id"])
        project = session.get(Project, saved.project_id)
        assert project is not None
        assert project.workspace == ""  # standalone project
        assert project.name == "Manually Uploaded"

    workdir = SCAN_WORK_DIR / f"p{scan['project_id']}-s{scan['id']}"
    assert (workdir / "app.py").exists()
    assert (workdir / "requirements.txt").exists()
    assert (workdir / ".ready").exists()


def test_upload_queue_capacity_returns_503_without_orphans(client, monkeypatch):
    from src.scanners.executor import ScanCapacityError

    def full(_scan_id):
        raise ScanCapacityError("scan executor capacity is full")

    monkeypatch.setattr("src.api.routers.uploads._launch", full)
    resp = client.post(
        "/api/uploads/scan",
        files={"file": ("queue-full.zip", _make_zip(("app.py", "x = 1")), "application/zip")},
        data={"scan_type": "sast"},
    )
    assert resp.status_code == 503
    assert resp.json()["detail"] == "scan queue is full"
    with Session(engine) as session:
        assert session.exec(select(Project).where(Project.name == "queue-full")).first() is None
        assert session.exec(select(Scan)).first() is None


def test_upload_repo_scan_rejects_traversal(client, monkeypatch):
    _noop_runner(monkeypatch)
    zip_bytes = _make_zip(("app.py", "x = 1\n"), ("../evil.txt", "zip-slip"))
    resp = client.post(
        "/api/uploads/scan",
        files={"file": ("vulnapp.zip", zip_bytes, "application/zip")},
        data={"scan_type": "sast"},
    )
    assert resp.status_code == 400


def test_upload_repo_scan_strips_wrapper_dir(client, monkeypatch):
    _noop_runner(monkeypatch)
    zip_bytes = _make_zip(
        ("repo-main/app.py", "import os\n"),
        ("repo-main/README.md", "hello\n"),
    )
    resp = client.post(
        "/api/uploads/scan",
        files={"file": ("repo.zip", zip_bytes, "application/zip")},
        data={"scan_type": "sast"},
    )
    assert resp.status_code == 200, resp.text
    scan = resp.json()
    workdir = SCAN_WORK_DIR / f"p{scan['project_id']}-s{scan['id']}"
    assert (workdir / "app.py").exists()
    assert (workdir / "README.md").exists()
    assert not (workdir / "repo-main").exists()


def test_upload_repo_scan_preset_full(client, monkeypatch):
    _noop_runner(monkeypatch)
    zip_bytes = _make_zip(("app.py", "import os\n"))
    resp = client.post(
        "/api/uploads/scan",
        files={"file": ("repo.zip", zip_bytes, "application/zip")},
        data={"preset": "full"},
    )
    assert resp.status_code == 200, resp.text
    scan = resp.json()
    assert scan["scan_type"] == "full"
    assert scan["engines"] == "bandit,opengrep,trivy,gitleaks,checkov,osv-scanner"


def test_direct_dast_register_does_not_launch(client, monkeypatch):
    """Registration alone must never create or start a scan."""
    _allow_test_dast_hosts(monkeypatch)
    headers = _dast_auth(monkeypatch)
    calls = _noop_runner(monkeypatch)
    resp = client.post("/api/uploads/dast", json={"url": "https://staging.example.com"}, headers=headers)
    assert resp.status_code == 200, resp.text
    target = resp.json()
    assert "next_step" in target
    assert calls == []
    with Session(engine) as session:
        assert session.exec(select(Scan)).all() == []


def test_direct_dast_register_approve_scan_flow(client, monkeypatch):
    _allow_test_dast_hosts(monkeypatch)
    headers = _dast_auth(monkeypatch)
    calls = _noop_runner(monkeypatch)
    resp = client.post("/api/uploads/dast", json={
        "name": "Staging portal",
        "url": "https://staging.example.com",
        "auth_mode": "form",
        "login_url": "https://staging.example.com/login",
        "username_field": "username",
        "password_field": "password",
        "auth_username": "alice",
        "auth_password": "s3cr3t",
    }, headers=headers)
    assert resp.status_code == 200, resp.text
    target = resp.json()

    # scan before approval -> refused
    resp = client.post("/api/scans", json={
        "project_id": target["project_id"], "scan_type": "dast", "dast_target": target["id"],
    }, headers=headers)
    assert resp.status_code == 400

    resp = client.post(
        f"/api/targets/{target['id']}/approve",
        json={"reason": "test", "production_ack": True},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    resp = client.post("/api/scans", json={
        "project_id": target["project_id"], "scan_type": "dast", "dast_target": target["id"],
    }, headers=headers)
    assert resp.status_code == 200, resp.text
    scan = resp.json()
    assert scan["scan_type"] == "dast"
    assert scan["engines"] == "zap"

    with Session(engine) as session:
        saved = session.get(Scan, scan["id"])
        assert saved is not None
        row = session.get(Target, int(saved.dast_target))
        assert row is not None
        assert row.project_id == saved.project_id
        assert row.auth_mode == "form"
        # credentials are encrypted at rest, never stored as plaintext
        assert row.auth_password != "s3cr3t"
        assert row.auth_password.startswith("enc:v1:")
        assert decrypt_secret(row.auth_password) == "s3cr3t"
        project = session.get(Project, saved.project_id)
        assert project.workspace == ""


def test_dast_password_requires_secret_key(client, monkeypatch):
    _allow_test_dast_hosts(monkeypatch)
    headers = _dast_auth(monkeypatch)
    monkeypatch.delenv("SCP_SECRET_KEY", raising=False)
    resp = client.post("/api/uploads/dast", json={
        "url": "https://staging.example.com", "auth_mode": "form",
        "login_url": "https://staging.example.com/login", "auth_password": "s3cr3t",
    }, headers=headers)
    assert resp.status_code == 400
    assert "SCP_SECRET_KEY" in resp.json()["detail"]


def test_dast_url_allowlist(client, monkeypatch):
    monkeypatch.setenv("SCP_DAST_ALLOWED_HOSTS", "staging.example.com,*.internal.corp")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    headers = _dast_auth(monkeypatch)
    ok = client.post("/api/uploads/dast", json={"url": "https://app.internal.corp/login?next=/"}, headers=headers)
    assert ok.status_code == 200, ok.text
    exact = client.post("/api/uploads/dast", json={"url": "https://staging.example.com"}, headers=headers)
    assert exact.status_code == 200
    denied = client.post("/api/uploads/dast", json={"url": "https://payments.example.org"}, headers=headers)
    assert denied.status_code == 400
    assert "SCP_DAST_ALLOWED_HOSTS" in denied.json()["detail"]
    # wildcard covers subdomains but not the bare apex or deeper tricks
    apex = client.post("/api/uploads/dast", json={"url": "https://internal.corp"}, headers=headers)
    assert apex.status_code == 400
    scheme = client.post("/api/uploads/dast", json={"url": "ftp://staging.example.com"}, headers=headers)
    assert scheme.status_code == 400


def test_dast_upload_scan_runs_without_staged_repo(client, monkeypatch):
    """DAST scans use ref_type='upload' but must NOT require a staged ZIP (.ready)."""
    from src.scanners.orchestrator import ScanRunner

    _allow_test_dast_hosts(monkeypatch)
    _dast_auth(monkeypatch)

    class FakeZap:
        def available(self):
            return True

        def run_dast(self, **kwargs):
            return []

    monkeypatch.setattr("src.scanners.orchestrator.ZapClient", FakeZap)

    with Session(engine) as session:
        project = Project(name="dast", workspace="", repo_slug="d1", default_branch="upload")
        session.add(project)
        session.commit()
        session.refresh(project)
        target = Target(project_id=project.id, url="https://staging.example.com", pre_approved=True, auth_mode="none")
        session.add(target)
        session.commit()
        session.refresh(target)
        from src.api.routers.scans import _target_digest

        scan = Scan(
            project_id=project.id,
            scan_type="dast",
            engines="zap",
            ref_type="upload",
            ref_name="dast",
            dast_target=str(target.id),
            dast_target_digest=_target_digest(target),
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id

    ScanRunner().run_scan(scan_id)

    with Session(engine) as session:
        s = session.get(Scan, scan_id)
        assert s.status == "succeeded"
        assert json.loads(s.engine_statuses)["zap"]["state"] == "done"
