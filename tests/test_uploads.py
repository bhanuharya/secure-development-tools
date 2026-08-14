import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from src.api.database import Project, Scan, Target, engine
from src.api.main import app
from src.config import SCAN_WORK_DIR


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
    assert scan["engines"] == "trivy"  # defaulted from scan_type
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
    assert scan["engines"] == "bandit,opengrep,trivy,gitleaks"


def test_direct_dast_requires_confirmation(client):
    resp = client.post("/api/uploads/dast", json={"url": "https://staging.example.com"})
    assert resp.status_code == 400


def test_direct_dast_creates_scan_and_target(client, monkeypatch):
    calls = _noop_runner(monkeypatch)
    resp = client.post("/api/uploads/dast", json={
        "name": "Staging portal",
        "url": "https://staging.example.com",
        "dast_confirmed": True,
        "auth_mode": "form",
        "login_url": "https://staging.example.com/login",
        "username_field": "username",
        "password_field": "password",
        "auth_username": "alice",
        "auth_password": "s3cr3t",
    })
    assert resp.status_code == 200, resp.text
    scan = resp.json()
    assert scan["scan_type"] == "dast"
    assert scan["ref_type"] == "upload"
    assert scan["engines"] == "zap"
    assert calls == [scan["id"]]

    with Session(engine) as session:
        saved = session.get(Scan, scan["id"])
        target = session.get(Target, int(saved.dast_target))
        assert target is not None
        assert target.project_id == saved.project_id
        assert target.auth_mode == "form"
        assert target.auth_password == "s3cr3t"
        project = session.get(Project, saved.project_id)
        assert project.workspace == ""


def test_dast_upload_scan_runs_without_staged_repo(client, monkeypatch):
    """DAST scans use ref_type='upload' but must NOT require a staged ZIP (.ready)."""
    from src.scanners.orchestrator import ScanRunner

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
        scan = Scan(
            project_id=project.id,
            scan_type="dast",
            engines="zap",
            ref_type="upload",
            ref_name="dast",
            dast_target=str(target.id),
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
