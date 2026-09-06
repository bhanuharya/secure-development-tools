import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from src.api.database import Project, Scan, engine
from src.api.main import app
from src.config import SCAN_WORK_DIR


@pytest.fixture()
def client(monkeypatch, tmp_path):
    root = tmp_path / "roots"
    root.mkdir()
    monkeypatch.setenv("SCP_LOCAL_SCAN_ROOTS", str(root))
    return TestClient(app), root


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


def test_folder_scan_disabled_without_roots(monkeypatch, tmp_path):
    monkeypatch.delenv("SCP_LOCAL_SCAN_ROOTS", raising=False)
    src = tmp_path / "app"
    src.mkdir()
    (src / "main.py").write_text("import os\n")
    client = TestClient(app)
    resp = client.post("/api/uploads/folder", json={"path": str(src), "scan_type": "sast"})
    assert resp.status_code == 400
    assert "SCP_LOCAL_SCAN_ROOTS" in resp.json()["detail"]


def test_folder_scan_rejects_path_outside_root(client, tmp_path):
    client, root = client
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "a.py").write_text("x\n")
    resp = client.post("/api/uploads/folder", json={"path": str(outside), "scan_type": "sast"})
    assert resp.status_code == 403


def test_folder_scan_success_stages_and_launches(client, monkeypatch):
    client, root = client
    calls = _noop_runner(monkeypatch)
    src = root / "app"
    src.mkdir()
    (src / "main.py").write_text("import pickle\n")
    (src / "requirements.txt").write_text("requests==2.31.0\n")

    resp = client.post(
        "/api/uploads/folder",
        json={"path": str(src), "name": "local app", "scan_type": "sast", "engines": ["bandit"]},
    )
    assert resp.status_code == 200, resp.text
    scan = resp.json()
    assert scan["ref_type"] == "folder"
    assert scan["engines"] == "bandit"
    assert calls == [scan["id"]]

    workdir = SCAN_WORK_DIR / f"p{scan['project_id']}-s{scan['id']}"
    assert (workdir / "main.py").exists()
    assert (workdir / "requirements.txt").exists()
    assert (workdir / ".ready").exists()

    with Session(engine) as session:
        saved = session.get(Scan, scan["id"])
        project = session.get(Project, saved.project_id)
        assert project.workspace == ""
        assert project.name == "local app"


def test_folder_scan_skips_symlinks(client, monkeypatch):
    client, root = client
    _noop_runner(monkeypatch)
    src = root / "app"
    src.mkdir()
    (src / "main.py").write_text("import os\n")
    target = root / "target"
    target.write_text("should not leak\n")
    try:
        (src / "link.py").symlink_to(target)
    except OSError:
        pytest.skip("symlinks not supported on this platform")

    resp = client.post(
        "/api/uploads/folder",
        json={"path": str(src), "scan_type": "sast", "engines": ["bandit"]},
    )
    assert resp.status_code == 200, resp.text
    scan = resp.json()
    workdir = SCAN_WORK_DIR / f"p{scan['project_id']}-s{scan['id']}"
    assert not (workdir / "link.py").exists()
    assert (workdir / "main.py").exists()
