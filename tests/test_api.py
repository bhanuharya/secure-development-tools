import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from src.api.database import Finding, Scan, Target, engine
from src.api.main import app


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def project(client):
    resp = client.post("/api/projects", json={"workspace": "miraworkspace", "repo_slug": "demo", "name": "Demo"})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _make_scan(session, project_id, **kw):
    scan = Scan(project_id=project_id, **kw)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_register_project_and_list(client, project):
    assert project["workspace"] == "miraworkspace"
    listing = client.get("/api/projects").json()
    assert any(p["id"] == project["id"] for p in listing)


def test_duplicate_register_returns_same(client, project):
    resp = client.post("/api/projects", json={"workspace": "miraworkspace", "repo_slug": "demo"})
    assert resp.json()["id"] == project["id"]


def test_dast_scan_requires_preapproved_target(client, project):
    with Session(engine) as session:
        target = Target(
            project_id=project["id"], url="https://staging.example.com",
            is_production=False, pre_approved=False, auth_mode="none",
        )
        session.add(target)
        session.commit()
        target_id = target.id

    # no confirmation -> rejected
    resp = client.post("/api/scans", json={"project_id": project["id"], "scan_type": "dast", "dast_target": target_id})
    assert resp.status_code == 400

    # confirm acknowledgement -> accepted
    resp = client.post("/api/scans", json={
        "project_id": project["id"], "scan_type": "dast", "dast_target": target_id, "dast_confirmed": True,
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["scan_type"] == "dast"


def test_dast_target_locked_to_project(client, project):
    with Session(engine) as session:
        other = Target(
            project_id=project["id"] + 999, url="https://other.example.com",
            is_production=False, pre_approved=True,
        )
        session.add(other)
        session.commit()
        other_id = other.id
    resp = client.post("/api/scans", json={"project_id": project["id"], "scan_type": "dast", "dast_target": other_id, "dast_confirmed": True})
    assert resp.status_code == 404


def test_finding_triage_records_audit(client, project):
    with Session(engine) as session:
        scan = _make_scan(session, project["id"], scan_type="sast", ref_type="branch", ref_name="main")
        finding = Finding(
            scan_id=scan.id, project_id=project["id"], tool="bandit", source_type="sast",
            rule_id="B324", severity="high", file_path="app.py", line_start=6,
            fingerprint="fp-1", status="new",
        )
        session.add(finding)
        session.commit()
        fid = finding.id

    resp = client.patch(f"/api/findings/{fid}", json={"status": "accepted_risk", "reason": "known legacy hash"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "accepted_risk"

    audit = client.get(f"/api/findings/{fid}/audit").json()
    assert audit[0]["from_status"] == "new"
    assert audit[0]["to_status"] == "accepted_risk"
    assert audit[0]["reason"] == "known legacy hash"


def test_finding_invalid_status_rejected(client, project):
    with Session(engine) as session:
        scan = _make_scan(session, project["id"], scan_type="sast", ref_type="branch", ref_name="main")
        finding = Finding(scan_id=scan.id, project_id=project["id"], tool="x", source_type="sast",
                          rule_id="R", severity="low", fingerprint="fp-2")
        session.add(finding)
        session.commit()
        fid = finding.id
    resp = client.patch(f"/api/findings/{fid}", json={"status": "banana"})
    assert resp.status_code == 400


def test_branch_scan_defaults_to_project_branch(client, project):
    # project default is 'main'; creating a scan with empty ref_name defaults to it
    resp = client.post("/api/scans", json={"project_id": project["id"], "scan_type": "sast", "ref_type": "branch"})
    assert resp.status_code == 200
    assert resp.json()["ref_name"] == "main"


def test_uploaded_project_cannot_be_rescanned_as_branch(client):
    # standalone uploaded projects have no Bitbucket repo; a generic branch/PR
    # scan must be rejected so the orchestrator never attempts a Bitbucket clone.
    from src.api.database import Project

    with Session(engine) as session:
        project = Project(name="uploaded", workspace="", repo_slug="up-1", default_branch="upload")
        session.add(project)
        session.commit()
        pid = project.id

    resp = client.post("/api/scans", json={"project_id": pid, "scan_type": "sast", "ref_type": "branch"})
    assert resp.status_code == 400
    resp = client.post("/api/scans", json={"project_id": pid, "scan_type": "sast", "ref_type": "pr", "ref_name": "5"})
    assert resp.status_code == 400