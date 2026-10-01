import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from src.api.database import Finding, FindingAuditEvent, engine
from src.api.main import app


@pytest.fixture()
def client():
    return TestClient(app)


def _make_finding(session, project_id, scan_id, **kw):
    defaults = dict(
        project_id=project_id,
        scan_id=scan_id,
        tool="bandit",
        source_type="sast",
        rule_id="B101",
        severity="high",
        file_path="app.py",
        line_start=1,
        snippet="assert True",
        fingerprint=f"fp-{kw.get('rule_id', 'B101')}-{len(str(kw))}",
    )
    defaults.update(kw)
    f = Finding(**defaults)
    session.add(f)
    session.commit()
    session.refresh(f)
    return f


@pytest.fixture()
def seeded(client):
    with Session(engine) as session:
        from src.api.database import Project, Scan

        project = Project(name="t", workspace="w", repo_slug="r", default_branch="main")
        session.add(project)
        session.commit()
        session.refresh(project)
        scan = Scan(project_id=project.id, scan_type="sast", ref_type="branch", ref_name="main")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        findings = [
            _make_finding(session, project.id, scan.id, severity="critical", rule_id="B1"),
            _make_finding(session, project.id, scan.id, severity="high", rule_id="B2"),
            _make_finding(session, project.id, scan.id, severity="medium", rule_id="B3"),
            _make_finding(session, project.id, scan.id, severity="low", rule_id="B4"),
        ]
        finding_ids = [f.id for f in findings]
    return {"project": project, "scan": scan, "findings": findings, "finding_ids": finding_ids}


def test_findings_pagination_and_total_count(client, seeded):
    resp = client.get("/api/findings?limit=2&offset=0")
    assert resp.status_code == 200
    assert resp.headers["X-Total-Count"] == "4"
    assert len(resp.json()) == 2

    page2 = client.get("/api/findings?limit=2&offset=2")
    assert page2.headers["X-Total-Count"] == "4"
    assert len(page2.json()) == 2
    ids_page1 = {f["id"] for f in resp.json()}
    ids_page2 = {f["id"] for f in page2.json()}
    assert not ids_page1 & ids_page2


def test_findings_severity_gte_threshold(client, seeded):
    resp = client.get("/api/findings?severity_gte=high")
    severities = {f["severity"] for f in resp.json()}
    assert severities == {"critical", "high"}

    resp = client.get("/api/findings?severity_gte=critical")
    assert {f["severity"] for f in resp.json()} == {"critical"}


def test_findings_severity_gte_invalid(client, seeded):
    resp = client.get("/api/findings?severity_gte=bogus")
    assert resp.status_code == 400


def test_bulk_status_updates_and_audits(client, seeded):
    ids = seeded["finding_ids"][:3]
    resp = client.post("/api/findings/bulk-status", json={"ids": ids, "status": "triaged", "reason": "bot triage"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["changed"] == 3
    assert data["missing"] == []

    with Session(engine) as session:
        for fid in ids:
            f = session.get(Finding, fid)
            assert f.status == "triaged"
            assert f.triage_reason == "bot triage"
        from sqlalchemy import select as sa_select

        audits = session.exec(
            sa_select(FindingAuditEvent).where(
                FindingAuditEvent.finding_id.in_(ids),
                FindingAuditEvent.to_status == "triaged",
                FindingAuditEvent.reason == "bot triage",
            )
        ).all()
        assert len(audits) == 3


def test_bulk_status_missing_ids_reported(client, seeded):
    good = seeded["finding_ids"][0]
    resp = client.post("/api/findings/bulk-status", json={"ids": [good, 999999], "status": "fixed"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["changed"] == 1
    assert data["missing"] == [999999]


def test_bulk_status_invalid_status_rejected(client, seeded):
    resp = client.post("/api/findings/bulk-status", json={"ids": [1], "status": "nope"})
    assert resp.status_code == 400


def test_scans_pagination_total_count(client, seeded):
    resp = client.get("/api/scans?limit=10")
    assert resp.status_code == 200
    assert resp.headers["X-Total-Count"] == "1"
