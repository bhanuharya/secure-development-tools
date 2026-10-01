"""Hermetic API tests for the fleet dashboard router (SQLite per tests/conftest)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from src.api.database import Baseline, BaselineItem, FindingObservation, Project, engine
from src.api.main import app

FUTURE = "2099-12-31T23:59:59+00:00"


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def clean_fleet_tables():
    """conftest's clean_db does not know the fleet tables.

    A Baseline left behind by the previous test would classify this test's
    findings as `existing`, so drop the fleet-owned rows too.
    """
    with Session(engine) as session:
        for table in (FindingObservation, BaselineItem, Baseline):
            session.exec(table.__table__.delete())
        session.commit()
    yield


def fingerprint(letter: str) -> str:
    return f"sha256:{letter * 64}"


def sast(rule_id: str, value: str, **extra) -> dict:
    finding = {"schemaVersion": "secure-dev/finding/v1alpha1", "id": f"{rule_id}@{value[-6:]}",
               "fingerprint": {"algorithm": "sdt-v2", "value": value},
               "scanner": {"adapter": "opengrep", "tool": "opengrep"}, "category": "sast",
               "rule": {"id": rule_id, "cwe": ["CWE-78"]}, "severity": {"canonical": "high"},
               "message": "untrusted input reaches a shell",
               "location": {"path": "src/app.py", "startLine": 8, "endLine": 9},
               "baselineState": "new", "redaction": {"applied": True}}
    finding.update(extra)
    return finding


def make_run(tmp_path: Path, run_id: str, findings: list[dict], *, slug: str = "app",
             branch: str = "main", status: str = "passed") -> str:
    """A fleet run directory laid out the way tools/sdt_fleet.py writes one."""
    run = tmp_path / run_id
    repo = run / "repositories" / slug
    repo.mkdir(parents=True)
    (repo / "findings.json").write_text(json.dumps({
        "schemaVersion": "secure-dev/report/v1alpha1", "runId": run_id, "status": status,
        "findings": findings, "policy": {}}))
    (repo / "run-manifest.json").write_text(json.dumps({
        "runId": run_id, "status": status, "exitCode": 0 if status == "passed" else 1,
        "tasks": [{"adapter": "opengrep", "state": "completed"},
                  {"adapter": "trivy-fs", "state": "completed"}]}))
    (run / "fleet-manifest.json").write_text(json.dumps({
        "schemaVersion": "sdt/fleet/v1", "runId": run_id, "workspace": "example",
        "selectedRepositories": 1, "repositoryCount": 1, "repositories": [
            {"repository": slug, "branch": branch, "commit": "abc123", "status": status,
             "findings": len(findings), "runId": run_id}]}))
    return str(run)


def ingest(client, run_dir: str):
    return client.post("/api/fleet/v1/ingest", json={"run_dir": run_dir})


def project_id() -> int:
    with Session(engine) as session:
        return session.exec(select(Project)).one().id


def test_ingest_reports_the_summary_dict(client, tmp_path):
    run = make_run(tmp_path, "run-1", [sast("injection", fingerprint("a"))])
    resp = ingest(client, run)
    assert resp.status_code == 200, resp.text
    summary = resp.json()
    assert (summary["repositories"], summary["scans"], summary["created"]) == (1, 1, 1)

    replay = ingest(client, run)
    assert replay.json()["already_ingested"] == 1
    assert replay.json().get("scans", 0) == 0
    assert replay.json()["created"] == 0
    listed = client.get("/api/fleet/v1/findings").json()
    assert listed["total"] == 1
    item = listed["items"][0]
    assert (item["repository"], item["workspace"], item["branch"], item["tool"]) == (
        "app", "example", "main", "opengrep")
    assert (item["rule_id"], item["severity"], item["file_path"], item["line_start"]) == (
        "injection", "high", "src/app.py", 8)
    assert item["verdict"] == "unreviewed" and item["lifecycle"] == "open"
    assert item["baseline_state"] == "unassessed"


@pytest.mark.parametrize("run_dir", ["/nonexistent/fleet/run-9", ""])
def test_ingest_refuses_a_directory_it_cannot_read(client, run_dir):
    resp = ingest(client, run_dir)
    assert resp.status_code == 400
    assert resp.json()["detail"]


def test_ingest_rejects_a_manifest_that_escapes_the_run_dir(client, tmp_path):
    run = make_run(tmp_path, "run-1", [])
    manifest = json.loads((Path(run) / "fleet-manifest.json").read_text())
    manifest["repositories"][0]["repository"] = "../outside"
    (Path(run) / "fleet-manifest.json").write_text(json.dumps(manifest))
    resp = ingest(client, run)
    assert resp.status_code == 400
    assert "not a repository slug" in resp.json()["detail"]


def test_overview_counts_the_fleet_state(client, tmp_path):
    run = make_run(tmp_path, "run-1", [sast("injection", fingerprint("a")),
                                       sast("xss", fingerprint("b"))])
    assert ingest(client, run).status_code == 200
    overview = client.get("/api/fleet/v1/overview").json()
    assert (overview["projects"], overview["scans"]) == (1, 1)
    assert overview["findings"] == {"open": 2, "resolved": 0}
    assert overview["by_severity"] == {"high": 2}
    assert overview["verdicts"] == {"unreviewed": 2}
    assert overview["baseline_states"] == {"unassessed": 2}
    assert overview["review_backlog"] == 2

    finding = client.get("/api/fleet/v1/findings").json()["items"][0]
    client.post(f"/api/fleet/v1/findings/{finding['id']}/review",
                json={"verdict": "true_positive", "reviewer": "alice", "reason": "queued"})
    overview = client.get("/api/fleet/v1/overview").json()
    assert overview["verdicts"] == {"unreviewed": 1, "true_positive": 1}
    assert overview["review_backlog"] == 1


def test_findings_filters_and_paging(client, tmp_path):
    assert ingest(client, make_run(tmp_path, "run-1", [sast("injection", fingerprint("a")),
                                                       sast("xss", fingerprint("b"))])).status_code == 200
    # run-2 re-observes "a" (so it is the most recently seen) and drops "b",
    # which the completed adapter therefore resolves.
    assert ingest(client, make_run(tmp_path, "run-2", [sast("injection", fingerprint("a"))])).status_code == 200

    all_items = client.get("/api/fleet/v1/findings").json()
    assert all_items["total"] == 2
    assert [item["lifecycle"] for item in all_items["items"]] == ["open", "resolved"]

    assert client.get("/api/fleet/v1/findings?project=app").json()["total"] == 2
    assert client.get("/api/fleet/v1/findings?project=no-such-repo").json()["total"] == 0
    assert client.get("/api/fleet/v1/findings?lifecycle=resolved").json()["total"] == 1
    assert client.get("/api/fleet/v1/findings?severity=high").json()["total"] == 2
    assert client.get("/api/fleet/v1/findings?severity=critical").json()["items"] == []
    assert client.get("/api/fleet/v1/findings?verdict=false_positive").json()["items"] == []
    assert client.get("/api/fleet/v1/findings?branch=feature/none").json()["items"] == []
    assert client.get("/api/fleet/v1/findings?limit=1").json() == {
        "total": 2, "items": all_items["items"][:1]}
    page = client.get("/api/fleet/v1/findings?limit=1&offset=1").json()["items"]
    assert len(page) == 1 and page[0]["id"] == all_items["items"][1]["id"]
    assert client.get("/api/fleet/v1/findings?limit=501").status_code == 422
    assert client.get("/api/fleet/v1/findings?limit=0").status_code == 422


def test_review_records_an_accepted_risk_with_its_deadline(client, tmp_path):
    assert ingest(client, make_run(tmp_path, "run-1", [sast("injection", fingerprint("a"))])).status_code == 200
    fid = client.get("/api/fleet/v1/findings").json()["items"][0]["id"]

    missing_expiry = client.post(f"/api/fleet/v1/findings/{fid}/review",
                                json={"verdict": "accepted_risk", "reviewer": "alice", "reason": "guarded"})
    assert missing_expiry.status_code == 400
    assert "expires_at" in missing_expiry.json()["detail"]

    reviewed = client.post(f"/api/fleet/v1/findings/{fid}/review",
                           json={"verdict": "accepted_risk", "reviewer": "alice", "reason": "guarded",
                                 "expires_at": FUTURE})
    assert reviewed.status_code == 200, reviewed.text
    body = reviewed.json()
    assert body["verdict"] == "accepted_risk" and body["lifecycle"] == "open"
    assert body["repository"] == "app"
    assert body["accepted_until"].startswith("2099-12-31")
    assert client.get("/api/fleet/v1/findings?verdict=accepted_risk").json()["total"] == 1


def test_review_rejects_a_verdict_the_service_does_not_know(client, tmp_path):
    assert ingest(client, make_run(tmp_path, "run-1", [sast("injection", fingerprint("a"))])).status_code == 200
    fid = client.get("/api/fleet/v1/findings").json()["items"][0]["id"]
    resp = client.post(f"/api/fleet/v1/findings/{fid}/review",
                       json={"verdict": "unknown_verdict", "reviewer": "alice", "reason": "real"})
    assert resp.status_code == 400
    assert "invalid verdict" in resp.json()["detail"]
    missing = client.post("/api/fleet/v1/findings/999999/review", json={"verdict": "true_positive"})
    assert missing.status_code == 400


def test_baseline_approval_classifies_the_next_ingest(client, tmp_path):
    assert ingest(client, make_run(tmp_path, "run-1", [sast("injection", fingerprint("a")),
                                                       sast("xss", fingerprint("b"))])).status_code == 200
    approved = client.post("/api/fleet/v1/baselines/approve",
                           json={"project_id": project_id(), "branch": "main", "approved_by": "alice",
                                 "reason": "pilot baseline"})
    assert approved.status_code == 200, approved.text
    baseline = approved.json()
    assert (baseline["approved_by"], baseline["branch"], baseline["finding_count"]) == ("alice", "main", 2)
    assert baseline["created_at"]

    assert ingest(client, make_run(tmp_path, "run-2", [sast("xss", fingerprint("b")),
                                                       sast("sqli", fingerprint("d"))])).status_code == 200
    existing = client.get("/api/fleet/v1/findings?baseline_state=existing").json()
    assert [item["rule_id"] for item in existing["items"]] == ["xss"]
    assert client.get("/api/fleet/v1/findings?baseline_state=new").json()["total"] == 1
    assert client.get("/api/fleet/v1/findings?baseline_state=unassessed").json()["total"] == 1


def test_the_legacy_status_endpoints_cannot_bypass_the_review_service(client, tmp_path):
    """P2-9: one review service. A bare status write would skip reviewer, reason and expiry."""
    ingest(client, make_run(tmp_path, "run-legacy", [sast("injection", fingerprint("a"))]))
    finding_id = client.get("/api/fleet/v1/findings").json()["items"][0]["id"]

    patched = client.patch(f"/api/findings/{finding_id}", json={"status": "accepted_risk", "reason": "trust me"})
    assert patched.status_code == 409
    assert patched.json()["detail"]["finding_ids"] == [finding_id]
    bulk = client.post("/api/findings/bulk-status", json={"ids": [finding_id], "status": "false_positive"})
    assert bulk.status_code == 409

    item = client.get("/api/fleet/v1/findings").json()["items"][0]
    assert (item["verdict"], item["accepted_until"]) == ("unreviewed", None)
    reviewed = client.post(f"/api/fleet/v1/findings/{finding_id}/review",
                           json={"verdict": "false_positive", "reviewer": "alice", "reason": "sanitised upstream"})
    assert reviewed.status_code == 200
