"""Hermetic tests for the fleet baseline/review model and service (SQLite file per test)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import func, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, SQLModel, create_engine, select

from src.api import database, fleet_store
from src.api.database import (
    Baseline,
    BaselineItem,
    Finding,
    FindingAuditEvent,
    FindingObservation,
    Project,
    Scan,
)


@pytest.fixture
def session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'fleet.db'}")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as db:
        yield db


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


def make_run(tmp_path: Path, *, run_id: str, findings: list[dict], status: str = "passed",
             adapters: dict[str, str] | None = None, slug: str = "app",
             branch: str = "main", generated_at: str = "", completed_at: str = "",
             config_digest: str = "", policy_digest: str = "") -> Path:
    """A fleet run directory laid out the way tools/sdt_fleet.py writes one.

    `generated_at` is the canonical report's own stamp, `completed_at` the fleet
    record's, and the digests the run manifest's: what tells ingest when this
    scan ran and which rules and policy produced it.
    """
    run = tmp_path / run_id
    repo = run / "repositories" / slug
    repo.mkdir(parents=True)
    (repo / "findings.json").write_text(json.dumps({
        "schemaVersion": "secure-dev/report/v1alpha1", "runId": run_id, "status": status,
        "generatedAt": generated_at, "findings": findings, "policy": {}}))
    tasks = [{"adapter": adapter, "state": state}
             for adapter, state in (adapters or {"opengrep": "completed"}).items()]
    (repo / "run-manifest.json").write_text(json.dumps({"runId": run_id, "status": status,
                                                        "configDigest": config_digest,
                                                        "policyDigest": policy_digest,
                                                        "tasks": tasks,
                                                        "exitCode": 0 if status == "passed" else 1}))
    record = {"repository": slug, "branch": branch, "commit": "abc123", "status": status,
              "findings": len(findings), "runId": run_id}
    if completed_at:
        record["completedAt"] = completed_at
    (run / "fleet-manifest.json").write_text(json.dumps({
        "schemaVersion": "sdt/fleet/v1", "runId": run_id, "workspace": "example",
        "selectedRepositories": 1, "repositoryCount": 1, "repositories": [record]}))
    return run


def counts(session: Session, model) -> int:
    return session.exec(select(func.count()).select_from(model)).one()


def rows_by_fingerprint(session: Session) -> dict[str, Finding]:
    return {finding.fingerprint[-1]: finding for finding in session.exec(select(Finding)).all()}


# The schema a deployment ran before the fleet work: every table `create_all`
# would have built, and none of the columns or indexes ingest has since needed.
# `findingobservation` is the pre-P2 shape (which scan saw which fingerprint, and
# nothing about what it saw), so the migration test proves the evidence columns
# land on a live deployment too.
_PRE_FLEET_TABLES = (
    """CREATE TABLE project (id INTEGER PRIMARY KEY, name VARCHAR, workspace VARCHAR, repo_slug VARCHAR,
       default_branch VARCHAR, languages VARCHAR, created_at DATETIME)""",
    """CREATE TABLE scan (id INTEGER PRIMARY KEY, project_id INTEGER, scan_type VARCHAR, engines VARCHAR,
       ref_type VARCHAR, ref_name VARCHAR, commit_sha VARCHAR, language_override VARCHAR,
       dast_target VARCHAR, status VARCHAR, engine_statuses VARCHAR, summary VARCHAR, progress_note VARCHAR,
       error VARCHAR, created_at DATETIME, started_at DATETIME, finished_at DATETIME)""",
    """CREATE TABLE finding (id INTEGER PRIMARY KEY, scan_id INTEGER, project_id INTEGER, tool VARCHAR,
       source_type VARCHAR, rule_id VARCHAR, severity VARCHAR, cwe VARCHAR, file_path VARCHAR,
       line_start INTEGER, line_end INTEGER, snippet VARCHAR, description VARCHAR, remediation VARCHAR,
       fingerprint VARCHAR, status VARCHAR, triage_reason VARCHAR, in_pr_diff BOOLEAN, first_seen DATETIME,
       last_seen DATETIME)""",
    """CREATE TABLE findingauditevent (id INTEGER PRIMARY KEY, finding_id INTEGER, from_status VARCHAR,
       to_status VARCHAR, reason VARCHAR, created_at DATETIME)""",
    "CREATE TABLE findingobservation (id INTEGER PRIMARY KEY, scan_id INTEGER, finding_id INTEGER)",
)

_PRE_FLEET_ROWS = (
    "INSERT INTO project (id, name, workspace, repo_slug, default_branch, languages, created_at) "
    "VALUES (1, 'app', 'example', 'app', 'main', 'python', '2026-09-19 09:00:00')",
    "INSERT INTO scan (id, project_id, scan_type, engines, ref_type, ref_name, commit_sha, status, "
    "engine_statuses, summary, created_at) VALUES (1, 1, 'sast', 'opengrep', 'branch', 'main', 'abc123', "
    "'succeeded', '{}', '{}', '2026-09-19 10:00:00')",
    "INSERT INTO scan (id, project_id, scan_type, engines, ref_type, ref_name, commit_sha, status, "
    "engine_statuses, summary, created_at) VALUES (2, 1, 'sast', 'opengrep', 'branch', 'main', 'def456', "
    "'succeeded', '{}', '{}', '2026-09-20 10:00:00')",
    # The same fingerprint seen by two scans: pre-fleet dashboard rows are per-scan
    # and deliberately repeat.
    "INSERT INTO finding (id, scan_id, project_id, tool, source_type, rule_id, severity, fingerprint, "
    "status, in_pr_diff, first_seen, last_seen) VALUES (1, 1, 1, 'opengrep', 'sast', 'injection', 'high', "
    "'{fp}', 'new', 0, '2026-09-19 10:00:00', '2026-09-19 10:00:00')",
    "INSERT INTO finding (id, scan_id, project_id, tool, source_type, rule_id, severity, fingerprint, "
    "status, in_pr_diff, first_seen, last_seen) VALUES (2, 2, 1, 'opengrep', 'sast', 'injection', 'high', "
    "'{fp}', 'triaged', 0, '2026-09-19 10:00:00', '2026-09-20 10:00:00')",
)


def legacy_deployment(tmp_path: Path) -> tuple[Path, object]:
    """A file database in the shape a deployment was left in, plus its caller's engine."""
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        for statement in _PRE_FLEET_TABLES:
            conn.execute(statement)
        for statement in _PRE_FLEET_ROWS:
            conn.execute(statement.replace("{fp}", fingerprint("a")))
    return path, create_engine(f"sqlite:///{path}")


def _columns(engine, table: str) -> set[str]:
    return {column["name"] for column in inspect(engine).get_columns(table)}


def _indexes(engine, *tables: str) -> set[str]:
    return {index["name"] for table in tables for index in inspect(engine).get_indexes(table)}


def test_ingest_maps_the_fleet_record_onto_a_scan(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    summary = fleet_store.ingest_run(run, session)
    assert (summary["repositories"], summary["scans"], summary["created"]) == (1, 1, 1)
    scan = session.exec(select(Scan)).one()
    assert (scan.ref_name, scan.commit_sha, scan.status, scan.run_id) == ("main", "abc123", "succeeded", "run-1")
    assert json.loads(scan.engine_statuses) == {"opengrep": "completed"}
    assert json.loads(scan.summary) == {"total": 1, "high": 1}
    # A run manifest that names no digests attests to none: '' is comparable only with ''.
    assert (scan.config_digest, scan.policy_digest) == ("", "")
    finding = session.exec(select(Finding)).one()
    assert (finding.branch, finding.tool, finding.source_type, finding.status) == ("main", "opengrep", "sast", "new")
    assert (finding.fingerprint_version, finding.baseline_state, finding.severity) == ("sdt-v2", "unassessed", "high")
    assert (finding.cwe, finding.file_path, finding.line_start, finding.line_end) == (
        "CWE-78", "src/app.py", 8, 9)
    assert json.loads(finding.evidence)["scanner"]["tool"] == "opengrep"


def test_policy_failed_is_a_complete_scan_and_secrets_are_a_different_source(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", status="policy_failed", findings=[
        {**sast("hardcoded-key", fingerprint("a")), "scanner": {"adapter": "gitleaks", "tool": "gitleaks"},
         "category": "secret"}])
    fleet_store.ingest_run(run, session)
    assert session.exec(select(Scan)).one().status == "succeeded"
    assert session.exec(select(Finding)).one().source_type == "secrets"


def test_replaying_a_run_changes_nothing(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    first = fleet_store.ingest_run(run, session)
    assert (first["scans"], first["already_ingested"]) == (1, 0)
    second = fleet_store.ingest_run(run, session)
    assert second["already_ingested"] == 1 and second.get("scans", 0) == 0
    assert (second["created"], second["resolved"], second["observed"]) == (0, 0, 0)
    assert counts(session, Scan) == 1 and counts(session, Finding) == 1
    assert counts(session, FindingObservation) == 1
    assert counts(session, FindingAuditEvent) == 0


def test_baseline_classifies_the_next_run_and_a_disappeared_finding_resolves(session, tmp_path):
    run1 = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a")),
                                                        sast("xss", fingerprint("b"))])
    fleet_store.ingest_run(run1, session)
    project = session.exec(select(Project)).one()
    baseline = fleet_store.approve_baseline(session, project.id, "main", "alice", "pilot baseline")
    assert (baseline.finding_count, baseline.approved_by) == (2, "alice")
    assert counts(session, BaselineItem) == 2

    run2 = make_run(tmp_path, run_id="run-2", findings=[sast("xss", fingerprint("b")),
                                                        sast("sqli", fingerprint("c"))])
    summary = fleet_store.ingest_run(run2, session)
    assert (summary["created"], summary["observed"], summary["resolved"]) == (1, 1, 1)

    findings = rows_by_fingerprint(session)
    # Created before any baseline existed, so no claim was made about them.
    # b is a member of the approved baseline, so the re-observation classifies it existing;
    # a predates the baseline and is not a member, so it reads new to that baseline.
    assert (findings["a"].baseline_state, findings["b"].baseline_state) == ("unassessed", "existing")
    # Created after the approval, and absent from it.
    assert findings["c"].baseline_state == "new"
    assert (findings["a"].lifecycle, findings["a"].status) == ("resolved", "fixed")
    assert (findings["b"].lifecycle, findings["b"].status) == ("open", "new")
    resolution = session.exec(select(FindingAuditEvent)
                              .where(FindingAuditEvent.finding_id == findings["a"].id)).one()
    assert (resolution.from_status, resolution.to_status, resolution.reviewer) == ("new", "fixed", "fleet-ingest")
    assert "run run-2" in resolution.reason


def test_a_baseline_member_stays_existing_after_a_reobservation(session, tmp_path):
    run1 = make_run(tmp_path, run_id="run-1", findings=[sast("xss", fingerprint("b"))])
    fleet_store.ingest_run(run1, session)
    project = session.exec(select(Project)).one()
    fleet_store.approve_baseline(session, project.id, "main", "alice", "pilot baseline")
    run2 = make_run(tmp_path, run_id="run-2", findings=[sast("xss", fingerprint("b"))])
    fleet_store.ingest_run(run2, session)
    finding = session.exec(select(Finding)).one()
    assert (finding.baseline_state, finding.lifecycle) == ("existing", "open")
    assert counts(session, FindingObservation) == 2
    assert session.exec(select(Baseline)).one().finding_count == 1


def test_the_newest_baseline_is_the_active_one(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run, session)
    project = session.exec(select(Project)).one()
    first = fleet_store.approve_baseline(session, project.id, "main", "alice", "empty pilot")
    run2 = make_run(tmp_path, run_id="run-2", findings=[sast("xss", fingerprint("b"))])
    fleet_store.ingest_run(run2, session)
    second = fleet_store.approve_baseline(session, project.id, "main", "bob", "after the second run")
    assert fleet_store.active_baseline(session, project.id, "main").id == second.id
    run3 = make_run(tmp_path, run_id="run-3", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run3, session)
    findings = rows_by_fingerprint(session)
    # "a" predates the active baseline, so it is new to it; "c" was never seen.
    assert findings["a"].baseline_state == "new"
    # "a" was resolved by run2 (its adapter completed without seeing it), so the
    # snapshot the second approval freezes contains only the open finding "b".
    assert first.finding_count == 1 and second.finding_count == 1


@pytest.mark.parametrize("status", ["failed", "inconclusive"])
def test_an_incomplete_scan_resolves_nothing(session, tmp_path, status):
    run1 = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run1, session)
    run2 = make_run(tmp_path, run_id="run-2", findings=[], status=status)
    summary = fleet_store.ingest_run(run2, session)
    assert summary.get("resolved", 0) == 0
    finding = session.exec(select(Finding)).one()
    assert (finding.lifecycle, finding.status) == ("open", "new")
    assert session.exec(select(Scan).where(Scan.run_id == "run-2")).one().status == status


@pytest.mark.parametrize("status", ["inconclusive", "execution_failed"])
def test_an_unfinished_adapter_resolves_nothing(session, tmp_path, status):
    """A completed *scan* is not enough: the adapter that stopped reporting must itself have finished."""
    run1 = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run1, session)
    run2 = make_run(tmp_path, run_id="run-2", findings=[], status="passed",
                    adapters={"opengrep": "timeout", "gitleaks": "completed"})
    summary = fleet_store.ingest_run(run2, session)
    assert summary.get("resolved", 0) == 0
    assert session.exec(select(Finding)).one().lifecycle == "open"


def test_the_scan_row_keeps_the_time_and_digests_the_artifacts_attest_to(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))],
                   generated_at="2026-09-20T10:00:00Z", config_digest="cfg-A", policy_digest="pol-A")
    fleet_store.ingest_run(run, session)
    scan = session.exec(select(Scan)).one()
    # SQLite hands back a naive UTC moment, like every other column on the row.
    assert fleet_store._utc(scan.scan_time) == datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)
    assert (scan.config_digest, scan.policy_digest) == ("cfg-A", "pol-A")


def test_scan_time_falls_back_to_the_record_and_then_the_clock(session, tmp_path):
    """An older report still says when it ran, even without its own generatedAt."""
    stamped = make_run(tmp_path, run_id="run-1", findings=[], completed_at="2026-09-19T08:30:00Z")
    fleet_store.ingest_run(stamped, session)
    report = json.loads((stamped / "repositories" / "app" / "findings.json").read_text())
    assert not report["generatedAt"]
    assert fleet_store._utc(session.exec(select(Scan)).one().scan_time) == datetime(2026, 9, 19, 8, 30, tzinfo=timezone.utc)

    undated = make_run(tmp_path, run_id="run-2", findings=[])
    fleet_store.ingest_run(undated, session)
    newest = session.exec(select(Scan).where(Scan.run_id == "run-2")).one()
    assert datetime.now(timezone.utc) - fleet_store._utc(newest.scan_time) < timedelta(minutes=5)
    # The undated run is later than the dated one, so it may still resolve it.
    assert newest.scan_time > session.exec(select(Scan).where(Scan.run_id == "run-1")).one().scan_time


def test_an_imported_older_scan_records_but_never_resolves(session, tmp_path):
    """Ingestion order is not scan order: a past run cannot resolve a current finding."""
    current = make_run(tmp_path, run_id="run-current", generated_at="2026-09-20T10:00:00Z",
                       findings=[sast("injection", fingerprint("a")), sast("xss", fingerprint("b"))])
    assert fleet_store.ingest_run(current, session)["created"] == 2
    historical = make_run(tmp_path, run_id="run-historical", generated_at="2026-09-19T10:00:00Z",
                          findings=[sast("xss", fingerprint("b"))])
    summary = fleet_store.ingest_run(historical, session)
    assert (summary["observed"], summary.get("resolved", 0)) == (1, 0)
    assert counts(session, FindingObservation) == 3
    findings = rows_by_fingerprint(session)
    assert [(findings["a"].lifecycle, findings["a"].status),
            (findings["b"].lifecycle, findings["b"].status)] == [("open", "new"), ("open", "new")]
    assert counts(session, FindingAuditEvent) == 0


def test_a_scan_that_ran_later_still_resolves(session, tmp_path):
    first = make_run(tmp_path, run_id="run-1", generated_at="2026-09-19T10:00:00Z",
                     findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(first, session)
    second = make_run(tmp_path, run_id="run-2", generated_at="2026-09-20T10:00:00Z", findings=[])
    assert fleet_store.ingest_run(second, session)["resolved"] == 1
    finding = session.exec(select(Finding)).one()
    assert (finding.lifecycle, finding.status) == ("resolved", "fixed")


@pytest.mark.parametrize("config_digest,policy_digest", [("cfg-B", "pol-A"), ("cfg-A", "pol-B"),
                                                         ("cfg-B", "pol-B")])
def test_a_different_rule_pack_or_policy_resolves_nothing(session, tmp_path, config_digest, policy_digest):
    """A completed adapter is not comparable coverage: a scan only proves what it looked for."""
    run1 = make_run(tmp_path, run_id="run-1", generated_at="2026-09-19T10:00:00Z",
                    findings=[sast("injection", fingerprint("a"))],
                    config_digest="cfg-A", policy_digest="pol-A")
    fleet_store.ingest_run(run1, session)
    run2 = make_run(tmp_path, run_id="run-2", generated_at="2026-09-20T10:00:00Z", findings=[],
                    config_digest=config_digest, policy_digest=policy_digest)
    summary = fleet_store.ingest_run(run2, session)
    assert summary["scans"] == 1 and summary.get("resolved", 0) == 0
    assert session.exec(select(Finding)).one().lifecycle == "open"
    assert counts(session, FindingAuditEvent) == 0


def test_an_unchanged_rule_pack_and_policy_still_resolve(session, tmp_path):
    run1 = make_run(tmp_path, run_id="run-1", generated_at="2026-09-19T10:00:00Z",
                    findings=[sast("injection", fingerprint("a"))],
                    config_digest="cfg-A", policy_digest="pol-A")
    fleet_store.ingest_run(run1, session)
    run2 = make_run(tmp_path, run_id="run-2", generated_at="2026-09-20T10:00:00Z", findings=[],
                    config_digest="cfg-A", policy_digest="pol-A")
    assert fleet_store.ingest_run(run2, session)["resolved"] == 1
    assert session.exec(select(Finding)).one().lifecycle == "resolved"


def test_a_deployment_gains_the_columns_resolution_needs(tmp_path, monkeypatch):
    """_migrate must upgrade a database that was built before scan_time existed."""
    path, legacy = legacy_deployment(tmp_path)
    monkeypatch.setattr(database, "engine", legacy)
    monkeypatch.setattr(database, "DATABASE_URL", f"sqlite:///{path}")
    database._migrate()
    database._migrate()  # idempotent: a second worker finds the columns already there
    assert {"run_id", "scan_time", "config_digest", "policy_digest"} <= _columns(legacy, "scan")
    assert {"branch", "fingerprint_version", "verdict", "lifecycle", "baseline_state",
            "accepted_until"} <= _columns(legacy, "finding")
    assert {"reviewer", "expires_at", "event_key", "from_verdict", "to_verdict"} <= _columns(
        legacy, "findingauditevent")
    assert {"severity", "line_start", "line_end", "message_digest"} <= _columns(legacy, "findingobservation")
    assert "ix_scan_project_run" in _indexes(legacy, "scan")
    assert "ix_finding_audit_event_key" in _indexes(legacy, "findingauditevent")
    assert "ix_project_workspace_repo" in _indexes(legacy, "project")
    assert "ix_finding_project_branch_fingerprint" in _indexes(legacy, "finding")
    # The pre-fleet dashboard records one row per scan, all on branch '', where a
    # fingerprint repeating across scans is the intended behaviour: the identity
    # index is partial precisely so this pass leaves those rows alone.
    with legacy.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM finding WHERE branch = ''")).scalar() == 2


def test_duplicate_fleet_rows_fold_before_the_index_lands(tmp_path, monkeypatch):
    """A race between two ingests is folded away, its history re-pointed, then prevented.

    The fold covers exactly the rows the partial index does, and the verdict
    rename travels with it: a stored 'triaged' never said whether the finding
    was real, which is the one thing rule precision needs to know.
    """
    path, legacy = legacy_deployment(tmp_path)
    monkeypatch.setattr(database, "engine", legacy)
    monkeypatch.setattr(database, "DATABASE_URL", f"sqlite:///{path}")
    database._migrate()
    with legacy.begin() as conn:
        conn.execute(text("DROP INDEX ix_finding_project_branch_fingerprint"))
        conn.execute(text("UPDATE finding SET branch = 'main'"))
        for scan_id, finding_id in ((1, 1), (1, 2), (3, 2)):
            conn.execute(text("INSERT INTO findingobservation (scan_id, finding_id) VALUES (:s, :f)"),
                         {"s": scan_id, "f": finding_id})
        conn.execute(text("UPDATE finding SET verdict = 'triaged' WHERE id = 1"))
        conn.execute(text("INSERT INTO findingauditevent (finding_id, from_status, to_status, reason, "
                          "to_verdict, created_at) "
                          "VALUES (1, 'new', 'triaged', 'checked', 'triaged', '2026-09-20 10:00:00')"))
    database._migrate()

    with legacy.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM finding WHERE id = 2")).scalar() == 0
        # The duplicate's own scan is kept; its copy of a scan the survivor already
        # reported attests to the same observation and records nothing.
        assert conn.execute(text("SELECT scan_id FROM findingobservation ORDER BY scan_id")).all() == [
            (1,), (3,)]
        assert conn.execute(text("SELECT verdict FROM finding WHERE id = 1")).scalar() == "true_positive"
        assert conn.execute(text("SELECT to_verdict FROM findingauditevent")).all() == [("true_positive",)]
    assert "ix_finding_project_branch_fingerprint" in _indexes(legacy, "finding")

    with pytest.raises(IntegrityError):
        with legacy.begin() as conn:
            conn.execute(text("INSERT INTO finding (id, scan_id, project_id, tool, fingerprint, branch, "
                              "fingerprint_version, status) "
                              "VALUES (5, 3, 1, 'opengrep', :fp, 'main', 'sdt-v2', 'new')"),
                         {"fp": fingerprint("a")})


def test_resolution_is_limited_to_the_scanned_branch(session, tmp_path):
    run1 = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run1, session)
    run2 = make_run(tmp_path, run_id="run-2", findings=[sast("other", fingerprint("d"))],
                    branch="feature/NGNH-123")
    summary = fleet_store.ingest_run(run2, session)
    assert summary.get("resolved", 0) == 0
    findings = rows_by_fingerprint(session)
    assert (findings["a"].branch, findings["a"].lifecycle) == ("main", "open")
    assert findings["d"].branch == "feature/NGNH-123"


def test_a_repository_without_a_report_is_counted_not_fatal(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    manifest = json.loads((run / "fleet-manifest.json").read_text())
    manifest["repositories"].append({"repository": "broken", "branch": "main", "status": "execution_failed",
                                     "findings": 0, "error": "clone_failed"})
    (run / "fleet-manifest.json").write_text(json.dumps(manifest))
    summary = fleet_store.ingest_run(run, session)
    assert (summary["repositories"], summary["scans"], summary["missing_report"]) == (2, 1, 1)
    assert counts(session, Project) == 1 and counts(session, Scan) == 1


def test_a_manifest_slug_cannot_escape_the_run_directory(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", findings=[])
    manifest = json.loads((run / "fleet-manifest.json").read_text())
    manifest["repositories"][0]["repository"] = "../outside"
    (run / "fleet-manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        fleet_store.ingest_run(run, session)


def test_a_report_without_a_run_id_cannot_be_made_idempotent(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    report = json.loads((run / "repositories" / "app" / "findings.json").read_text())
    del report["runId"]
    (run / "repositories" / "app" / "findings.json").write_text(json.dumps(report))
    manifest = json.loads((run / "fleet-manifest.json").read_text())
    del manifest["repositories"][0]["runId"]
    (run / "fleet-manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        fleet_store.ingest_run(run, session)


@pytest.mark.parametrize("verdict,expected", [("true_positive", "triaged"), ("needs_context", "triaged"),
                                             ("false_positive", "false_positive"),
                                             ("unreviewed", "new")])
def test_the_legacy_status_follows_the_verdict(session, tmp_path, verdict, expected):
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run, session)
    finding = session.exec(select(Finding)).one()
    reviewed = fleet_store.review_finding(session, finding.id, verdict, reviewer="alice", reason="checked")
    assert (reviewed.verdict, reviewed.lifecycle, reviewed.status) == (verdict, "open", expected)


def test_a_resolved_finding_stays_fixed_however_it_is_reviewed(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run, session)
    run2 = make_run(tmp_path, run_id="run-2", findings=[])
    fleet_store.ingest_run(run2, session)
    finding = session.exec(select(Finding)).one()
    reviewed = fleet_store.review_finding(session, finding.id, "false_positive", reviewer="alice",
                                          reason="was a test fixture")
    assert (reviewed.lifecycle, reviewed.status) == ("resolved", "fixed")


def test_accepted_risk_needs_an_owner_a_reason_and_a_deadline(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run, session)
    finding = session.exec(select(Finding)).one()
    deadline = datetime(2026, 12, 31, tzinfo=timezone.utc)
    for kwargs in ({}, {"reviewer": "alice"}, {"reason": "guarded"}, {"expires_at": deadline},
                   {"reviewer": "alice", "reason": "guarded"},
                   {"reviewer": "alice", "expires_at": deadline},
                   {"reason": "guarded", "expires_at": deadline}):
        with pytest.raises(ValueError):
            fleet_store.review_finding(session, finding.id, "accepted_risk", **kwargs)
    # A deadline already in the past is a promise nobody is making, so it is
    # refused rather than stored as coverage that never existed.
    with pytest.raises(ValueError):
        fleet_store.review_finding(session, finding.id, "accepted_risk", reviewer="alice", reason="guarded",
                                   expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    # A deadline in the past is refused for every verdict, not only that one.
    with pytest.raises(ValueError):
        fleet_store.review_finding(session, finding.id, "true_positive", reviewer="alice", reason="real",
                                   expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    with pytest.raises(ValueError):
        fleet_store.review_finding(session, finding.id + 999, "true_positive")
    assert session.exec(select(Finding)).one().verdict == "unreviewed"
    assert counts(session, FindingAuditEvent) == 0


def test_triaged_is_no_longer_a_verdict(session, tmp_path):
    """'triaged' never said whether the finding was real, which precision needs."""
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run, session)
    finding = session.exec(select(Finding)).one()
    assert list(database.VERDICTS) == ["unreviewed", "true_positive", "false_positive", "accepted_risk",
                                       "needs_context"]
    with pytest.raises(ValueError):
        fleet_store.review_finding(session, finding.id, "triaged", reviewer="alice", reason="queued")
    assert counts(session, FindingAuditEvent) == 0
    # What it meant is now said by name, and no longer needs a deadline.
    assert fleet_store.review_finding(session, finding.id, "true_positive", reviewer="alice",
                                      reason="real").verdict == "true_positive"



def test_the_same_idempotency_key_records_one_event(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run, session)
    finding = session.exec(select(Finding)).one()
    deadline = datetime(2026, 12, 31, tzinfo=timezone.utc)
    review = {"verdict": "accepted_risk", "reviewer": "alice", "reason": "guarded by a parser",
              "expires_at": deadline, "idempotency_key": "review-1"}
    accepted = fleet_store.review_finding(session, finding.id, **review)
    assert (accepted.verdict, accepted.status) == ("accepted_risk", "accepted_risk")
    assert fleet_store._utc(accepted.accepted_until) == fleet_store._utc(deadline)
    replayed = fleet_store.review_finding(session, finding.id, **review)
    assert (replayed.status, fleet_store._utc(replayed.accepted_until)) == ("accepted_risk", deadline)
    events = session.exec(select(FindingAuditEvent)).all()
    assert len(events) == 1
    assert events[0].event_key == f"{finding.id}:accepted_risk:alice:review-1"
    assert (events[0].reviewer, events[0].from_status, events[0].to_status) == (
        "alice", "new", "accepted_risk")
    # The whole decision is in the trail: what it was before, and what it is now.
    assert (events[0].from_verdict, events[0].to_verdict) == ("unreviewed", "accepted_risk")
    assert fleet_store._utc(events[0].expires_at) == deadline

    # A different key is a different decision, and a caller that says nothing
    # gets a fresh key, so it is recorded on its own merits.
    fleet_store.review_finding(session, finding.id, **{**review, "idempotency_key": "review-2"})
    assert counts(session, FindingAuditEvent) == 2
    fleet_store.review_finding(session, finding.id, **{**review, "idempotency_key": None})
    assert counts(session, FindingAuditEvent) == 3


def test_a_different_decision_still_leaves_trail(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run, session)
    finding = session.exec(select(Finding)).one()
    fleet_store.review_finding(session, finding.id, "needs_context", reviewer="alice", reason="ask the team")
    fleet_store.review_finding(session, finding.id, "false_positive", reviewer="bob", reason="test fixture")
    events = session.exec(select(FindingAuditEvent).order_by(FindingAuditEvent.id)).all()
    assert [(event.reviewer, event.to_status) for event in events] == [("alice", "triaged"),
                                                                      ("bob", "false_positive")]


def test_an_accepted_risk_without_an_expiry_never_expires(session, tmp_path):
    """The service insists on a deadline; a row migrated from before it stays honoured."""
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run, session)
    finding = session.exec(select(Finding)).one()
    finding.verdict = "accepted_risk"
    finding.status = database.derived_status(finding)
    session.add(finding)
    session.commit()

    assert finding.accepted_until is None
    assert fleet_store.effective_verdict(finding) == "accepted_risk"
    assert fleet_store.is_live_acceptance(finding) is True
    assert fleet_store.verdict_counts(session) == {"accepted_risk": 1}
    assert fleet_store.review_finding(session, finding.id, "unreviewed").status == "new"


def test_an_expired_acceptance_needs_the_queue_again(session, tmp_path):
    """The stored verdict is never rewritten; what changes is whether it covers the finding."""
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(run, session)
    finding = session.exec(select(Finding)).one()
    deadline = datetime(2026, 12, 31, tzinfo=timezone.utc)
    fleet_store.review_finding(session, finding.id, "accepted_risk", reviewer="alice",
                               reason="guarded by a parser", expires_at=deadline)
    finding = session.exec(select(Finding)).one()
    before, after = deadline - timedelta(days=1), deadline + timedelta(days=1)
    assert fleet_store.effective_verdict(finding, before) == "accepted_risk"
    assert fleet_store.effective_verdict(finding, after) == fleet_store.EXPIRED_ACCEPTANCE
    assert (fleet_store.is_live_acceptance(finding, before),
            fleet_store.is_live_acceptance(finding, after)) == (True, False)
    assert finding.verdict == "accepted_risk"
    assert fleet_store.verdict_counts(session, before) == {"accepted_risk": 1}
    assert fleet_store.verdict_counts(session, after) == {fleet_store.EXPIRED_ACCEPTANCE: 1}


def test_a_reobservation_notes_an_expired_acceptance_once(session, tmp_path, monkeypatch):
    """The queue has to say so from the day the deadline passed, and say it once."""
    first = make_run(tmp_path, run_id="run-1", generated_at="2026-09-20T10:00:00Z",
                     findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(first, session)
    finding = session.exec(select(Finding)).one()
    monkeypatch.setattr(fleet_store, "utcnow", lambda: datetime(2026, 9, 25, tzinfo=timezone.utc))
    fleet_store.review_finding(session, finding.id, "accepted_risk", reviewer="alice", reason="guarded",
                               expires_at=datetime(2026, 9, 28, tzinfo=timezone.utc))
    monkeypatch.setattr(fleet_store, "utcnow", lambda: datetime(2026, 9, 29, tzinfo=timezone.utc))

    second = make_run(tmp_path, run_id="run-2", generated_at="2026-09-29T10:00:00Z",
                      findings=[sast("injection", fingerprint("a"))])
    assert fleet_store.ingest_run(second, session)["observed"] == 1
    notes = session.exec(select(FindingAuditEvent).where(FindingAuditEvent.to_status == "expired")).all()
    assert [(note.reviewer, note.from_verdict, note.to_verdict) for note in notes] == [
        ("fleet-ingest", "accepted_risk", "accepted_risk")]
    assert notes[0].event_key == f"{finding.id}:accepted_risk:fleet-ingest:expired:2026-09-28T00:00:00+00:00"

    third = make_run(tmp_path, run_id="run-3", generated_at="2026-09-30T10:00:00Z",
                     findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(third, session)
    assert len(session.exec(select(FindingAuditEvent).where(FindingAuditEvent.to_status == "expired")).all()) == 1
    assert counts(session, FindingAuditEvent) == 2


def test_an_observation_keeps_what_its_own_scan_reported(session, tmp_path):
    """The finding row shows the newest report; every observation keeps its own."""
    first = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"))])
    fleet_store.ingest_run(first, session)
    moved = {**sast("injection", fingerprint("a")), "severity": {"canonical": "critical"},
             "location": {"path": "src/app.py", "startLine": 40, "endLine": 41},
             "message": "untrusted input reaches a shell, in app.py"}
    second = make_run(tmp_path, run_id="run-2", findings=[moved])
    assert fleet_store.ingest_run(second, session)["observed"] == 1

    finding = session.exec(select(Finding)).one()
    assert (finding.severity, finding.line_start, finding.line_end) == ("critical", 40, 41)
    observations = session.exec(select(FindingObservation).order_by(FindingObservation.id)).all()
    assert [(o.severity, o.line_start, o.line_end) for o in observations] == [
        ("high", 8, 9), ("critical", 40, 41)]
    # A digest, not the message: a reworded report reads as a change, a repeat does not.
    assert all(len(o.message_digest) == 32 and set(o.message_digest) <= set("0123456789abcdef")
               for o in observations)
    assert observations[0].message_digest != observations[1].message_digest


def test_a_severity_the_schema_does_not_know_reads_as_info(session, tmp_path):
    run = make_run(tmp_path, run_id="run-1", findings=[sast("injection", fingerprint("a"),
                                                          severity={"canonical": "blocker"})])
    fleet_store.ingest_run(run, session)
    assert session.exec(select(Finding)).one().severity == "info"
    assert session.exec(select(FindingObservation)).one().severity == "info"


def test_an_approval_can_freeze_the_scan_an_operator_watched(session, tmp_path):
    """An approval can name the run it was based on, not whatever the table held."""
    first = make_run(tmp_path, run_id="run-1", generated_at="2026-09-19T10:00:00Z",
                     findings=[sast("injection", fingerprint("a")), sast("xss", fingerprint("b"))])
    fleet_store.ingest_run(first, session)
    second = make_run(tmp_path, run_id="run-2", generated_at="2026-09-20T10:00:00Z",
                      findings=[sast("xss", fingerprint("b"))])
    assert fleet_store.ingest_run(second, session)["resolved"] == 1
    project = session.exec(select(Project)).one()
    watched = session.exec(select(Scan).where(Scan.run_id == "run-1")).one()

    baseline = fleet_store.approve_baseline(session, project.id, "main", "alice", "as of run-1",
                                           source_scan_id=watched.id)
    assert (baseline.finding_count, baseline.source_scan_id) == (2, watched.id)
    members = session.exec(select(BaselineItem).where(BaselineItem.baseline_id == baseline.id)).all()
    assert {item.fingerprint[-1] for item in members} == {"a", "b"}

    # Run-3 re-observes the resolved "a": it is a baseline member because run-1
    # reported it, whatever the row looked like when the approval landed.
    third = make_run(tmp_path, run_id="run-3", generated_at="2026-09-21T10:00:00Z",
                     findings=[sast("injection", fingerprint("a"))])
    assert fleet_store.ingest_run(third, session)["observed"] == 1
    findings = rows_by_fingerprint(session)
    assert (findings["a"].lifecycle, findings["a"].baseline_state) == ("open", "existing")
    reopened = session.exec(select(FindingAuditEvent)
                            .where(FindingAuditEvent.to_status == "new")).one()
    assert (reopened.from_status, reopened.from_verdict, reopened.to_verdict, reopened.reviewer) == (
        "resolved", "unreviewed", "unreviewed", "")
    assert reopened.event_key.endswith("reopen:run-3")

    # Without a source scan the frozen set is the branch as it reads right now (1 open finding).
    current = fleet_store.approve_baseline(session, project.id, "main", "bob", "current state")
    assert (current.finding_count, current.source_scan_id) == (1, None)

    other_branch = make_run(tmp_path, run_id="run-4", generated_at="2026-09-22T10:00:00Z",
                            findings=[], branch="feature/NGNH-123")
    fleet_store.ingest_run(other_branch, session)
    wrong = session.exec(select(Scan).where(Scan.run_id == "run-4")).one()
    for scan_id in (wrong.id, 9999):
        with pytest.raises(ValueError):
            fleet_store.approve_baseline(session, project.id, "main", "bob", "no", source_scan_id=scan_id)
    assert counts(session, Baseline) == 2


def test_a_postgres_deployment_is_migrated_too(monkeypatch):
    """The migration pass is no longer SQLite-only, and every statement has both spellings."""
    reached = []
    monkeypatch.setattr(database, "DATABASE_URL", "postgresql+psycopg://sdt@localhost:5432/sdt")
    monkeypatch.setattr(database, "_migrate_fleet_columns", lambda inspector: reached.append("fleet"))
    database._migrate()
    assert reached == ["fleet"]
    assert database._ddl("ALTER TABLE scan ADD COLUMN scan_time {datetime}") == (
        "ALTER TABLE scan ADD COLUMN scan_time TIMESTAMP")
    assert database._ddl("ALTER TABLE target ADD COLUMN production_confirmed BOOLEAN DEFAULT {false}") == (
        "ALTER TABLE target ADD COLUMN production_confirmed BOOLEAN DEFAULT FALSE")
    statements = [ddl for _, _, ddl in database._FLEET_COLUMNS]
    statements += [ddl for _, ddl in database._FLEET_INDEXES]
    statements += [ddl for _, _, ddl in database._UNIQUE_INDEXES]
    assert [ddl for ddl in statements if "{" in database._ddl(ddl)] == []




def test_a_renewed_acceptance_that_lapses_again_is_noted_again(session, tmp_path, monkeypatch):
    """P2-7: the expiry key is per deadline, so each acceptance period expires on the record."""
    fleet_store.ingest_run(make_run(tmp_path, run_id="run-1", generated_at="2026-09-10T00:00:00Z",
                                    findings=[sast("injection", fingerprint("a"))]), session)
    finding = session.exec(select(Finding)).one()
    now = datetime(2026, 9, 20, tzinfo=timezone.utc)
    monkeypatch.setattr(fleet_store, "utcnow", lambda: now)
    fleet_store.review_finding(session, finding.id, "accepted_risk", reviewer="alice", reason="first",
                               expires_at=now + timedelta(days=1))
    monkeypatch.setattr(fleet_store, "utcnow", lambda: now + timedelta(days=2))
    fleet_store.ingest_run(make_run(tmp_path, run_id="run-2", generated_at="2026-09-22T00:00:00Z",
                                    findings=[sast("injection", fingerprint("a"))]), session)
    fleet_store.review_finding(session, finding.id, "accepted_risk", reviewer="alice", reason="renewed",
                               expires_at=now + timedelta(days=3))
    monkeypatch.setattr(fleet_store, "utcnow", lambda: now + timedelta(days=4))
    fleet_store.ingest_run(make_run(tmp_path, run_id="run-3", generated_at="2026-09-24T00:00:00Z",
                                    findings=[sast("injection", fingerprint("a"))]), session)
    expired = session.exec(select(FindingAuditEvent).where(FindingAuditEvent.to_status == "expired")).all()
    assert len(expired) == 2


def test_an_older_run_imported_late_does_not_reopen_what_a_newer_scan_resolved(session, tmp_path):
    """P1-1: scan time, not ingestion order, decides the lifecycle."""
    fleet_store.ingest_run(make_run(tmp_path, run_id="r1", generated_at="2026-09-10T00:00:00Z",
                                    findings=[sast("injection", fingerprint("a"))]), session)
    fleet_store.ingest_run(make_run(tmp_path, run_id="r2", generated_at="2026-09-20T00:00:00Z", findings=[]), session)
    finding = session.exec(select(Finding)).one()
    assert finding.lifecycle == "resolved"
    fleet_store.ingest_run(make_run(tmp_path, run_id="r0", generated_at="2026-09-01T00:00:00Z",
                                    findings=[sast("injection", fingerprint("a"))]), session)
    session.refresh(finding)
    assert finding.lifecycle == "resolved"
    assert counts(session, FindingObservation) == 2  # the old run is still on the record


def test_an_older_run_imported_late_does_not_overwrite_what_the_finding_shows(session, tmp_path):
    """P1-1: the newest scan owns severity, lines and message; last_seen is scan time."""
    fleet_store.ingest_run(make_run(tmp_path, run_id="new", generated_at="2026-09-20T00:00:00Z",
                                    findings=[sast("injection", fingerprint("a"), severity={"canonical": "critical"})]),
                           session)
    fleet_store.ingest_run(make_run(tmp_path, run_id="old", generated_at="2026-09-10T00:00:00Z",
                                    findings=[sast("injection", fingerprint("a"), severity={"canonical": "low"})]),
                           session)
    finding = session.exec(select(Finding)).one()
    assert finding.severity == "critical"
    observed = session.exec(select(FindingObservation.severity).order_by(FindingObservation.id)).all()
    assert observed == ["critical", "low"]


def test_a_reopen_is_dated_when_the_scan_ran_not_when_it_was_imported(session, tmp_path):
    fleet_store.ingest_run(make_run(tmp_path, run_id="r1", generated_at="2026-09-10T00:00:00Z",
                                    findings=[sast("injection", fingerprint("a"))]), session)
    fleet_store.ingest_run(make_run(tmp_path, run_id="r2", generated_at="2026-09-20T00:00:00Z", findings=[]), session)
    fleet_store.ingest_run(make_run(tmp_path, run_id="r3", generated_at="2026-09-25T08:30:00Z",
                                    findings=[sast("injection", fingerprint("a"))]), session)
    reopen = session.exec(select(FindingAuditEvent).where(FindingAuditEvent.from_status == "resolved")).one()
    assert fleet_store._utc(reopen.created_at) == datetime(2026, 9, 25, 8, 30, tzinfo=timezone.utc)


def test_sonar_decisions_land_through_the_review_service_once(session, tmp_path):
    """Reviews made in SonarQube become verdicts with an audit trail, idempotently."""
    fleet_store.ingest_run(make_run(tmp_path, run_id="r1", generated_at="2026-09-10T00:00:00Z",
                                    findings=[sast("scp.py.injection", fingerprint("a")),
                                              sast("scp.py.other", fingerprint("b"),
                                                   location={"path": "src/b.py", "startLine": 3})]), session)
    project_id = session.exec(select(Project)).one().id
    decisions = [
        {"key": "AX1", "rule": "opengrep-py:scp.py.injection", "path": "src/app.py", "line": 8,
         "verdict": "false_positive", "reviewer": "bob", "reason": "sanitised"},
        {"key": "AX2", "rule": "opengrep-py:scp.py.other", "path": "src/b.py", "line": 3,
         "verdict": "accepted_risk", "reviewer": "", "reason": ""},
        {"key": "AX3", "rule": "opengrep-py:scp.py.injection", "path": "src/missing.py", "line": 1,
         "verdict": "true_positive"},
        {"key": "AX4", "rule": "python:S5332", "path": "src/app.py", "line": 8, "verdict": "true_positive"},
    ]
    assert fleet_store.apply_sonar_decisions(session, project_id, "main", decisions) == {
        "applied": 2, "unchanged": 0, "unmatched": 2}
    rows = {f.rule_id: f for f in session.exec(select(Finding)).all()}
    assert rows["scp.py.injection"].verdict == "false_positive"
    accepted = rows["scp.py.other"]
    assert accepted.verdict == "accepted_risk" and fleet_store.is_live_acceptance(accepted)
    reviewers = {e.reviewer for e in session.exec(select(FindingAuditEvent)).all()}
    assert reviewers == {"sonar:bob", "sonar:unknown"}
    assert fleet_store.apply_sonar_decisions(session, project_id, "main", decisions)["unchanged"] == 2
    assert counts(session, FindingAuditEvent) == 2
