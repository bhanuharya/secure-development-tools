"""Fleet dashboard API: run ingest, fleet-wide review state, and baselines.

Every endpoint reads or writes the state ``src/api/fleet_store.py`` builds from
immutable fleet run artifacts, so this router holds no policy of its own — the
service functions are shared with the ingest CLI and stay the single source of
validation rules.

Authentication is the app-level ``AuthMiddleware`` (as for the other ``/api``
routers): an unconfigured control plane only answers to localhost peers.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlmodel import Session, select

from src.api import fleet_store
from src.api.database import Baseline, Finding, Project, Scan, get_session, utcnow
from src.scanners.evidence import redact_text

router = APIRouter(prefix="/api/fleet/v1", tags=["fleet"])


class IngestRequest(BaseModel):
    run_dir: str


class ReviewRequest(BaseModel):
    verdict: str  # one of src.api.database.VERDICTS
    reviewer: str = ""
    reason: str = ""
    expires_at: datetime | None = None
    idempotency_key: str | None = Field(
        default=None,
        description="retry token: a repeated decision carrying the same key is recorded once")


class BaselineApproveRequest(BaseModel):
    project_id: int
    branch: str
    approved_by: str
    reason: str = ""
    source_scan_id: int | None = None


@router.post("/ingest")
def ingest_run(body: IngestRequest, session: Session = Depends(get_session)):
    """Import one fleet run directory. Replaying the same run is a no-op.

    Local-lab convenience: ``run_dir`` is a directory on the server's own
    filesystem (the fleet orchestrator's output directory), so this is for a
    trusted operator. A remote CI job should run ``tools/sdt_fleet_ingest.py``
    against the same database instead of posting a host path here.
    """
    roots = [Path(p).resolve() for p in (os.environ.get("SCP_FLEET_RUN_ROOTS") or "").split(":") if p]
    if roots:
        run_path = Path(body.run_dir).resolve()
        if not any(run_path == root or root in run_path.parents for root in roots):
            raise HTTPException(status_code=400, detail="run_dir is outside SCP_FLEET_RUN_ROOTS")
    try:
        return fleet_store.ingest_run(Path(body.run_dir), session)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/overview")
def overview(session: Session = Depends(get_session)):
    """Fleet-wide counts: what was scanned, and what is still open.

    `verdicts` is keyed by the verdict a reader should act on, so an accepted
    risk past its deadline counts as expired rather than as covered, and the
    backlog is what is unreviewed plus whatever has come due again.
    """
    is_open = Finding.lifecycle == "open"
    verdicts = fleet_store.verdict_counts(session, utcnow())
    backlog = sum(verdicts.get(verdict, 0)
                  for verdict in ("unreviewed", fleet_store.EXPIRED_ACCEPTANCE))
    return {
        "projects": _count(session, Project),
        "scans": _count(session, Scan),
        "findings": {
            "open": _count(session, Finding, is_open),
            "resolved": _count(session, Finding, Finding.lifecycle == "resolved"),
        },
        "by_severity": _open_counts_by(session, Finding.severity),
        "verdicts": verdicts,
        "baseline_states": _open_counts_by(session, Finding.baseline_state),
        "review_backlog": backlog,
    }


@router.get("/findings")
def list_findings(
    project: str | None = Query(None, description="repository slug"),
    branch: str | None = Query(None),
    verdict: str | None = Query(None),
    lifecycle: str | None = Query(None),
    baseline_state: str | None = Query(None),
    severity: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    session: Session = Depends(get_session),
):
    """The newest-seen findings across the fleet, filterable by review state.

    `verdict` filters the verdict as recorded; every row also carries
    `effective_verdict`, which is what the overview counts by and reads
    `expired_accepted_risk` once an acceptance has run out.
    """
    conditions = []
    if project:
        conditions.append(Project.repo_slug == project)
    if branch:
        conditions.append(Finding.branch == branch)
    if verdict:
        conditions.append(Finding.verdict == verdict)
    if lifecycle:
        conditions.append(Finding.lifecycle == lifecycle)
    if baseline_state:
        conditions.append(Finding.baseline_state == baseline_state)
    if severity:
        conditions.append(Finding.severity == severity)

    joined = select(Finding, Project).join(Project, Project.id == Finding.project_id)
    total = session.exec(
        select(func.count()).select_from(Finding).join(Project, Project.id == Finding.project_id).where(*conditions)
    ).one()
    rows = session.exec(
        joined.where(*conditions).order_by(Finding.last_seen.desc(), Finding.id.desc()).offset(offset).limit(limit)
    ).all()
    return {"total": total, "items": [_finding_dict(finding, repo) for finding, repo in rows]}


@router.post("/findings/{finding_id}/review")
def review_finding(finding_id: int, body: ReviewRequest, session: Session = Depends(get_session)):
    """Record one human decision on a finding (owner, reason, expiry for risks)."""
    try:
        finding = fleet_store.review_finding(
            session, finding_id, body.verdict, reviewer=body.reviewer, reason=body.reason,
            expires_at=body.expires_at, idempotency_key=body.idempotency_key,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return _finding_dict(finding, session.get(Project, finding.project_id))


@router.post("/baselines/approve")
def approve_baseline(body: BaselineApproveRequest, session: Session = Depends(get_session)):
    """Freeze one project+branch's open findings as the active accepted-known baseline."""
    if session.get(Project, body.project_id) is None:
        raise HTTPException(status_code=404, detail=f"project {body.project_id} not found")
    if body.source_scan_id is not None and session.get(Scan, body.source_scan_id) is None:
        raise HTTPException(status_code=404, detail=f"scan {body.source_scan_id} not found")
    try:
        baseline = fleet_store.approve_baseline(
            session, body.project_id, body.branch, body.approved_by, body.reason,
            source_scan_id=body.source_scan_id,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return _baseline_dict(baseline)


def _count(session: Session, model, *conditions) -> int:
    return session.exec(select(func.count()).select_from(model).where(*conditions)).one()


def _open_counts_by(session: Session, column) -> dict[str, int]:
    """Count of still-open findings, grouped by one of their state columns."""
    rows = session.exec(select(column, func.count()).where(Finding.lifecycle == "open").group_by(column)).all()
    return {str(key): int(value) for key, value in rows}


def _finding_dict(finding: Finding, project: Project | None) -> dict:
    """The row the fleet dashboard lists; `message` is the finding description."""
    return {
        "id": finding.id,
        "repository": project.repo_slug if project else "",
        "workspace": project.workspace if project else "",
        "branch": finding.branch,
        "tool": finding.tool,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "file_path": redact_text(finding.file_path),
        "line_start": finding.line_start,
        "message": redact_text(finding.description),
        "verdict": finding.verdict,
        "effective_verdict": fleet_store.effective_verdict(finding, utcnow()),
        "lifecycle": finding.lifecycle,
        "baseline_state": finding.baseline_state,
        "accepted_until": finding.accepted_until,
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
    }


def _baseline_dict(baseline: Baseline) -> dict:
    return {
        "id": baseline.id,
        "project_id": baseline.project_id,
        "branch": baseline.branch,
        "approved_by": baseline.approved_by,
        "finding_count": baseline.finding_count,
        "source_scan_id": baseline.source_scan_id,
        "created_at": baseline.created_at,
    }
