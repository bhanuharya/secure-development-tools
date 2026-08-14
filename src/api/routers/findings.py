from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import Session, select

from src.api.database import Finding, FindingAuditEvent, get_session, utcnow

router = APIRouter(prefix="/api/findings", tags=["findings"])


class FindingUpdate(BaseModel):
    status: str  # new|triaged|fixed|false_positive|accepted_risk
    reason: str = ""


@router.get("")
def list_findings(
    scan_id: int | None = Query(None),
    project_id: int | None = Query(None),
    status: str | None = Query(None),
    severity: str | None = Query(None),
    tool: str | None = Query(None),
    source_type: str | None = Query(None),
    pr_changed: bool | None = Query(None),
    q: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    session: Session = Depends(get_session),
):
    stmt = select(Finding).order_by(Finding.severity.asc(), Finding.id.desc())
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if project_id:
        stmt = stmt.where(Finding.project_id == project_id)
    if status:
        stmt = stmt.where(Finding.status == status)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if tool:
        stmt = stmt.where(Finding.tool == tool)
    if source_type:
        stmt = stmt.where(Finding.source_type == source_type)
    if pr_changed is not None:
        stmt = stmt.where(Finding.in_pr_diff == pr_changed)
    if q:
        stmt = stmt.where(
            (Finding.description.contains(q)) | (Finding.rule_id.contains(q)) | (Finding.file_path.contains(q))
        )
    return [_serialize_finding(finding) for finding in session.exec(stmt.limit(limit)).all()]


@router.get("/{finding_id}")
def get_finding(finding_id: int, session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "finding not found")
    return _serialize_finding(finding)


@router.patch("/{finding_id}")
def update_finding(finding_id: int, body: FindingUpdate, session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "finding not found")
    valid = {"new", "triaged", "fixed", "false_positive", "accepted_risk"}
    if body.status not in valid:
        raise HTTPException(400, f"invalid status; expected one of {sorted(valid)}")
    if body.status != finding.status:
        audit = FindingAuditEvent(
            finding_id=finding.id,
            from_status=finding.status,
            to_status=body.status,
            reason=body.reason,
            created_at=utcnow(),
        )
        session.add(audit)
        finding.status = body.status
        finding.triage_reason = body.reason
        session.add(finding)
        session.commit()
        session.refresh(finding)
    return _serialize_finding(finding)


@router.get("/{finding_id}/audit")
def finding_audit(finding_id: int, session: Session = Depends(get_session)):
    if not session.get(Finding, finding_id):
        raise HTTPException(404, "finding not found")
    return session.exec(
        select(FindingAuditEvent).where(FindingAuditEvent.finding_id == finding_id).order_by(FindingAuditEvent.id.desc())
    ).all()


def _serialize_finding(finding: Finding) -> dict:
    data = finding.model_dump()
    try:
        evidence = json.loads(finding.evidence or "{}")
    except (json.JSONDecodeError, TypeError):
        evidence = {}
    data["evidence"] = evidence if isinstance(evidence, dict) else {}
    return data
