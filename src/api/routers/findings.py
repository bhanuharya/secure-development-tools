from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import case
from sqlmodel import Session, select

from src.api.database import Finding, FindingAuditEvent, get_session, utcnow
from src.scanners.evidence import redact_text

router = APIRouter(prefix="/api/findings", tags=["findings"])

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_VALID_STATUSES = {"new", "triaged", "fixed", "false_positive", "accepted_risk"}


class FindingUpdate(BaseModel):
    status: str  # new|triaged|fixed|false_positive|accepted_risk
    reason: str = ""


class BulkStatusUpdate(BaseModel):
    ids: list[int] = Field(min_length=1)
    status: str
    reason: str = ""


@router.get("")
def list_findings(
    response: Response,
    scan_id: int | None = Query(None),
    project_id: int | None = Query(None),
    status: str | None = Query(None),
    severity: str | None = Query(None),
    severity_gte: str | None = Query(None),
    tool: str | None = Query(None),
    source_type: str | None = Query(None),
    pr_changed: bool | None = Query(None),
    q: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=5000),
    include_evidence: bool = Query(
        False, description="include the (up to 8 KiB) evidence blob per finding; the detail endpoint always includes it"
    ),
    session: Session = Depends(get_session),
):
    from sqlalchemy import func

    conditions = []
    if scan_id:
        conditions.append(Finding.scan_id == scan_id)
    if project_id:
        conditions.append(Finding.project_id == project_id)
    if status:
        conditions.append(Finding.status == status)
    if severity:
        conditions.append(Finding.severity == severity)
    if severity_gte:
        if severity_gte not in _SEVERITY_RANK:
            raise HTTPException(400, f"invalid severity_gte: {severity_gte}")
        conditions.append(Finding.severity.in_(
            [s for s, r in _SEVERITY_RANK.items() if r <= _SEVERITY_RANK[severity_gte]]
        ))
    if tool:
        conditions.append(Finding.tool == tool)
    if source_type:
        conditions.append(Finding.source_type == source_type)
    if pr_changed is not None:
        conditions.append(Finding.in_pr_diff == pr_changed)
    if q:
        conditions.append(
            (Finding.description.contains(q)) | (Finding.rule_id.contains(q)) | (Finding.file_path.contains(q))
        )

    total = session.exec(select(func.count()).select_from(Finding).where(*conditions)).one()
    # Order by true severity rank, not alphabetically ("info" would otherwise
    # sort before "low"/"medium").
    rank = case(
        {sev: i for i, sev in enumerate(_SEVERITY_RANK)},
        value=Finding.severity,
        else_=len(_SEVERITY_RANK),
    )
    stmt = select(Finding).order_by(rank, Finding.id.desc())
    if conditions:
        stmt = stmt.where(*conditions)
    rows = session.exec(stmt.offset(offset).limit(limit)).all()
    response.headers["X-Total-Count"] = str(total)
    return [_serialize_finding(f, include_evidence=include_evidence) for f in rows]


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
    if body.status not in _VALID_STATUSES:
        raise HTTPException(400, f"invalid status; expected one of {sorted(_VALID_STATUSES)}")
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


@router.post("/bulk-status")
def bulk_status_update(body: BulkStatusUpdate, session: Session = Depends(get_session)):
    """Batch triage: set the same status on many findings in one call.

    Returns the count of findings actually changed, plus any ids that were not
    found (so a bot can decide whether to treat them as errors).
    """
    if body.status not in _VALID_STATUSES:
        raise HTTPException(400, f"invalid status; expected one of {sorted(_VALID_STATUSES)}")
    rows = session.exec(select(Finding).where(Finding.id.in_(body.ids))).all()
    found_ids = {f.id for f in rows}
    missing = [i for i in body.ids if i not in found_ids]
    changed = 0
    for f in rows:
        if f.status != body.status:
            session.add(FindingAuditEvent(
                finding_id=f.id,
                from_status=f.status,
                to_status=body.status,
                reason=body.reason,
                created_at=utcnow(),
            ))
            f.status = body.status
            f.triage_reason = body.reason
            session.add(f)
            changed += 1
    session.commit()
    return {"changed": changed, "missing": missing}


def _serialize_finding(finding: Finding, include_evidence: bool = True) -> dict:
    data = _redact_value(finding.model_dump())
    if include_evidence:
        try:
            evidence = json.loads(finding.evidence or "{}")
        except (json.JSONDecodeError, TypeError):
            evidence = {}
        data["evidence"] = _redact_value(evidence) if isinstance(evidence, dict) else {}
    else:
        data.pop("evidence", None)
    return data


def _redact_value(value: Any) -> Any:
    """Redact string leaves at the API boundary, including legacy rows."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    return value
