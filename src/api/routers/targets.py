"""Target approval endpoints.

DAST targets must be approved server-side before any active scan can run.
Approval is a deliberate, separate, audited action — never a client-supplied
flag on the scan request — so launching an active scan against an arbitrary
URL requires two distinct calls and leaves a trail.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from src.api.database import Target, TargetAuditEvent, get_session, utcnow
from src.api.routers.projects import _mask
from src.util.dastgate import require_dast_control_auth

router = APIRouter(prefix="/api/targets", tags=["targets"])


class ApproveRequest(BaseModel):
    reason: str = ""
    # Required (true) only when the target is flagged as production.
    production_ack: bool = False


@router.post("/{target_id}/approve")
def approve_target(target_id: int, body: ApproveRequest, session: Session = Depends(get_session)):
    """Mark a target as approved for active scanning (audited)."""
    try:
        require_dast_control_auth()
    except ValueError as exc:
        raise HTTPException(403, str(exc)) from exc
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(404, "target not found")
    if target.is_production and not body.production_ack:
        raise HTTPException(
            400,
            "target is production: approval requires production_ack=true to "
            "record an explicit acknowledgement",
        )
    changed = not target.pre_approved
    target.pre_approved = True
    if target.is_production:
        target.production_confirmed = True
    session.add(target)
    if changed:
        session.add(TargetAuditEvent(
            target_id=target.id,
            action="approve",
            reason=body.reason,
            created_at=utcnow(),
        ))
    session.commit()
    session.refresh(target)
    return _mask(target)


@router.post("/{target_id}/revoke")
def revoke_target(target_id: int, body: ApproveRequest, session: Session = Depends(get_session)):
    """Withdraw approval; pending/new scans of this target will be refused."""
    try:
        require_dast_control_auth()
    except ValueError as exc:
        raise HTTPException(403, str(exc)) from exc
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(404, "target not found")
    if target.pre_approved:
        target.pre_approved = False
        target.production_confirmed = False
        session.add(target)
        session.add(TargetAuditEvent(
            target_id=target.id,
            action="revoke",
            reason=body.reason,
            created_at=utcnow(),
        ))
        session.commit()
        session.refresh(target)
    return _mask(target)


@router.get("/{target_id}/audit")
def target_audit(target_id: int, session: Session = Depends(get_session)):
    try:
        require_dast_control_auth()
    except ValueError as exc:
        raise HTTPException(403, str(exc)) from exc
    if not session.get(Target, target_id):
        raise HTTPException(404, "target not found")
    return session.exec(
        select(TargetAuditEvent)
        .where(TargetAuditEvent.target_id == target_id)
        .order_by(TargetAuditEvent.id.desc())
    ).all()
