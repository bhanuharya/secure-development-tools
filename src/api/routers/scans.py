from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from src.api.database import Project, Scan, Target, engine, get_session
from src.api.events import event_bus, sse_format
from src.scanners.executor import ScanCapacityError, get_executor
from src.scanners.orchestrator import ALL_ENGINES, ScanRunner


def _target_digest(target: Target) -> str:
    values = {k: getattr(target, k, "") for k in (
        "url", "is_production", "auth_mode", "login_url", "username_field",
        "password_field", "auth_username", "auth_password", "context_file_path",
        "production_confirmed", "pre_approved")}
    return hashlib.sha256(json.dumps(values, sort_keys=True, default=str).encode()).hexdigest()

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["scans"])

# Hard cap for the SSE progress stream so a stuck scan can never pin a
# connection (and a per-tick DB session) open forever.
SSE_MAX_SECONDS = 3600


class ScanCreate(BaseModel):
    project_id: int
    scan_type: str = Field(default="sast", pattern="^(sast|sca|secrets|dast|iac)$")
    ref_type: str = Field(default="branch", pattern="^(branch|pr)$")
    ref_name: str = Field(default="")
    engines: list[str] = Field(default_factory=list)
    language_override: str = ""
    dast_target: int | None = None


@router.post("")
def create_scan(body: ScanCreate, session: Session = Depends(get_session)):
    project = session.get(Project, body.project_id)
    if not project:
        raise HTTPException(404, "project not found")

    # Uploaded (standalone) projects have no Bitbucket repository to clone.
    # Reject generic branch/PR rescans so the orchestrator never tries to hit
    # Bitbucket with an empty workspace. DAST scans never clone anything, so
    # they stay allowed for standalone (uploaded) projects.
    if body.scan_type != "dast" and project.workspace == "" and body.ref_type in ("branch", "pr"):
        raise HTTPException(
            400,
            "uploaded projects cannot be rescanned as branch/PR; upload a new ZIP to scan a new snapshot",
        )

    if body.ref_type == "branch" and not body.ref_name:
        body.ref_name = project.default_branch

    engines = body.engines or []
    if body.scan_type == "dast" and not engines:
        engines = ["zap"]
    if engines:
        unknown = [e for e in engines if e not in ALL_ENGINES]
        if unknown:
            raise HTTPException(400, f"unknown engines: {unknown}")

    # DAST safety gate: only server-side, audited approval state counts.
    # There is deliberately no client-supplied "confirmed" flag — approving a
    # target is a separate, audited action (POST /api/targets/{id}/approve).
    dast_target_id = body.dast_target
    if body.scan_type == "dast":
        if dast_target_id is None:
            raise HTTPException(400, "dast scans require a configured target")
        target = session.get(Target, dast_target_id)
        if not target or target.project_id != body.project_id:
            raise HTTPException(404, "target not found for this project")
        if not target.pre_approved:
            raise HTTPException(
                400,
                "target is not approved: approve it first via "
                f"POST /api/targets/{dast_target_id}/approve",
            )
        if target.is_production and not target.production_confirmed:
            raise HTTPException(
                400,
                "target is production: approval with production_ack=true is "
                "required before scanning",
            )

    scan = Scan(
        project_id=body.project_id,
        scan_type=body.scan_type,
        engines=",".join(engines) if engines else "",
        ref_type=body.ref_type,
        ref_name=body.ref_name,
        language_override=body.language_override,
        dast_target=str(dast_target_id) if dast_target_id else "",
        dast_target_digest=_target_digest(target) if body.scan_type == "dast" else "",
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    runner = ScanRunner()
    try:
        get_executor().submit(scan.id, runner.run_scan)
    except ScanCapacityError as exc:
        scan.status = "failed"
        scan.error = "scan queue is full"
        session.add(scan)
        session.commit()
        raise HTTPException(503, "scan queue is full") from exc
    return scan


@router.get("")
def list_scans(
    response: Response,
    project_id: int | None = Query(None),
    status: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: Session = Depends(get_session),
):
    from sqlalchemy import func

    conditions = []
    if project_id:
        conditions.append(Scan.project_id == project_id)
    if status:
        conditions.append(Scan.status == status)
    total = session.exec(select(func.count()).select_from(Scan).where(*conditions)).one()
    stmt = select(Scan).order_by(Scan.id.desc())
    if conditions:
        stmt = stmt.where(*conditions)
    rows = session.exec(stmt.offset(offset).limit(limit)).all()
    response.headers["X-Total-Count"] = str(total)
    return rows


@router.get("/{scan_id}")
def get_scan(scan_id: int, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    return scan


@router.get("/{scan_id}/events")
async def scan_events(scan_id: int, session: Session = Depends(get_session)):
    """Server-Sent Events stream of live scan progress."""
    if not session.get(Scan, scan_id):
        raise HTTPException(404, "scan not found")

    async def stream():
        last_seq = 0
        deadline = time.monotonic() + SSE_MAX_SECONDS
        while time.monotonic() < deadline:
            evs, last_seq = event_bus.events_since(scan_id, last_seq)
            for _seq, etype, data in evs:
                yield sse_format(etype, data)
            with Session(engine) as s:
                scan = s.get(Scan, scan_id)
            if scan is None:
                # scan row vanished (deleted); end the stream instead of
                # spinning forever
                yield sse_format("__end__", {"status": "unknown"})
                return
            if scan.status in ("succeeded", "failed", "aborted"):
                yield sse_format("__end__", {"status": scan.status})
                return
            await asyncio.sleep(1)
        yield sse_format("__end__", {"status": "timeout"})

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
