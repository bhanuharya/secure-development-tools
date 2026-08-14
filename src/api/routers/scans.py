from __future__ import annotations

import asyncio
import logging
import threading

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from src.api.database import Project, Scan, Target, engine, get_session
from src.api.events import event_bus, sse_format
from src.scanners.orchestrator import ALL_ENGINES, ScanRunner

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["scans"])


class ScanCreate(BaseModel):
    project_id: int
    scan_type: str = Field(default="sast", pattern="^(sast|sca|secrets|dast)$")
    ref_type: str = Field(default="branch", pattern="^(branch|pr)$")
    ref_name: str = Field(default="")
    engines: list[str] = Field(default_factory=list)
    language_override: str = ""
    dast_target: int | None = None
    dast_confirmed: bool = False


@router.post("")
def create_scan(body: ScanCreate, session: Session = Depends(get_session)):
    project = session.get(Project, body.project_id)
    if not project:
        raise HTTPException(404, "project not found")

    # Uploaded (standalone) projects have no Bitbucket repository to clone.
    # Reject generic branch/PR rescans so the orchestrator never tries to hit
    # Bitbucket with an empty workspace.
    if project.workspace == "" and body.ref_type in ("branch", "pr"):
        raise HTTPException(
            400,
            "uploaded projects cannot be rescanned as branch/PR; upload a new ZIP to scan a new snapshot",
        )

    if body.ref_type == "branch" and not body.ref_name:
        body.ref_name = project.default_branch

    engines = body.engines or []
    if engines:
        unknown = [e for e in engines if e not in ALL_ENGINES]
        if unknown:
            raise HTTPException(400, f"unknown engines: {unknown}")

    # DAST safety gate: pre-approved non-prod target, or explicit override confirmation.
    dast_target_id = body.dast_target
    if body.scan_type == "dast":
        if dast_target_id is None:
            raise HTTPException(400, "dast scans require a configured target")
        target = session.get(Target, dast_target_id)
        if not target or target.project_id != body.project_id:
            raise HTTPException(404, "target not found for this project")
        if target.is_production and not body.dast_confirmed:
            raise HTTPException(400, "target is production: you must confirm active scanning explicitly")
        if not target.pre_approved and not body.dast_confirmed:
            raise HTTPException(400, "target is not pre-approved: confirm to run active scan")

    scan = Scan(
        project_id=body.project_id,
        scan_type=body.scan_type,
        engines=",".join(engines) if engines else "",
        ref_type=body.ref_type,
        ref_name=body.ref_name,
        language_override=body.language_override,
        dast_target=str(dast_target_id) if dast_target_id else "",
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    runner = ScanRunner()
    threading.Thread(target=runner.run_scan, args=(scan.id,), daemon=True).start()
    return scan


@router.get("")
def list_scans(
    project_id: int | None = Query(None),
    status: str | None = Query(None),
    session: Session = Depends(get_session),
):
    stmt = select(Scan).order_by(Scan.id.desc())
    if project_id:
        stmt = stmt.where(Scan.project_id == project_id)
    if status:
        stmt = stmt.where(Scan.status == status)
    return session.exec(stmt).all()


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
        while True:
            evs, last_seq = event_bus.events_since(scan_id, last_seq)
            for _seq, etype, data in evs:
                yield sse_format(etype, data)
            with Session(engine) as s:
                scan = s.get(Scan, scan_id)
            if scan and scan.status in ("succeeded", "failed", "aborted"):
                yield sse_format("__end__", {"status": scan.status})
                return
            await asyncio.sleep(1)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
