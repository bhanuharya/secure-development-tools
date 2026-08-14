from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlmodel import Session, select

from src.api.database import Finding, Project, Scan, get_session
from src.config import REPORT_DIR
from src.reporting.pdf_report import PdfReportBuilder

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["reports"])


class ProjectReportRequest(BaseModel):
    pr_only: bool = False


def _findings_of(session: Session, scan_id: int) -> list[Finding]:
    return list(session.exec(select(Finding).where(Finding.scan_id == scan_id)).all())


@router.post("/scan/{scan_id}")
def generate_scan_report(scan_id: int, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    project = session.get(Project, scan.project_id)
    findings = _findings_of(session, scan_id)
    out = REPORT_DIR / f"scan-{scan_id}.pdf"
    builder = PdfReportBuilder(str(out))
    builder.build_scan(scan, project, findings)
    builder.save()
    return {"scan_id": scan_id, "file": f"/api/reports/scan/{scan_id}/download", "count": len(findings)}


@router.post("/project/{project_id}")
def generate_project_report(
    project_id: int,
    body: ProjectReportRequest,
    session: Session = Depends(get_session),
):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(404, "project not found")
    findings = list(
        session.exec(
            select(Finding).where(Finding.project_id == project_id)
        ).all()
    )
    if body.pr_only:
        findings = [f for f in findings if f.in_pr_diff]
    out = REPORT_DIR / f"project-{project_id}.pdf"
    builder = PdfReportBuilder(str(out))
    builder.build_project(project, findings, pr_only=body.pr_only)
    builder.save()
    return {
        "project_id": project_id,
        "file": f"/api/reports/project/{project_id}/download",
        "count": len(findings),
        "pr_only": body.pr_only,
    }


@router.get("/scan/{scan_id}/download")
def download_scan_report(scan_id: int):
    path = REPORT_DIR / f"scan-{scan_id}.pdf"
    if not path.exists():
        raise HTTPException(404, "report not generated yet")
    return FileResponse(path, media_type="application/pdf", filename=f"scan-{scan_id}.pdf")


@router.get("/project/{project_id}/download")
def download_project_report(project_id: int):
    path = REPORT_DIR / f"project-{project_id}.pdf"
    if not path.exists():
        raise HTTPException(404, "report not generated yet")
    return FileResponse(path, media_type="application/pdf", filename=f"project-{project_id}.pdf")
