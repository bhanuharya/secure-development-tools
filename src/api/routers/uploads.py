from __future__ import annotations

import io
import logging
import shutil
import threading
import uuid
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlmodel import Session

from src.api.database import Project, Scan, Target, get_session
from src.config import (
    MAX_COMPRESSION_RATIO,
    MAX_EXPANDED_BYTES,
    MAX_FILES,
    MAX_FILE_BYTES,
    MAX_UPLOAD_BYTES,
    SCAN_WORK_DIR,
)
from src.integrations.bitbucket_client import safe_slug
from src.scanners.orchestrator import ALL_ENGINES, ScanRunner

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/uploads", tags=["uploads"])

VALID_SOURCE_TYPES = {"full", "sast", "sca", "secrets"}
DAST_SAFETY_MSG = "target is not pre-approved: confirm to run active scan"

# preset name -> (scan_type, default engines)
PRESETS: dict[str, tuple[str, list[str]]] = {
    "full": ("full", ["bandit", "opengrep", "trivy", "gitleaks"]),
    "sast": ("sast", ["bandit", "opengrep"]),
    "dependencies": ("sca", ["trivy"]),
    "secrets": ("secrets", ["gitleaks"]),
}

# engine names allowed per scan type (zap handled separately as DAST-only)
ENGINE_COMPAT: dict[str, set[str]] = {
    "full": {"bandit", "opengrep", "trivy", "gitleaks"},
    "sast": {"bandit", "opengrep"},
    "sca": {"trivy"},
    "secrets": {"gitleaks"},
}

READY_MARKER = ".ready"


def _standalone_project(session: Session, name: str) -> Project:
    """Create a manual/uploaded project that is NOT backed by a Bitbucket repo.

    workspace is left empty so callers (and the UI) can detect it as a
    standalone project. repo_slug gets a random suffix so repeated uploads with
    the same name stay distinct.
    """
    base = (name or "upload").strip() or "upload"
    slug = safe_slug(base) or "upload"
    project = Project(name=base, workspace="", repo_slug=f"{slug}-{uuid.uuid4().hex[:6]}", default_branch="upload")
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


def _validate_zip(raw: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)):
            pass
    except (zipfile.BadZipFile, OSError) as exc:
        raise HTTPException(400, "invalid zip archive") from exc


def _member_type(member: zipfile.ZipInfo) -> str:
    """Classify a ZIP member: 'dir' | 'file' | 'symlink' | 'special'."""
    if member.is_dir():
        return "dir"
    mode = (member.external_attr >> 16) & 0o170000
    if mode == 0o120000:
        return "symlink"
    if mode in (0o040000, 0o020000, 0o060000, 0o140000):  # dir, char, block, fifo
        return "special" if mode != 0o040000 else "dir"
    if mode == 0o100000 or mode == 0:
        return "file"
    return "special"


def _strip_common_root(names: list[str]) -> list[str]:
    """Strip a single GitHub/GitLab/Bitbucket top-level wrapper directory.

    Repository exports typically wrap everything in one directory
    (``repo-main/...``). If every member shares a single top-level directory,
    that prefix is removed so findings report repository-relative paths.
    """
    files = [n for n in names if n and not n.endswith("/")]
    if not files:
        return names
    tops = {n.split("/", 1)[0] for n in files}
    if len(tops) == 1:
        root = tops.pop()
        if all("/" in n for n in files):
            return [n[len(root) + 1:] for n in names]
    return names


def _plan_extraction(zf: zipfile.ZipFile) -> list[tuple[zipfile.ZipInfo, str]]:
    """Validate the archive and return (member, relative_target) pairs."""
    members = zf.infolist()
    if not members:
        raise HTTPException(400, "zip archive is empty")

    # reject unsafe names first
    for m in members:
        name = m.filename.replace("\\", "/")
        if name.startswith("/") or "\x00" in name:
            raise HTTPException(400, f"unsafe archive entry: {m.filename!r}")
        if any(part in ("..",) for part in name.split("/")):
            raise HTTPException(400, "archive contains a path-traversal entry")

    file_members = [m for m in members if _member_type(m) == "file"]
    for m in members:
        if _member_type(m) in ("symlink", "special"):
            raise HTTPException(400, f"unsupported archive entry type: {m.filename!r}")

    if len(file_members) > MAX_FILES:
        raise HTTPException(413, f"archive has too many files (max {MAX_FILES})")

    total = sum(m.file_size for m in file_members)
    if total > MAX_EXPANDED_BYTES:
        raise HTTPException(413, "archive expands beyond the allowed size")

    for m in file_members:
        if m.file_size > MAX_FILE_BYTES:
            raise HTTPException(413, f"file too large: {m.filename!r}")
        if m.file_size > 0 and m.compress_size > 0:
            ratio = m.file_size / m.compress_size
            if ratio > MAX_COMPRESSION_RATIO:
                raise HTTPException(413, f"archive entry has an excessive compression ratio: {m.filename!r}")

    stripped = _strip_common_root([m.filename for m in members])
    name_map = {m.filename: stripped[i] for i, m in enumerate(members)}
    return [(m, name_map[m.filename]) for m in file_members]


def _extract_zip(raw: bytes, workdir: Path) -> None:
    root = workdir.resolve()
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        plan = _plan_extraction(zf)
        for member, rel in plan:
            if not rel or rel.endswith("/"):
                continue
            target = (workdir / rel).resolve()
            if not target.is_relative_to(root):
                raise HTTPException(400, f"archive entry escapes the workspace: {member.filename!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
    (workdir / READY_MARKER).write_text("ok", encoding="utf-8")


def _launch(scan: Scan) -> None:
    runner = ScanRunner()
    threading.Thread(target=runner.run_scan, args=(scan.id,), daemon=True).start()


@router.post("/scan")
async def upload_repo_scan(
    file: UploadFile = File(...),
    name: str = Form(""),
    scan_type: str = Form("sast"),
    engines: list[str] = Form(default=[]),
    preset: str = Form(""),
    language_override: str = Form(""),
    session: Session = Depends(get_session),
):
    """Scan a manually uploaded repository archive (full / SAST / SCA / secrets).

    The archive is unzipped into the scan workdir and handed to the normal
    engine machinery. No Bitbucket integration is required.
    """
    engines = [e for e in engines if e]

    if preset:
        if preset not in PRESETS and preset != "custom":
            raise HTTPException(400, f"unknown preset: {preset}")
        if preset == "custom":
            if not engines:
                raise HTTPException(400, "custom preset requires at least one engine")
        else:
            scan_type, engines = PRESETS[preset]

    if scan_type not in VALID_SOURCE_TYPES:
        raise HTTPException(400, f"scan_type must be one of {sorted(VALID_SOURCE_TYPES)}")

    if not engines:
        engines = list(ENGINE_COMPAT.get(scan_type, []))
        if not engines:
            raise HTTPException(400, "select at least one engine")

    unknown = [e for e in engines if e not in ALL_ENGINES]
    if unknown:
        raise HTTPException(400, f"unknown engines: {unknown}")
    if "zap" in engines:
        raise HTTPException(400, "zap is only available for DAST scans")
    incompatible = [e for e in engines if e not in ENGINE_COMPAT.get(scan_type, set())]
    if incompatible:
        raise HTTPException(400, f"engines {incompatible} are not valid for scan_type={scan_type}")

    filename = file.filename or ""
    if not filename.lower().endswith(".zip"):
        raise HTTPException(400, "please upload a .zip archive")
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"upload exceeds the maximum size of {MAX_UPLOAD_BYTES} bytes")
    _validate_zip(raw)

    project = _standalone_project(session, name or Path(filename).stem)
    scan = Scan(
        project_id=project.id,
        scan_type=scan_type,
        engines=",".join(engines),
        ref_type="upload",
        ref_name=project.name,
        language_override=language_override,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    workdir = SCAN_WORK_DIR / f"p{project.id}-s{scan.id}"
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        _extract_zip(raw, workdir)
    except Exception:
        # roll back the half-created project/scan so no orphan records remain
        shutil.rmtree(workdir, ignore_errors=True)
        session.delete(scan)
        session.delete(project)
        session.commit()
        raise

    _launch(scan)
    return scan


class DirectDastCreate(BaseModel):
    name: str = ""
    url: str = Field(min_length=1)
    is_production: bool = False
    pre_approved: bool = False
    auth_mode: str = "none"  # none | form | context_file
    login_url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    auth_username: str = ""
    auth_password: str = ""
    context_file_path: str = ""
    dast_confirmed: bool = False


@router.post("/dast")
def create_direct_dast(body: DirectDastCreate, session: Session = Depends(get_session)):
    """Run DAST directly against a target URL, without a Bitbucket project.

    The target is stored as a normal Target bound to a standalone project so
    the existing ZAP machinery and DAST safety gates are reused unchanged.
    """
    if body.is_production and not body.dast_confirmed:
        raise HTTPException(400, "target is production: you must confirm active scanning explicitly")
    if not body.pre_approved and not body.dast_confirmed:
        raise HTTPException(400, DAST_SAFETY_MSG)

    project = _standalone_project(session, body.name or body.url)
    target = Target(
        project_id=project.id,
        name=body.name or body.url,
        url=body.url,
        is_production=body.is_production,
        pre_approved=body.pre_approved,
        auth_mode=body.auth_mode,
        login_url=body.login_url,
        username_field=body.username_field,
        password_field=body.password_field,
        auth_username=body.auth_username,
        auth_password=body.auth_password,
        context_file_path=body.context_file_path,
    )
    session.add(target)
    session.commit()
    session.refresh(target)

    scan = Scan(
        project_id=project.id,
        scan_type="dast",
        engines="zap",
        ref_type="upload",
        ref_name=project.name,
        dast_target=str(target.id),
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    _launch(scan)
    return scan
