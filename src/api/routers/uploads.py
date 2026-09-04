from __future__ import annotations

import io
import logging
import shutil
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
    ConfigurationError,
)
from src.integrations.bitbucket_client import safe_slug
from src.api.routers.projects import _mask
from src.scanners.executor import ScanCapacityError, get_executor
from src.util.dastgate import validate_dast_context, validate_dast_url
from src.util.secretbox import encrypt_secret
from src.scanners.orchestrator import ALL_ENGINES, ScanRunner

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/uploads", tags=["uploads"])

VALID_SOURCE_TYPES = {"full", "sast", "sca", "secrets", "iac"}

# preset name -> (scan_type, default engines)
PRESETS: dict[str, tuple[str, list[str]]] = {
    "full": ("full", ["bandit", "opengrep", "trivy", "gitleaks", "checkov", "osv-scanner"]),
    "sast": ("sast", ["bandit", "opengrep"]),
    "dependencies": ("sca", ["trivy", "osv-scanner"]),
    "secrets": ("secrets", ["gitleaks"]),
    "iac": ("iac", ["checkov", "trivy"]),
}

# engine names allowed per scan type (zap handled separately as DAST-only).
# Ordered tuples keep default engine selection deterministic (registry order).
ENGINE_COMPAT: dict[str, tuple[str, ...]] = {
    "full": ("bandit", "opengrep", "trivy", "gitleaks", "checkov", "osv-scanner"),
    "sast": ("bandit", "opengrep"),
    "sca": ("trivy", "osv-scanner"),
    "secrets": ("gitleaks",),
    "iac": ("checkov", "trivy"),
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


def _launch(scan_id: int) -> None:
    runner = ScanRunner()
    get_executor().submit(scan_id, runner.run_scan)


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

    try:
        _launch(scan.id)
    except ScanCapacityError as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        session.delete(scan)
        session.delete(project)
        session.commit()
        raise HTTPException(503, "scan queue is full") from exc
    return scan


class DirectDastCreate(BaseModel):
    name: str = ""
    url: str = Field(min_length=1)
    is_production: bool = False
    auth_mode: str = "none"  # none | form | context_file
    login_url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    auth_username: str = ""
    auth_password: str = ""
    context_file_path: str = ""


@router.post("/dast")
def create_direct_dast(body: DirectDastCreate, session: Session = Depends(get_session)):
    """Register a DAST target URL, without a Bitbucket project.

    This only CREATES the target — it never launches anything. The target must
    then be approved via ``POST /api/targets/{id}/approve`` (an audited,
    server-side decision) before a scan can be started against it, and the scan
    itself is requested through ``POST /api/scans``.
    """
    try:
        validate_dast_url(body.url)
        if body.login_url:
            validate_dast_url(body.login_url)
        if body.context_file_path:
            body.context_file_path = validate_dast_context(body.context_file_path)
        password = encrypt_secret(body.auth_password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ConfigurationError as exc:
        raise HTTPException(400, str(exc)) from exc

    project = _standalone_project(session, body.name or body.url)
    target = Target(
        project_id=project.id,
        name=body.name or body.url,
        url=body.url,
        is_production=body.is_production,
        auth_mode=body.auth_mode,
        login_url=body.login_url,
        username_field=body.username_field,
        password_field=body.password_field,
        auth_username=body.auth_username,
        auth_password=password,
        context_file_path=body.context_file_path,
    )
    session.add(target)
    session.commit()
    session.refresh(target)
    data = _mask(target)
    data["project_id"] = project.id
    data["next_step"] = (
        f"approve via POST /api/targets/{target.id}/approve, then scan via "
        f"POST /api/scans with scan_type=dast and dast_target={target.id}"
    )
    return data


class FolderScanCreate(BaseModel):
    path: str
    name: str = ""
    scan_type: str = "sast"  # full|sast|sca|secrets|iac
    engines: list[str] = Field(default=[])
    preset: str = ""
    language_override: str = ""


def _validate_local_root(path: Path) -> Path:
    """Resolve the source path and ensure it stays within an allowlisted root.

    Fails closed when no roots are configured, so the folder-scan endpoint can
    never be used to read arbitrary host paths. Roots are read at request time
    (like auth) so the platform can be reconfigured by restarting with new env.
    """
    import os

    from src.config import LOCAL_SCAN_ROOTS as _CONFIG_ROOTS

    roots = tuple(
        p for p in os.getenv("SCP_LOCAL_SCAN_ROOTS", "").split(os.pathsep) if p
    ) or _CONFIG_ROOTS
    if not roots:
        raise HTTPException(
            400,
            "local folder scanning is disabled: set SCP_LOCAL_SCAN_ROOTS to "
            "the directories you want to allow",
        )
    resolved = path.expanduser().resolve()
    if not resolved.is_dir():
        raise HTTPException(400, f"path is not a directory: {path}")
    root_paths = [Path(r).expanduser().resolve() for r in roots]
    if not any(resolved.is_relative_to(root) for root in root_paths):
        raise HTTPException(403, "path is outside the configured scan roots")
    return resolved


def _stage_folder(source: Path, workdir: Path) -> None:
    """Descriptor-first copy: no symlinks, races, special files, or size bypasses."""
    import os
    import stat
    root = workdir.resolve()
    count = total = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)

    def walk(fd: int, rel: Path) -> None:
        nonlocal count, total
        for entry in os.scandir(fd):
            child_rel = rel / entry.name
            if entry.name in (".", ".."):
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    child = os.open(entry.name, flags | getattr(os, "O_DIRECTORY", 0), dir_fd=fd)
                    try:
                        (workdir / child_rel).mkdir(parents=True, exist_ok=True)
                        walk(child, child_rel)
                    finally:
                        os.close(child)
                    continue
                child = os.open(entry.name, flags, dir_fd=fd)
                try:
                    st = os.fstat(child)
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    count += 1
                    if count > MAX_FILES:
                        raise HTTPException(413, f"folder has too many files (max {MAX_FILES})")
                    if st.st_size > MAX_FILE_BYTES or total + st.st_size > MAX_EXPANDED_BYTES:
                        raise HTTPException(413, "folder exceeds the allowed size")
                    dest = (workdir / child_rel).resolve()
                    if not dest.is_relative_to(root):
                        raise HTTPException(400, f"path escapes the workspace: {child_rel}")
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with open(dest, "xb") as out:
                        copied = 0
                        while True:
                            chunk = os.read(child, min(1024 * 1024, MAX_EXPANDED_BYTES - total - copied + 1))
                            if not chunk:
                                break
                            copied += len(chunk)
                            if copied > MAX_FILE_BYTES or total + copied > MAX_EXPANDED_BYTES:
                                raise HTTPException(413, "folder exceeds the allowed size")
                            out.write(chunk)
                    total += copied
                finally:
                    os.close(child)
            except (FileNotFoundError, OSError) as exc:
                # A symlink or a concurrent replacement is intentionally not
                # followed; skip it rather than turning a safe omission into
                # an intake failure.
                if getattr(exc, "errno", None) not in (2, 40):
                    raise
                continue
    source_fd = os.open(source, flags | getattr(os, "O_DIRECTORY", 0))
    try:
        walk(source_fd, Path())
    finally:
        os.close(source_fd)
    (workdir / READY_MARKER).write_text("ok", encoding="utf-8")


@router.post("/folder")
def upload_folder_scan(body: FolderScanCreate, session: Session = Depends(get_session)):
    """Scan a local folder on the host.

    The folder must live under an allowlisted root (SCP_LOCAL_SCAN_ROOTS). It is
    copied into the scan workdir and handed to the normal engine machinery.
    """
    engines = [e for e in body.engines if e]

    if body.preset:
        if body.preset not in PRESETS and body.preset != "custom":
            raise HTTPException(400, f"unknown preset: {body.preset}")
        if body.preset == "custom":
            if not engines:
                raise HTTPException(400, "custom preset requires at least one engine")
        else:
            body.scan_type, engines = PRESETS[body.preset]

    if body.scan_type not in VALID_SOURCE_TYPES:
        raise HTTPException(400, f"scan_type must be one of {sorted(VALID_SOURCE_TYPES)}")

    if not engines:
        engines = list(ENGINE_COMPAT.get(body.scan_type, []))
        if not engines:
            raise HTTPException(400, "select at least one engine")

    unknown = [e for e in engines if e not in ALL_ENGINES]
    if unknown:
        raise HTTPException(400, f"unknown engines: {unknown}")
    if "zap" in engines:
        raise HTTPException(400, "zap is only available for DAST scans")
    incompatible = [e for e in engines if e not in ENGINE_COMPAT.get(body.scan_type, set())]
    if incompatible:
        raise HTTPException(400, f"engines {incompatible} are not valid for scan_type={body.scan_type}")

    source = _validate_local_root(Path(body.path))

    project = _standalone_project(session, body.name or source.name or "folder")
    scan = Scan(
        project_id=project.id,
        scan_type=body.scan_type,
        engines=",".join(engines),
        ref_type="folder",
        ref_name=project.name,
        language_override=body.language_override,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    workdir = SCAN_WORK_DIR / f"p{project.id}-s{scan.id}"
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        _stage_folder(source, workdir)
    except Exception:
        shutil.rmtree(workdir, ignore_errors=True)
        session.delete(scan)
        session.delete(project)
        session.commit()
        raise

    try:
        _launch(scan.id)
    except ScanCapacityError as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        session.delete(scan)
        session.delete(project)
        session.commit()
        raise HTTPException(503, "scan queue is full") from exc
    return scan
