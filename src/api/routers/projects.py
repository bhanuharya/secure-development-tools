from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from src.api.database import Project, Target, get_session
from src.config import ConfigurationError
from src.integrations.bitbucket_client import BitbucketClient, BitbucketError
from src.util.dastgate import (
    require_dast_control_auth,
    validate_auth_mode,
    validate_dast_auth_fields,
    validate_dast_context,
    validate_dast_url,
)
from src.util.secretbox import encrypt_secret

router = APIRouter(prefix="/api/projects", tags=["projects"])


class ProjectCreate(BaseModel):
    workspace: str = Field(min_length=1)
    repo_slug: str = Field(min_length=1)
    name: str = ""


class TargetCreate(BaseModel):
    project_id: int
    name: str = ""
    url: str = Field(min_length=1)
    # Unknown targets default to production: an omitted flag must never
    # silently become a non-production target that approves without ack.
    is_production: bool = True
    auth_mode: str = "none"  # none | form | context_file
    login_url: str = ""
    username_field: str = ""
    password_field: str = ""
    auth_username: str = ""
    auth_password: str = ""
    context_file_path: str = ""


class TargetUpdate(BaseModel):
    url: str | None = None
    name: str | None = None
    is_production: bool | None = None
    auth_mode: str | None = None
    login_url: str | None = None
    username_field: str | None = None
    password_field: str | None = None
    auth_username: str | None = None
    auth_password: str | None = None
    context_file_path: str | None = None


@router.post("")
def create_project(body: ProjectCreate, session: Session = Depends(get_session)):
    slug = body.repo_slug
    repo_name = ""
    default_branch = "main"
    try:
        bb = BitbucketClient()
    except BitbucketError:
        bb = None
    if bb is not None:
        try:
            repo = bb.get_repo(body.workspace, slug)
            default_branch = (repo.get("mainbranch") or {}).get("name") or "main"
            repo_name = repo.get("name") or ""
        except BitbucketError as exc:
            raise HTTPException(400, f"Could not verify repo in Bitbucket: {exc}") from exc

    existing = session.exec(
        select(Project).where(Project.workspace == body.workspace, Project.repo_slug == slug)
    ).first()
    if existing:
        return existing
    project = Project(
        name=body.name or repo_name or slug,
        workspace=body.workspace,
        repo_slug=slug,
        default_branch=default_branch,
    )
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


@router.get("")
def list_projects(session: Session = Depends(get_session)):
    return session.exec(select(Project).order_by(Project.name)).all()


@router.get("/{project_id}")
def get_project(project_id: int, session: Session = Depends(get_session)):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(404, "project not found")
    targets = session.exec(select(Target).where(Target.project_id == project_id)).all()
    return {**project.model_dump(), "targets": [_mask(target) for target in targets]}


@router.post("/{project_id}/targets")
def create_target(project_id: int, body: TargetCreate, session: Session = Depends(get_session)):
    if not session.get(Project, project_id):
        raise HTTPException(404, "project not found")
    try:
        require_dast_control_auth()
    except ValueError as exc:
        raise HTTPException(403, str(exc)) from exc
    if body.is_production is False:
        raise HTTPException(
            400,
            "is_production cannot be lowered by the caller; targets require trusted operator classification",
        )
    try:
        validate_dast_url(body.url)
        validate_auth_mode(body.auth_mode)
        validate_dast_auth_fields(
            body.auth_mode,
            body.login_url,
            body.context_file_path,
            body.username_field,
            body.password_field,
        )
        if body.login_url:
            validate_dast_url(body.login_url)
        if body.context_file_path:
            body.context_file_path = validate_dast_context(body.context_file_path)
        password = encrypt_secret(body.auth_password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ConfigurationError as exc:
        raise HTTPException(400, str(exc)) from exc
    data = body.model_dump(exclude={"auth_password", "project_id"})
    target = Target(project_id=project_id, auth_password=password, **data)
    session.add(target)
    session.commit()
    session.refresh(target)
    return _mask(target)


@router.patch("/targets/{target_id}")
def update_target(target_id: int, body: TargetUpdate, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(404, "target not found")
    try:
        require_dast_control_auth()
    except ValueError as exc:
        raise HTTPException(403, str(exc)) from exc
    data = body.model_dump(exclude_unset=True)
    # Validate every security-sensitive field whenever any of them changes:
    # auth_mode, login_url, and context_file_path are always rechecked
    # together so a login/context update can never bypass validation.
    sensitive = {"auth_mode", "login_url", "context_file_path", "url",
                 "is_production", "username_field", "password_field",
                 "auth_username", "auth_password"}
    if data.get("auth_password"):
        try:
            data["auth_password"] = encrypt_secret(data["auth_password"])
        except ConfigurationError as exc:
            raise HTTPException(400, str(exc)) from exc
    if any(k in data for k in ("auth_mode", "login_url", "context_file_path", "url")):
        try:
            eff_mode = data.get("auth_mode", target.auth_mode)
            eff_login = data.get("login_url", target.login_url)
            eff_ctx = data.get("context_file_path", target.context_file_path)
            validate_auth_mode(eff_mode)
            validate_dast_auth_fields(
                eff_mode,
                eff_login,
                eff_ctx,
                data.get("username_field", target.username_field),
                data.get("password_field", target.password_field),
            )
            if "url" in data:
                validate_dast_url(data["url"])
            if "login_url" in data and data["login_url"]:
                validate_dast_url(data["login_url"])
            if "context_file_path" in data and data["context_file_path"]:
                data["context_file_path"] = validate_dast_context(data["context_file_path"])
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    if "is_production" in data:
        if data["is_production"] is False:
            raise HTTPException(
                400,
                "is_production cannot be lowered by the caller; targets require trusted operator classification",
            )
        try:
            validate_auth_mode(data.get("auth_mode", target.auth_mode))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    for k, v in data.items():
        setattr(target, k, v)
    # Invalidate approval on security-sensitive changes: a new URL, auth
    # mode, credential, context, or production flag requires fresh approval.
    # Conservatively revoke whenever a sensitive field was present in the
    # request (approval is cheap, active scans are not).
    if any(k in data for k in sensitive):
        target.pre_approved = False
        target.production_confirmed = False
    session.add(target)
    session.commit()
    session.refresh(target)
    return _mask(target)


def _mask(target: Target) -> dict:
    data = target.model_dump()
    data["auth_password"] = "***" if data.get("auth_password") else ""
    return data
