from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import event
from sqlmodel import Field, Session, SQLModel, create_engine

from src.config import DATABASE_URL


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Project(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    workspace: str = Field(index=True)
    repo_slug: str = Field(index=True)
    default_branch: str = "main"
    languages: str = Field(default="", description="comma-separated auto-detected languages")
    created_at: datetime = Field(default_factory=utcnow)


class Scan(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id", index=True)
    scan_type: str = Field(default="sast", description="sast | sca | secrets | dast")
    engines: str = Field(default="", description="comma-separated engine names")
    ref_type: str = Field(default="branch", description="branch | pr")
    ref_name: str = Field(default="", description="branch name or PR id")
    commit_sha: str = Field(default="")
    language_override: str = Field(default="")
    dast_target: str = Field(default="")
    status: str = Field(default="pending", index=True,
                        description="pending|running|succeeded|failed|aborted")
    engine_statuses: str = Field(default="{}", description="json engine -> state")
    summary: str = Field(default="{}", description="json counts")
    progress_note: str = Field(default="")
    error: str = Field(default="")
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = Field(default=None)
    finished_at: datetime | None = Field(default=None)


class Finding(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    project_id: int = Field(foreign_key="project.id", index=True)
    tool: str = Field(index=True)
    source_type: str = Field(default="sast", description="sast|sca|secrets|dast")
    rule_id: str = Field(default="", index=True)
    severity: str = Field(default="info", index=True)
    cwe: str = Field(default="")
    file_path: str = Field(default="")
    line_start: int | None = Field(default=None)
    line_end: int | None = Field(default=None)
    snippet: str = Field(default="")
    description: str = Field(default="")
    remediation: str = Field(default="")
    fingerprint: str = Field(index=True)
    status: str = Field(default="new", index=True,
                        description="new|triaged|fixed|false_positive|accepted_risk")
    triage_reason: str = Field(default="")
    in_pr_diff: bool = Field(default=False, index=True)
    evidence: str = Field(default="{}", description="versioned JSON evidence")
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)


class FindingAuditEvent(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id", index=True)
    from_status: str = Field(default="")
    to_status: str = Field(default="")
    reason: str = Field(default="")
    created_at: datetime = Field(default_factory=utcnow)


class Target(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id", index=True)
    name: str = Field(default="", description="friendly label")
    url: str = Field(default="")
    is_production: bool = Field(default=False)
    pre_approved: bool = Field(default=False)
    auth_mode: str = Field(default="none", description="none|form|context_file")
    login_url: str = Field(default="")
    username_field: str = Field(default="")
    password_field: str = Field(default="")
    auth_username: str = Field(default="")
    auth_password: str = Field(default="", description="stored; never returned by the API")
    context_file_path: str = Field(default="", description="raw ZAP context file path (escape hatch)")
    created_at: datetime = Field(default_factory=utcnow)


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)
SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


def init_db() -> None:
    SQLModel.metadata.create_all(engine)
    _migrate()


def _migrate() -> None:
    """Idempotent, framework-free schema migrations.

    The project has no Alembic setup yet; add columns here with a guard so the
    operation is a no-op on databases that already have them.
    """
    if not DATABASE_URL.startswith("sqlite"):
        return
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "finding" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("finding")}
    if "evidence" not in columns:
        from sqlalchemy.exc import OperationalError

        try:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE finding ADD COLUMN evidence VARCHAR DEFAULT '{}'")
                )
        except OperationalError:
            # Two workers can observe the column as missing concurrently. Only
            # suppress the race when another worker actually added it.
            if "evidence" not in {c["name"] for c in inspect(engine).get_columns("finding")}:
                raise


def recover_incomplete_scans() -> int:
    """Fail scans that cannot survive a process restart."""
    from sqlmodel import select

    recovered = 0
    with Session(engine) as session:
        rows = session.exec(select(Scan).where(Scan.status.in_(["pending", "running"]))).all()
        for scan in rows:
            scan.status = "failed"
            scan.error = "scan interrupted by service restart"
            scan.finished_at = utcnow()
            session.add(scan)
            recovered += 1
        if recovered:
            session.commit()
    return recovered


# Pragmas for concurrent access (WAL) — read-heavy dashboard + writer thread.
@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    if DATABASE_URL.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()
