from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Index, UniqueConstraint, event, text
from sqlmodel import Field, Session, SQLModel, create_engine

from src.config import DATABASE_URL


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


VERDICTS = ("unreviewed", "true_positive", "false_positive", "accepted_risk", "needs_context")

# The pre-fleet UI and API only understand `status`, so it stays derived from
# the review fields rather than being maintained by hand. A resolved finding is
# "fixed" whatever the verdict says.
_STATUS_BY_VERDICT = {
    "unreviewed": "new",
    "true_positive": "triaged",
    "needs_context": "triaged",
    "false_positive": "false_positive",
    "accepted_risk": "accepted_risk",
}


def derived_status(finding: "Finding") -> str:
    """The legacy status value that matches a finding's verdict and lifecycle."""
    if finding.lifecycle == "resolved":
        return "fixed"
    return _STATUS_BY_VERDICT.get(finding.verdict, "new")


class Project(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    workspace: str = Field(index=True)
    repo_slug: str = Field(index=True)
    default_branch: str = "main"
    languages: str = Field(default="", description="comma-separated auto-detected languages")
    created_at: datetime = Field(default_factory=utcnow)

    # One project per repository: a second row for the same slug would split its
    # scans, findings and baselines across two identities.
    __table_args__ = (
        Index("ix_project_workspace_repo", "workspace", "repo_slug", unique=True),
    )


class Scan(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id", index=True)
    scan_type: str = Field(default="sast", description="sast | sca | secrets | dast")
    engines: str = Field(default="", description="comma-separated engine names")
    ref_type: str = Field(default="branch", description="branch | pr")
    ref_name: str = Field(default="", description="branch name or PR id")
    commit_sha: str = Field(default="")
    run_id: str = Field(default="", description="runId of the canonical report; the fleet ingest idempotency key")
    # When the scan itself ran, read off the report. Ingestion order (Scan.id) is
    # not scan order: importing last month's run must not rewrite today's state.
    scan_time: datetime = Field(default_factory=utcnow, index=True,
                                description="report generatedAt, else the record's completedAt, else ingest time")
    language_override: str = Field(default="")
    dast_target: str = Field(default="")
    dast_target_digest: str = Field(default="")
    # A scan only proves the absence of a finding when the same rules and policy
    # were in force; '' means the run manifest attested to neither.
    config_digest: str = Field(default="", description="run-manifest.json configDigest")
    policy_digest: str = Field(default="", description="run-manifest.json policyDigest")
    status: str = Field(default="pending", index=True,
                        description="pending|running|succeeded|failed|aborted")
    engine_statuses: str = Field(default="{}", description="json engine -> state")
    summary: str = Field(default="{}", description="json counts")
    progress_note: str = Field(default="")
    error: str = Field(default="")
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = Field(default=None)
    finished_at: datetime | None = Field(default=None)

    # One row per (project, runId). Partial so the local dashboard, which has no
    # runId, keeps creating scans; NULL/'' rows stay outside the index.
    __table_args__ = (
        Index("ix_scan_project_run", "project_id", "run_id", unique=True,
              sqlite_where=text("run_id <> ''"), postgresql_where=text("run_id <> ''")),
    )


class Finding(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    project_id: int = Field(foreign_key="project.id", index=True)
    branch: str = Field(default="", index=True, description="branch this finding was observed on")
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
    fingerprint_version: str = Field(default="sdt-v2", description="fingerprint algorithm/version")
    status: str = Field(default="new", index=True,
                        description="new|triaged|fixed|false_positive|accepted_risk (derived, kept for old UI code)")
    verdict: str = Field(default="unreviewed", index=True,
                         description="|".join(VERDICTS))
    lifecycle: str = Field(default="open", description="open|resolved")
    baseline_state: str = Field(default="unassessed",
                                description="unassessed|new|existing against the active baseline")
    accepted_until: datetime | None = Field(default=None,
                                            description="when an accepted_risk verdict must be revisited")
    triage_reason: str = Field(default="")
    in_pr_diff: bool = Field(default=False, index=True)
    evidence: str = Field(default="{}", description="versioned JSON evidence")
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)

    # The fleet identity: one row per (project, branch, fingerprint_version,
    # fingerprint). Partial because the pre-fleet dashboard records one row per
    # scan, all on branch '', where repeating a fingerprint across scans is the
    # intended behaviour.
    __table_args__ = (
        Index("ix_finding_project_branch_fingerprint", "project_id", "branch",
              "fingerprint_version", "fingerprint", unique=True,
              sqlite_where=text("branch <> ''"), postgresql_where=text("branch <> ''")),
    )


class FindingAuditEvent(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id", index=True)
    from_status: str = Field(default="")
    to_status: str = Field(default="")
    from_verdict: str = Field(default="", description="verdict before the decision, '' for legacy rows")
    to_verdict: str = Field(default="", description="verdict the decision recorded")
    reason: str = Field(default="")
    reviewer: str = Field(default="")
    expires_at: datetime | None = Field(default=None)
    event_key: str = Field(default="", description="deterministic dedupe key set by the review service")
    created_at: datetime = Field(default_factory=utcnow)

    # Partial so legacy rows (no key) and future unmapped writes cannot collide.
    __table_args__ = (
        Index("ix_finding_audit_event_key", "event_key", unique=True,
              sqlite_where=text("event_key <> ''"), postgresql_where=text("event_key <> ''")),
    )


class Baseline(SQLModel, table=True):
    """An approved set of known findings; the newest row is the active one."""

    id: int | None = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id", index=True)
    branch: str = Field(default="", index=True)
    approved_by: str = Field(default="")
    reason: str = Field(default="")
    source_scan_id: int | None = Field(default=None)
    finding_count: int = Field(default=0)
    created_at: datetime = Field(default_factory=utcnow)


class BaselineItem(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    baseline_id: int = Field(foreign_key="baseline.id", index=True)
    fingerprint: str = Field(index=True)
    fingerprint_version: str = Field(default="sdt-v2")

    __table_args__ = (UniqueConstraint("baseline_id", "fingerprint"),)


class FindingObservation(SQLModel, table=True):
    """Which scan saw which fingerprint; absence from a scan resolves it.

    The finding row carries the current display state; the observation keeps what
    this one scan reported, so a re-observation that moves a line or changes a
    severity does not rewrite history.
    """

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    finding_id: int = Field(foreign_key="finding.id", index=True)
    severity: str = Field(default="", description="severity as this scan reported it, '' if pre-fleet")
    line_start: int | None = Field(default=None)
    line_end: int | None = Field(default=None)
    message_digest: str = Field(default="", description="first 32 hex chars of sha256(message), message redacted")

    __table_args__ = (UniqueConstraint("scan_id", "finding_id"),)


class Target(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id", index=True)
    name: str = Field(default="", description="friendly label")
    url: str = Field(default="")
    is_production: bool = Field(default=False)
    pre_approved: bool = Field(default=False)
    production_confirmed: bool = Field(
        default=False,
        description="server-side record that an operator acknowledged this "
        "production target before any active scan (set via /api/targets/{id}/approve)",
    )
    auth_mode: str = Field(default="none", description="none|form|context_file")
    login_url: str = Field(default="")
    username_field: str = Field(default="")
    password_field: str = Field(default="")
    auth_username: str = Field(default="")
    auth_password: str = Field(default="", description="encrypted at rest; never returned by the API")
    context_file_path: str = Field(default="", description="raw ZAP context file path (escape hatch)")
    created_at: datetime = Field(default_factory=utcnow)


class TargetAuditEvent(SQLModel, table=True):
    """Audit trail for target approval decisions (mirrors FindingAuditEvent)."""

    id: int | None = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    action: str = Field(description="approve | revoke")
    reason: str = Field(default="")
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


def _is_sqlite() -> bool:
    return DATABASE_URL.startswith("sqlite")


def _ddl(statement: str) -> str:
    """Spell the two types SQLite and PostgreSQL disagree about.

    Migration DDL is written once, with `{datetime}` and `{false}` tokens, so the
    same statements upgrade a PostgreSQL deployment as well as the local SQLite one.
    """
    return (statement.replace("{datetime}", "DATETIME" if _is_sqlite() else "TIMESTAMP")
                    .replace("{false}", "0" if _is_sqlite() else "FALSE"))


def _migrate() -> None:
    """Idempotent, framework-free schema migrations.

    The project has no Alembic setup yet; add columns here with a guard so the
    operation is a no-op on databases that already have them.
    """
    from sqlalchemy import inspect

    inspector = inspect(engine)
    if "finding" not in inspector.get_table_names():
        return
    if "evidence" not in {c["name"] for c in inspector.get_columns("finding")}:
        _add_column("finding", "evidence", "ALTER TABLE finding ADD COLUMN evidence VARCHAR DEFAULT '{}'")

    if "target" in inspector.get_table_names():
        target_cols = {c["name"] for c in inspector.get_columns("target")}
        if "production_confirmed" not in target_cols:
            _add_column("target", "production_confirmed",
                        "ALTER TABLE target ADD COLUMN production_confirmed BOOLEAN DEFAULT {false}")
    # Queued DAST scans bind to an immutable target/configuration digest.
    if "scan" in inspector.get_table_names():
        scan_cols = {c["name"] for c in inspector.get_columns("scan")}
        if "dast_target_digest" not in scan_cols:
            _add_column("scan", "dast_target_digest",
                        "ALTER TABLE scan ADD COLUMN dast_target_digest VARCHAR DEFAULT ''")

    _migrate_fleet_columns(inspector)


def _add_column(table: str, column: str, template: str) -> None:
    """Add one missing column, tolerating a concurrent worker that added it first."""
    from sqlalchemy import inspect as sa_inspect
    from sqlalchemy.exc import OperationalError, ProgrammingError

    try:
        with engine.begin() as conn:
            conn.execute(text(_ddl(template)))
    except (OperationalError, ProgrammingError):
        # Two workers can observe the column as missing concurrently. SQLite
        # reports that as an operational error and PostgreSQL as a programming
        # one. Only suppress the race when another worker actually added it.
        if column not in {c["name"] for c in sa_inspect(engine).get_columns(table)}:
            raise


# Fleet baseline/review model: columns and indexes added to tables that already
# exist in a deployed database. Every statement is guarded, so re-running is a
# no-op, and only `new` defaults keep old rows meaningful.
_FLEET_COLUMNS = (
    ("finding", "branch", "ALTER TABLE finding ADD COLUMN branch VARCHAR DEFAULT ''"),
    ("finding", "fingerprint_version",
     "ALTER TABLE finding ADD COLUMN fingerprint_version VARCHAR DEFAULT 'sdt-v2'"),
    ("finding", "verdict", "ALTER TABLE finding ADD COLUMN verdict VARCHAR DEFAULT 'unreviewed'"),
    ("finding", "lifecycle", "ALTER TABLE finding ADD COLUMN lifecycle VARCHAR DEFAULT 'open'"),
    ("finding", "baseline_state",
     "ALTER TABLE finding ADD COLUMN baseline_state VARCHAR DEFAULT 'unassessed'"),
    ("finding", "accepted_until", "ALTER TABLE finding ADD COLUMN accepted_until {datetime}"),
    ("findingauditevent", "reviewer",
     "ALTER TABLE findingauditevent ADD COLUMN reviewer VARCHAR DEFAULT ''"),
    ("findingauditevent", "expires_at", "ALTER TABLE findingauditevent ADD COLUMN expires_at {datetime}"),
    ("findingauditevent", "event_key",
     "ALTER TABLE findingauditevent ADD COLUMN event_key VARCHAR DEFAULT ''"),
    ("findingauditevent", "from_verdict",
     "ALTER TABLE findingauditevent ADD COLUMN from_verdict VARCHAR DEFAULT ''"),
    ("findingauditevent", "to_verdict",
     "ALTER TABLE findingauditevent ADD COLUMN to_verdict VARCHAR DEFAULT ''"),
    ("findingobservation", "severity",
     "ALTER TABLE findingobservation ADD COLUMN severity VARCHAR DEFAULT ''"),
    ("findingobservation", "line_start", "ALTER TABLE findingobservation ADD COLUMN line_start INTEGER"),
    ("findingobservation", "line_end", "ALTER TABLE findingobservation ADD COLUMN line_end INTEGER"),
    ("findingobservation", "message_digest",
     "ALTER TABLE findingobservation ADD COLUMN message_digest VARCHAR DEFAULT ''"),
    ("scan", "run_id", "ALTER TABLE scan ADD COLUMN run_id VARCHAR DEFAULT ''"),
    ("scan", "scan_time", "ALTER TABLE scan ADD COLUMN scan_time {datetime}"),
    ("scan", "config_digest", "ALTER TABLE scan ADD COLUMN config_digest VARCHAR DEFAULT ''"),
    ("scan", "policy_digest", "ALTER TABLE scan ADD COLUMN policy_digest VARCHAR DEFAULT ''"),
)

_FLEET_INDEXES = (
    ("finding", "CREATE INDEX IF NOT EXISTS ix_finding_branch ON finding (branch)"),
    ("finding", "CREATE INDEX IF NOT EXISTS ix_finding_verdict ON finding (verdict)"),
    ("scan", "CREATE INDEX IF NOT EXISTS ix_scan_scan_time ON scan (scan_time)"),
    ("scan", "CREATE UNIQUE INDEX IF NOT EXISTS ix_scan_project_run ON scan (project_id, run_id) "
             "WHERE run_id <> ''"),
    ("findingauditevent", "CREATE UNIQUE INDEX IF NOT EXISTS ix_finding_audit_event_key "
                          "ON findingauditevent (event_key) WHERE event_key <> ''"),
)

# The fleet identities, spelled the way `__table_args__` declares them so a
# database built by `create_all` already has them and this is a no-op. A deployed
# database predating them gains them here, after any rows that would collide are
# merged away.
_UNIQUE_INDEXES = (
    ("project", "ix_project_workspace_repo",
     "CREATE UNIQUE INDEX IF NOT EXISTS ix_project_workspace_repo ON project (workspace, repo_slug)"),
    ("finding", "ix_finding_project_branch_fingerprint",
     "CREATE UNIQUE INDEX IF NOT EXISTS ix_finding_project_branch_fingerprint "
     "ON finding (project_id, branch, fingerprint_version, fingerprint) WHERE branch <> ''"),
)

# The verdict rename: 'triaged' said nothing about whether the finding was real,
# which is the one thing rule precision needs to know.
_VERDICT_RENAMES = (
    ("finding", "verdict", "UPDATE finding SET verdict = 'true_positive' WHERE verdict = 'triaged'"),
    ("findingauditevent", "to_verdict",
     "UPDATE findingauditevent SET to_verdict = 'true_positive' WHERE to_verdict = 'triaged'"),
    ("findingauditevent", "from_verdict",
     "UPDATE findingauditevent SET from_verdict = 'true_positive' WHERE from_verdict = 'triaged'"),
)


def _migrate_fleet_columns(inspector) -> None:
    from sqlalchemy import inspect as sa_inspect

    tables = inspector.get_table_names()
    for table, column, ddl in _FLEET_COLUMNS:
        if table not in tables or column in {c["name"] for c in inspector.get_columns(table)}:
            continue
        _add_column(table, column, ddl)
    for table, ddl in _FLEET_INDEXES:
        if table in tables:
            with engine.begin() as conn:
                conn.execute(text(_ddl(ddl)))

    _migrate_unique_indexes(sa_inspect(engine))
    _migrate_verdict_names(sa_inspect(engine))


def _migrate_unique_indexes(inspector) -> None:
    """Add the fleet uniqueness guarantees, merging the duplicates that block them."""
    from sqlalchemy.exc import IntegrityError, OperationalError

    for table, index, ddl in _UNIQUE_INDEXES:
        if table not in inspector.get_table_names():
            continue
        if index in {i["name"] for i in inspector.get_indexes(table)}:
            continue
        try:
            if table == "finding":
                _merge_duplicate_findings()
            with engine.begin() as conn:
                conn.execute(text(_ddl(ddl)))
        except (OperationalError, IntegrityError):
            # Rows this pass cannot merge (a database predating the identity
            # columns, say) must not take the whole service down; the index is
            # retried next startup.
            continue


def _merge_duplicate_findings() -> None:
    """Fold findings sharing the fleet identity onto the lowest id, one statement per table.

    Only a race between two ingests can produce these; re-pointing observations
    and audit events keeps the history readable after the fold, and the unique
    index is what stops it happening again. The fold covers exactly the rows the
    partial index does: a pre-fleet dashboard row lives on branch '' and is
    meant to repeat a fingerprint across scans, so folding it would delete
    history the index deliberately allows.
    """
    from sqlalchemy import inspect as sa_inspect

    tables = set(sa_inspect(engine).get_table_names())
    children = [table for table in ("findingobservation", "findingauditevent") if table in tables]
    with engine.begin() as conn:
        duplicates = conn.execute(text(
            "SELECT dup.id, keep.id FROM finding dup JOIN finding keep "
            "ON keep.project_id = dup.project_id AND keep.branch = dup.branch "
            "AND keep.fingerprint_version = dup.fingerprint_version "
            "AND keep.fingerprint = dup.fingerprint AND keep.id < dup.id "
            "WHERE dup.branch <> ''"
        )).all()
        for duplicate_id, kept_id in duplicates:
            if "findingobservation" in tables:
                # This scan already holds the kept finding: the duplicate records nothing.
                conn.execute(text(
                    "DELETE FROM findingobservation WHERE finding_id = :duplicate AND scan_id IN "
                    "(SELECT scan_id FROM findingobservation WHERE finding_id = :kept)"),
                    {"duplicate": duplicate_id, "kept": kept_id})
            for child in children:
                conn.execute(text(f"UPDATE {child} SET finding_id = :kept WHERE finding_id = :duplicate"),
                             {"kept": kept_id, "duplicate": duplicate_id})
            conn.execute(text("DELETE FROM finding WHERE id = :duplicate"), {"duplicate": duplicate_id})


def _migrate_verdict_names(inspector) -> None:
    """Rewrite the stored verdicts the one review service now understands."""
    for table, column, dml in _VERDICT_RENAMES:
        if table not in inspector.get_table_names():
            continue
        if column not in {c["name"] for c in inspector.get_columns(table)}:
            continue
        with engine.begin() as conn:
            conn.execute(text(_ddl(dml)))


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
