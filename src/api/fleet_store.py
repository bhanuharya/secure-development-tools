"""Fleet baseline and review state, built from immutable fleet run artifacts.

Each fleet run is a directory: a `fleet-manifest.json` beside a
`repositories/<slug>/` tree holding that scan's canonical `findings.json` and
`run-manifest.json`. Ingest turns those read-only artifacts into the durable
data model the dashboard reads: one Scan per (project, runId), one Finding per
(project, branch, fingerprint), and one FindingObservation per (scan, finding)
holding what that scan itself reported.

These are plain functions over a caller-supplied SQLModel session and import no
FastAPI, so the ingest CLI and the API share one implementation.

A decision is recorded once, in the review store: canonical results keep every
accepted finding and the readers filter by verdict, so nothing here writes a
scanner ignore file. A scan may only resolve a finding it is comparable to —
same rule and policy digests, and a scan time no earlier than the observation
being superseded — which is why an imported historical run records what it saw
and changes nothing else.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from src.api.database import (
    VERDICTS,
    Baseline,
    BaselineItem,
    Finding,
    FindingAuditEvent,
    FindingObservation,
    Project,
    Scan,
    derived_status,
    utcnow,
)
from src.scanners.evidence import redact_text

# A policy-blocked run still produced a complete report; only a scan the engine
# could not finish proves nothing.
SCAN_STATUS = {"passed": "succeeded", "policy_failed": "succeeded",
               "inconclusive": "inconclusive", "execution_failed": "failed"}
ADAPTER_COMPLETED = "completed"
CATEGORY_SOURCE_TYPE = {"sast": "sast", "secret": "secrets", "dependency-vulnerability": "sca",
                        "image-vulnerability": "sca", "misconfiguration": "iac"}
SEVERITIES = ("critical", "high", "medium", "low", "info")
# tools/sdt_fleet.py validates the same grammar before a slug is ever a path
# component; ingest re-checks it because these manifests are external input.
REPO_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
INGEST_REVIEWER = "fleet-ingest"
# An accepted risk whose deadline has passed: still the verdict on the row, but
# no longer a reason to leave the finding off the queue.
EXPIRED_ACCEPTANCE = "expired_accepted_risk"
_METADATA_KEYS = ("id", "schemaVersion", "scanner", "rule", "artifact", "evidence", "reachability",
                  "confidence", "baselineState", "metadata", "suppression")


# ------------------------------------------------------------------------ ingest
def ingest_run(run_dir: Path, session: Session) -> dict:
    """Import one fleet run. Replaying the same run is a no-op."""
    run_dir = Path(run_dir)
    manifest = json.loads((run_dir / "fleet-manifest.json").read_text())
    workspace = str(manifest.get("workspace") or "")
    if not workspace:
        raise ValueError("fleet manifest has no workspace")
    counts: Counter = Counter({"repositories": len(manifest.get("repositories") or []),
                              "scans": 0, "already_ingested": 0, "missing_report": 0,
                              "created": 0, "observed": 0, "duplicate": 0,
                              "unfingerprinted": 0, "resolved": 0})
    for record in manifest.get("repositories") or []:
        slug = str(record.get("repository") or "")
        if not REPO_SLUG.fullmatch(slug):
            raise ValueError(f"not a repository slug: {slug!r}")
        report_dir = run_dir / "repositories" / slug
        report_path = report_dir / "findings.json"
        if not report_path.is_file():
            counts["missing_report"] += 1
            continue
        report = json.loads(report_path.read_text())
        project = _get_or_create_project(session, workspace, slug)
        run_id = _run_id(report, record)
        if _scan_of_run(session, project.id, run_id) is not None:
            counts["already_ingested"] += 1
            continue
        scan = _create_scan(session, project, record, report, report_dir, run_id)
        adapter_states = json.loads(scan.engine_statuses)
        completed = sorted(adapter for adapter, state in adapter_states.items()
                           if state == ADAPTER_COMPLETED)
        baseline = _active_baseline_members(session, project.id, scan.ref_name)
        for raw in report.get("findings") or []:
            outcome = _upsert_finding(session, scan, raw, baseline)
            counts[outcome] += 1
        if scan.status == "succeeded":
            counts["resolved"] += _resolve(session, scan, completed)
        counts["scans"] += 1
        session.commit()
    return dict(counts)


def _run_id(report: dict, record: dict) -> str:
    """The canonical report's runId is the idempotency key; the record mirrors it."""
    run_id = str(report.get("runId") or record.get("runId") or "")
    if not run_id:
        raise ValueError("findings.json has no runId; every ingest needs one to replay safely")
    return run_id


def _get_or_create_project(session: Session, workspace: str, slug: str) -> Project:
    project = session.exec(select(Project).where(Project.workspace == workspace,
                                                  Project.repo_slug == slug)).first()
    if project:
        return project
    project = Project(name=slug, workspace=workspace, repo_slug=slug)
    session.add(project)
    session.flush()
    return project


def _scan_of_run(session: Session, project_id: int, run_id: str) -> Scan | None:
    return session.exec(select(Scan).where(Scan.project_id == project_id, Scan.run_id == run_id)).first()


def _create_scan(session: Session, project: Project, record: dict, report: dict,
                 report_dir: Path, run_id: str) -> Scan:
    status = str(report.get("status") or record.get("status") or "")
    findings = report.get("findings") or []
    manifest = _run_manifest(report_dir / "run-manifest.json")
    scan = Scan(project_id=project.id, run_id=run_id, ref_type="branch",
                ref_name=str(record.get("branch") or ""), commit_sha=str(record.get("commit") or ""),
                status=SCAN_STATUS.get(status, "failed"),
                scan_time=_scan_time(report, record),
                config_digest=str(manifest.get("configDigest") or ""),
                policy_digest=str(manifest.get("policyDigest") or ""),
                engine_statuses=json.dumps(_adapter_states(manifest), sort_keys=True),
                summary=json.dumps(_severity_counts(findings), sort_keys=True))
    session.add(scan)
    session.flush()
    return scan


def _run_manifest(path: Path) -> dict:
    """The scan's own run manifest; an absent one attests to nothing."""
    if not path.is_file():
        return {}
    return json.loads(path.read_text())


def _adapter_states(manifest: dict) -> dict[str, str]:
    """adapter -> state for one scan. No tasks means nothing completed."""
    tasks = manifest.get("tasks") or []
    return {str(task["adapter"]): str(task.get("state") or "") for task in tasks if task.get("adapter")}


def _scan_time(report: dict, record: dict) -> datetime:
    """When the scan ran, from whichever artifact says so; never the ingest clock if avoidable."""
    for stamp in (report.get("generatedAt"), record.get("completedAt")):
        moment = _parse_time(stamp)
        if moment is not None:
            return moment
    return utcnow()


def _parse_time(stamp: object) -> datetime | None:
    """An ISO 8601 stamp from a scan artifact, or None when it is unusable."""
    text = str(stamp or "").strip()
    if not text:
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return _utc(moment)


def _severity_counts(findings: list) -> dict[str, int]:
    counts: Counter = Counter({"total": len(findings)})
    for finding in findings:
        counts[str((finding.get("severity") or {}).get("canonical") or "unknown")] += 1
    return dict(counts)


def _upsert_finding(session: Session, scan: Scan, raw: dict,
                    baseline: set[tuple[str, str]] | None) -> str:
    """Return the counter key describing what this finding did to the database."""
    printed = raw.get("fingerprint") or {}
    value = str(printed.get("value") or "")
    if not value:
        return "unfingerprinted"
    version = str(printed.get("algorithm") or "sdt-v2")
    existing = session.exec(select(Finding).where(Finding.project_id == scan.project_id,
                                                  Finding.branch == scan.ref_name,
                                                  Finding.fingerprint_version == version,
                                                  Finding.fingerprint == value)).first()
    if existing is not None:
        newest = _is_newest_observation(session, scan, existing)
        if baseline is not None and newest:
            # Baseline membership is a property of (scan, baseline): recompute it
            # on every newest observation so approval changes reflect on known findings.
            existing.baseline_state = "existing" if (version, value) in baseline else "new"
            session.add(existing)
        outcome = "observed" if _observe(session, scan, existing, raw, newest) else "duplicate"
        _note_expired_acceptance(session, existing)
        return outcome
    finding = _new_finding(scan, raw, value, version, baseline)
    session.add(finding)
    session.flush()
    session.add(_observation(scan, finding.id, raw))
    return "created"


def _is_newest_observation(session: Session, scan: Scan, finding: Finding) -> bool:
    """True when no other scan that saw this finding ran later than this one.

    Scan time, not ingestion order, decides: an older run imported late is
    history and must not move the finding's state or display fields backwards.
    """
    previous = _last_observed_scans(session, [finding.id]).get(finding.id)
    return previous is None or previous.id == scan.id or _scan_moment(scan) >= _scan_moment(previous)


def _observe(session: Session, scan: Scan, finding: Finding, raw: dict, newest: bool = True) -> bool:
    """Record that this scan saw a known finding; reopen it when it had resolved.

    The finding row is what an analyst reads, so the newest report (by scan time)
    owns its display fields while every observation row keeps what its own scan
    saw. An older scan only adds its observation.
    """
    if newest:
        _apply_report(finding, raw)
    if session.exec(select(FindingObservation.id).where(FindingObservation.scan_id == scan.id,
                                                        FindingObservation.finding_id == finding.id)).first():
        session.add(finding)
        return False
    session.add(_observation(scan, finding.id, raw))
    if not newest:
        return True
    seen_at = _scan_moment(scan)
    last_seen = _utc(finding.last_seen)
    finding.last_seen = seen_at if last_seen is None or seen_at > last_seen else finding.last_seen
    if finding.lifecycle == "resolved":
        # The weakness is back: reopen it and leave an audit trail dated when the scan ran.
        finding.lifecycle = "open"
        finding.status = derived_status(finding)
        _append_audit(session, finding, from_status="resolved", to_status=finding.status,
                      from_verdict=finding.verdict, to_verdict=finding.verdict,
                      reason=f"re-observed by scan {scan.run_id}", reviewer="",
                      created=seen_at, idempotency_key=f"reopen:{scan.run_id}")
    session.add(finding)
    return True


def _new_finding(scan: Scan, raw: dict, fingerprint: str, version: str,
                 baseline: set[tuple[str, str]] | None) -> Finding:
    rule = raw.get("rule") or {}
    location = raw.get("location") or {}
    artifact = raw.get("artifact") or {}
    category = str(raw.get("category") or "")
    cwes = rule.get("cwe") or []
    if baseline is None:
        # Nothing has been approved for this branch yet, so no claim is made.
        baseline_state = "unassessed"
    else:
        baseline_state = "existing" if (version, fingerprint) in baseline else "new"
    finding = Finding(
        scan_id=scan.id,
        project_id=scan.project_id,
        branch=scan.ref_name,
        tool=str((raw.get("scanner") or {}).get("adapter") or ""),
        source_type=CATEGORY_SOURCE_TYPE.get(category, "sast"),
        rule_id=str(rule.get("id") or ""),
        cwe=", ".join(str(item) for item in cwes) if isinstance(cwes, list) else str(cwes),
        file_path=redact_text(str(location.get("path") or artifact.get("target") or "")),
        fingerprint=fingerprint,
        fingerprint_version=version,
        baseline_state=baseline_state,
        evidence=json.dumps(_metadata(raw), sort_keys=True),
    )
    _apply_report(finding, raw)
    finding.status = derived_status(finding)
    return finding


def _apply_report(finding: Finding, raw: dict) -> None:
    """Show the finding as its newest observation reported it.

    Only the display fields move: `file_path` and the fingerprint stay as first
    recorded, because they are what makes this finding the same finding.
    """
    reported = _reported(raw)
    for field, value in reported.items():
        setattr(finding, field, value)


def _reported(raw: dict) -> dict:
    """The display fields a scan reports for one fingerprint."""
    location = raw.get("location") or {}
    severity = str((raw.get("severity") or {}).get("canonical") or "info")
    return {"severity": severity if severity in SEVERITIES else "info",
            "line_start": _line(location.get("startLine")),
            "line_end": _line(location.get("endLine")),
            "description": redact_text(str(raw.get("message") or "")),
            "remediation": redact_text(str((raw.get("remediation") or {}).get("guidance") or ""))}


def _observation(scan: Scan, finding_id: int, raw: dict) -> FindingObservation:
    """One scan's own account of a finding, kept whatever later runs say."""
    reported = _reported(raw)
    return FindingObservation(scan_id=scan.id, finding_id=finding_id,
                              severity=reported["severity"], line_start=reported["line_start"],
                              line_end=reported["line_end"],
                              message_digest=_message_digest(reported["description"]))


def _message_digest(message: str) -> str:
    """A short, storable handle on the report text: enough to tell a reworded
    finding from the same message seen again, without keeping the message twice."""
    return hashlib.sha256(message.encode()).hexdigest()[:32]


def _metadata(raw: dict) -> dict:
    """The scanner fields an analyst needs, kept as evidence JSON."""
    return {key: raw[key] for key in _METADATA_KEYS if key in raw}


def _line(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _resolve(session: Session, scan: Scan, completed: list[str]) -> int:
    """Close findings a successful scan's completed adapters no longer report.

    Absence is only evidence when the scan that reports it is comparable to the
    one that last saw the finding, so three things must hold: the scan succeeded
    (an unfinished run proves nothing about what is absent); it ran *after* the
    finding's newest observation (an imported historical run describes the past,
    and must never flip lifecycle backwards); and its config and policy digests
    match that last observation (a different rule pack or policy simply did not
    look for this finding).
    """
    if scan.status != "succeeded" or not completed:
        return 0
    observed_here = select(FindingObservation.finding_id).where(FindingObservation.scan_id == scan.id)
    candidates = session.exec(select(Finding).where(Finding.project_id == scan.project_id,
                                                    Finding.branch == scan.ref_name,
                                                    Finding.lifecycle == "open",
                                                    Finding.tool.in_(completed),
                                                    Finding.id.notin_(observed_here))).all()
    if not candidates:
        return 0
    last_seen = _last_observed_scans(session, [finding.id for finding in candidates])
    scan_moment = _scan_moment(scan)
    created = utcnow().replace(microsecond=0)
    resolved = 0
    for finding in candidates:
        previous = last_seen.get(finding.id)
        if previous is None:
            continue
        if scan_moment <= _scan_moment(previous):
            continue
        if (scan.config_digest, scan.policy_digest) != (previous.config_digest, previous.policy_digest):
            continue
        status = finding.status
        finding.lifecycle = "resolved"
        finding.status = derived_status(finding)
        session.add(finding)
        _append_audit(session, finding, from_status=status, to_status=finding.status,
                      from_verdict=finding.verdict, to_verdict=finding.verdict,
                      reason=f"not observed in run {scan.run_id}", reviewer=INGEST_REVIEWER,
                      created=created, idempotency_key=f"resolve:{scan.run_id}")
        resolved += 1
    return resolved


def _last_observed_scans(session: Session, finding_ids: list[int]) -> dict[int, Scan]:
    """Each finding's newest-by-scan-time observation, which is the state to compare against.

    Ascending order plus a dict comprehension leaves the newest row per finding;
    Scan.id cannot be the tiebreaker because it records ingestion, not scanning.
    """
    rows = session.exec(select(FindingObservation.finding_id, Scan)
                        .join(Scan, Scan.id == FindingObservation.scan_id)
                        .where(FindingObservation.finding_id.in_(finding_ids))
                        .order_by(Scan.scan_time, Scan.id)).all()
    return {finding_id: scan for finding_id, scan in rows}


def _scan_moment(scan: Scan) -> datetime:
    """When a scan ran; a row migrated before scan_time existed falls back to ingestion."""
    return _utc(scan.scan_time) or _utc(scan.created_at) or utcnow()


# ----------------------------------------------------------------------- review
def review_finding(session: Session, finding_id: int, verdict: str, reviewer: str = "",
                   reason: str = "", expires_at: datetime | None = None,
                   idempotency_key: str | None = None) -> Finding:
    """Record one human decision on a finding.

    An accepted risk is a promise with a deadline, so it needs an owner, a
    reason, and an expiry to revisit it against — and a deadline already in the
    past is a promise nobody is making, so it is refused rather than stored as
    coverage that never existed.

    `idempotency_key` is what lets a caller retry the same decision without
    recording it twice. Without one, every call is its own event, so two
    reviewers — or one reviewer twice in the same second — leave two rows.
    """
    if verdict not in VERDICTS:
        raise ValueError(f"invalid verdict {verdict!r}; expected one of {', '.join(VERDICTS)}")
    if verdict == "accepted_risk" and not (reviewer and reason and expires_at):
        raise ValueError("accepted_risk requires reviewer, reason and expires_at")
    deadline = _utc(expires_at)
    if deadline is not None and deadline <= utcnow():
        raise ValueError("expires_at must be in the future")
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise ValueError(f"finding {finding_id} not found")
    previous, previous_verdict = finding.status, finding.verdict
    finding.verdict = verdict
    finding.triage_reason = reason
    finding.accepted_until = deadline if verdict == "accepted_risk" else None
    finding.status = derived_status(finding)
    session.add(finding)
    _append_audit(session, finding, from_status=previous, to_status=finding.status,
                  from_verdict=previous_verdict, to_verdict=verdict, reason=reason,
                  reviewer=reviewer, created=utcnow().replace(microsecond=0),
                  expires_at=finding.accepted_until, idempotency_key=idempotency_key)
    session.commit()
    session.refresh(finding)
    return finding


def is_live_acceptance(finding: Finding, now: datetime | None = None) -> bool:
    """True when this finding rests on an acceptance that has not run out.

    An acceptance with no recorded deadline never runs out: the service insists
    on one, and a row migrated from before it existed stays honoured.
    """
    return finding.verdict == "accepted_risk" and effective_verdict(finding, now) == "accepted_risk"


def effective_verdict(finding: Finding, now: datetime | None = None) -> str:
    """The verdict a reader should act on; the stored verdict is never changed."""
    return _verdict_as_of(finding.verdict, finding.accepted_until, now)


def _verdict_as_of(verdict: str, accepted_until: datetime | None,
                   now: datetime | None) -> str:
    deadline = _utc(accepted_until)
    if verdict != "accepted_risk" or deadline is None or deadline > (_utc(now) or utcnow()):
        return verdict
    return EXPIRED_ACCEPTANCE


def verdict_counts(session: Session, now: datetime | None = None) -> dict[str, int]:
    """Open findings grouped by the verdict a reader should act on."""
    counts: Counter = Counter()
    for verdict, accepted_until in session.exec(select(Finding.verdict, Finding.accepted_until)
                                                .where(Finding.lifecycle == "open")).all():
        counts[_verdict_as_of(str(verdict), accepted_until, now)] += 1
    return dict(counts)


def _note_expired_acceptance(session: Session, finding: Finding) -> bool:
    """Leave one trail per finding when a re-observation finds its acceptance run out.

    The decision stands as recorded; what changed is that it needs making again,
    and the queue has to say so from the day the deadline passed.
    """
    deadline = _utc(finding.accepted_until)
    if finding.verdict != "accepted_risk" or deadline is None or deadline > utcnow():
        return False
    return _append_audit(session, finding, from_status=finding.status, to_status="expired",
                         from_verdict=finding.verdict, to_verdict=finding.verdict,
                         reason=f"accepted risk expired {deadline.date().isoformat()}",
                         reviewer=INGEST_REVIEWER, created=utcnow().replace(microsecond=0),
                         expires_at=finding.accepted_until,
                         # One event per acceptance: a renewed-then-lapsed risk expires again.
                         idempotency_key=f"expired:{deadline.isoformat()}")


def approve_baseline(session: Session, project_id: int, branch: str, approved_by: str,
                     reason: str, source_scan_id: int | None = None) -> Baseline:
    """Freeze one branch's findings as accepted known risk.

    Without a source scan the frozen set is the branch as it reads right now:
    every open finding. With one it is exactly what that run reported, so an
    approval can name the scan an operator actually watched instead of whatever
    the table happened to hold when the call landed.
    """
    if source_scan_id is None:
        open_findings = session.exec(select(Finding).where(Finding.project_id == project_id,
                                                           Finding.branch == branch,
                                                           Finding.lifecycle == "open")).all()
        members = {(finding.fingerprint_version, finding.fingerprint) for finding in open_findings}
    else:
        members = _scan_reported_members(session, source_scan_id, project_id, branch)
    baseline = Baseline(project_id=project_id, branch=branch, approved_by=approved_by, reason=reason,
                        source_scan_id=source_scan_id, finding_count=len(members))
    session.add(baseline)
    session.flush()
    for version, fingerprint in sorted(members):
        session.add(BaselineItem(baseline_id=baseline.id, fingerprint=fingerprint,
                                fingerprint_version=version))
    session.commit()
    session.refresh(baseline)
    return baseline


def _scan_reported_members(session: Session, scan_id: int, project_id: int,
                           branch: str) -> set[tuple[str, str]]:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise ValueError(f"source scan {scan_id} not found")
    if scan.project_id != project_id or scan.ref_name != branch:
        raise ValueError(f"source scan {scan_id} is not a {branch} scan of project {project_id}")
    return set(session.exec(select(Finding.fingerprint_version, Finding.fingerprint)
                            .join(FindingObservation, FindingObservation.finding_id == Finding.id)
                            .where(FindingObservation.scan_id == scan_id)).all())


def active_baseline(session: Session, project_id: int, branch: str) -> Baseline | None:
    """The newest approval for this project+branch is the one in force."""
    return session.exec(select(Baseline).where(Baseline.project_id == project_id,
                                               Baseline.branch == branch)
                        .order_by(Baseline.created_at.desc(), Baseline.id.desc())).first()


def _active_baseline_members(session: Session, project_id: int,
                             branch: str) -> set[tuple[str, str]] | None:
    baseline = active_baseline(session, project_id, branch)
    if baseline is None:
        return None
    return set(session.exec(select(BaselineItem.fingerprint_version, BaselineItem.fingerprint)
                            .where(BaselineItem.baseline_id == baseline.id)).all())


def _append_audit(session: Session, finding: Finding, *, from_status: str, to_status: str,
                  from_verdict: str, to_verdict: str, reason: str, reviewer: str, created: datetime,
                  expires_at: datetime | None = None, idempotency_key: str | None = None) -> bool:
    """Append one decision event.

    The key is the whole dedupe story: a caller that retried the same decision
    passes the same `idempotency_key` and adds nothing, while a caller that says
    nothing gets a fresh key and is recorded on its own merits.
    """
    key = f"{finding.id}:{to_verdict}:{reviewer}:{idempotency_key or uuid.uuid4().hex}"
    if session.exec(select(FindingAuditEvent.id).where(FindingAuditEvent.event_key == key)).first():
        return False
    session.add(FindingAuditEvent(finding_id=finding.id, from_status=from_status, to_status=to_status,
                                  from_verdict=from_verdict, to_verdict=to_verdict, reason=reason,
                                  reviewer=reviewer, expires_at=expires_at, created_at=created,
                                  event_key=key))
    try:
        with session.begin_nested():
            session.flush()
    except IntegrityError:
        # Another writer recorded the same decision concurrently.
        return False
    return True


def _utc(value: datetime | None) -> datetime | None:
    """SQLite stores a DATETIME without an offset, so read values come back naive."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# ----------------------------------------------------------------- sonar reviews
SONAR_REVIEWER_PREFIX = "sonar:"


def apply_sonar_decisions(session: Session, project_id: int, branch: str, decisions: list[dict],
                          accept_days: int = 90) -> dict:
    """Record reviews made in SonarQube, through the one review service.

    Each decision is ``{"key", "rule", "path", "line", "verdict", "reviewer", "reason"}``,
    where ``rule`` is the Sonar rule key ("opengrep-dart:scp.x", "sdt:secret"). A decision
    lands on the finding with the same rule, file and first line on this branch; it is a
    no-op when the finding already carries that verdict, and replaying it adds nothing.
    Sonar's "accepted" has no deadline, so an accepted risk gets ``accept_days`` to be
    looked at again.
    """
    counts: Counter = Counter({"applied": 0, "unchanged": 0, "unmatched": 0})
    for decision in decisions:
        finding = _finding_for_sonar(session, project_id, branch, decision)
        if finding is None:
            counts["unmatched"] += 1
            continue
        verdict = decision["verdict"]
        if finding.verdict == verdict and (verdict != "accepted_risk" or is_live_acceptance(finding)):
            counts["unchanged"] += 1
            continue
        expires = utcnow() + timedelta(days=accept_days) if verdict == "accepted_risk" else None
        review_finding(session, finding.id, verdict,
                       reviewer=SONAR_REVIEWER_PREFIX + (decision.get("reviewer") or "unknown"),
                       reason=decision.get("reason") or f"reviewed in SonarQube ({decision['key']})",
                       expires_at=expires, idempotency_key=f"sonar:{decision['key']}:{verdict}")
        counts["applied"] += 1
    return dict(counts)


def _finding_for_sonar(session: Session, project_id: int, branch: str, decision: dict) -> Finding | None:
    repository, _, rule_id = str(decision.get("rule") or "").partition(":")
    conditions = [Finding.project_id == project_id, Finding.branch == branch,
                  Finding.file_path == str(decision.get("path") or ""),
                  Finding.line_start == (decision.get("line") or None)]
    if repository.startswith("opengrep-"):
        conditions.append(Finding.rule_id == rule_id)
    elif (repository, rule_id) in {("sdt", "secret"), ("sdt", "secret-in-history")}:
        conditions.append(Finding.tool == "gitleaks")
    else:
        return None
    return session.exec(select(Finding).where(*conditions).order_by(Finding.id)).first()
