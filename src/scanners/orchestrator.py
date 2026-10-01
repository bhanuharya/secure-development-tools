from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from sqlmodel import Session

from src.api.database import engine, Finding, Scan, Target
from src.api.events import event_bus
from src.config import MAX_CONCURRENT_ENGINES, SCAN_WORK_DIR
from src.dast.zap_client import ZapClient
from src.integrations.bitbucket_client import BitbucketClient
from src.integrations.diff_parser import ParsedDiff, parse_diff
from src.scanners.base import RawFinding
from src.scanners.errors import REAL_FAILURE_KINDS, ScannerError
from src.scanners.evidence import build_evidence, redact_text
from src.scanners.registry import EngineContext, REGISTRY, all_engines, resolve_engines
from src.util.fingerprint import fingerprint
from src.util.language import detect_languages


def _target_digest(target: Target) -> str:
    import hashlib
    values = {k: getattr(target, k, "") for k in (
        "url", "is_production", "auth_mode", "login_url", "username_field",
        "password_field", "auth_username", "auth_password", "context_file_path",
        "production_confirmed", "pre_approved")}
    return hashlib.sha256(json.dumps(values, sort_keys=True, default=str).encode()).hexdigest()

SEVERITIES = ("critical", "high", "medium", "low", "info")

log = logging.getLogger(__name__)

# Backwards-compatible re-exports. Prefer the registry helpers for new code.
SAST_ENGINES = tuple(
    name for name, spec in REGISTRY.items() if spec.source_type == "sast"
)
ALL_ENGINES = all_engines()
ENGINE_SOURCE_TYPE = {name: spec.source_type for name, spec in REGISTRY.items()}


@dataclass
class _ScanSnapshot:
    """Scalar scan inputs safe to retain across long-running engine calls."""

    id: int
    project_id: int
    scan_type: str
    engines: str
    ref_type: str
    ref_name: str
    commit_sha: str
    language_override: str
    dast_target: str
    dast_target_digest: str


class ScanRunner:
    def __init__(self, bitbucket: BitbucketClient | None = None, zap: ZapClient | None = None) -> None:
        self._bitbucket = bitbucket
        self._zap = zap

    def _bb(self) -> BitbucketClient:
        return self._bitbucket or BitbucketClient()

    def _zap_client(self) -> ZapClient:
        return self._zap or ZapClient()

    # ------------------------------------------------------------------ entry
    def run_scan(self, scan_id: int) -> None:
        with Session(engine) as session:
            row = session.get(Scan, scan_id)
            if row is None:
                return
            scan = _snapshot(row)

        if not self._mark(scan_id, status="running", started=True):
            return
        event_bus.publish(scan_id, "scan_status", {"status": "running"})
        try:
            with Session(engine) as session:
                persisted = self._execute(session, scan)
            if not persisted:
                return
            if self._mark(scan_id, status="succeeded", finished=True):
                event_bus.publish(scan_id, "scan_status", {"status": "succeeded"})
        except Exception as exc:  # noqa: BLE001
            error = redact_text(_sanitize_reason(str(exc))[:500])
            # Persist, publish, and log the same sanitized diagnostic. A raw
            # traceback would reintroduce absolute workspace paths via the
            # exception text, defeating the API/event redaction below.
            log.error("scan %s failed: %s", scan_id, error)
            if self._mark(scan_id, status="failed", error=error, finished=True):
                event_bus.publish(scan_id, "scan_status", {"status": "failed", "error": error})
        finally:
            _cleanup_scan_workdir(scan)

    def _execute(self, session: Session, scan: _ScanSnapshot) -> bool:
        project = _project_of(session, scan.project_id)
        project_id = project.id
        workspace = project.workspace
        repo_slug = project.repo_slug
        workdir: Path | None = None
        parsed_diff: ParsedDiff | None = None

        engines = _resolve_engines(scan)
        # Re-read the approval and the complete target configuration immediately
        # before starting ZAP. This closes the queued-scan revocation window.
        # The bound digest pins an immutable validated snapshot; scope/DNS is
        # revalidated here so a re-pointed host or credential-bearing URL can
        # never launch even with a stale approval.
        if scan.scan_type == "dast":
            from src.util.dastgate import validate_dast_url

            target = session.get(Target, int(scan.dast_target or 0))
            if (not target or not target.pre_approved or
                    (target.is_production and not target.production_confirmed) or
                    _target_digest(target) != scan.dast_target_digest):
                raise RuntimeError("DAST target approval or configuration was revoked")
            try:
                validate_dast_url(target.url)
                if target.login_url:
                    validate_dast_url(target.login_url)
            except ValueError as exc:
                raise RuntimeError(f"DAST target scope revoked: {exc}") from exc
        # Uploaded archives and local folders don't touch Bitbucket at all, so
        # skip instantiating the client (which requires a token).
        staged = scan.ref_type in ("upload", "folder")
        need_bb = scan.ref_type == "pr" or (not staged and scan.scan_type != "dast")
        bb = self._bb() if need_bb else None

        if scan.ref_type == "pr":
            diff_text = bb.get_pull_request_diff(workspace, repo_slug, scan.ref_name)
            parsed_diff = parse_diff(diff_text)
            scan.commit_sha = bb.pull_request_head_sha(workspace, repo_slug, scan.ref_name)
            live_scan = session.get(Scan, scan.id)
            if live_scan is None:
                return False
            live_scan.commit_sha = scan.commit_sha
            session.add(live_scan)
            session.commit()

        if scan.scan_type == "dast":
            # DAST runs against ZAP; there is no local checkout to stage.
            workdir = None
        elif scan.ref_type in ("upload", "folder"):
            # Repository already staged into the workdir by the intake handler.
            # Require the readiness marker so a missing/partial stage fails
            # loudly instead of producing a false "clean" scan.
            workdir = SCAN_WORK_DIR / f"p{project_id}-s{scan.id}"
            if not (workdir / ".ready").exists():
                raise RuntimeError("repository was not staged correctly (.ready missing)")
            event_bus.publish(scan.id, "clone", {"status": "running", "note": "Preparing repository..."})
            event_bus.publish(scan.id, "clone", {"status": "done"})
        else:
            workdir = SCAN_WORK_DIR / f"p{project_id}-s{scan.id}"
            if workdir.exists():
                shutil.rmtree(workdir, ignore_errors=True)
            # git clone creates the destination itself; only ensure the
            # parent work root exists (0700) then harden the checkout after.
            try:
                import os as _os

                SCAN_WORK_DIR.mkdir(parents=True, exist_ok=True)
                _os.chmod(SCAN_WORK_DIR, 0o700)
            except OSError:
                pass
            ref = scan.commit_sha
            if scan.ref_type == "branch":
                if bb is None:
                    raise RuntimeError("Bitbucket client unavailable for branch scan")
                ref = bb.branch_head_sha(workspace, repo_slug, scan.ref_name)
                if not re.fullmatch(r"[0-9a-fA-F]{40}", ref or ""):
                    raise RuntimeError("Bitbucket returned an invalid branch head SHA")
                live_scan = session.get(Scan, scan.id)
                if live_scan is None:
                    return False
                live_scan.commit_sha = ref
                session.add(live_scan)
                session.commit()
            if not ref:
                ref = scan.ref_name
            event_bus.publish(scan.id, "clone", {"status": "running"})
            bb.clone_repo(workspace, repo_slug, ref, str(workdir))
            try:
                import os as _os

                _os.chmod(workdir, 0o700)
            except OSError:
                pass
            event_bus.publish(scan.id, "clone", {"status": "done"})

        lang_override = scan.language_override
        detected = []
        if workdir is not None:
            detected = detect_languages(workdir)
        if lang_override:
            detected = [lang_override]

        findings: list[RawFinding] = []
        engine_states: dict[str, dict] = {}
        completed: set[str] = set()
        engine_failure = False

        with ThreadPoolExecutor(max_workers=max(1, MAX_CONCURRENT_ENGINES)) as pool:
            futures: dict = {}
            for eng in engines:
                scanner = self._build_engine(eng, workdir, detected, scan)
                if scanner is None:
                    reason = _skip_reason(eng, workdir, detected)
                    engine_states[eng] = _eng_state("skipped", reason=reason)
                    event_bus.publish(scan.id, "engine_status", {"engine": eng, "state": "skipped", "reason": reason})
                    continue
                if not scanner.available():
                    reason = f"{eng} executable not found"
                    engine_states[eng] = _eng_state("unavailable", reason=reason)
                    event_bus.publish(scan.id, "engine_status", {"engine": eng, "state": "unavailable", "reason": reason})
                    continue
                engine_states[eng] = _eng_state("running")
                event_bus.publish(scan.id, "engine_status", {"engine": eng, "state": "running"})
                futures[pool.submit(scanner.run)] = (eng, scanner)

            for fut in as_completed(futures):
                eng, scanner = futures[fut]
                try:
                    found = fut.result()
                except ScannerError as exc:
                    state = "unavailable" if exc.kind == "unavailable" else "failed"
                    reason = redact_text(_sanitize_reason(exc.message))
                    engine_states[eng] = _eng_state(state, reason=reason, kind=exc.kind)
                    event_bus.publish(
                        scan.id, "engine_status",
                        {"engine": eng, "state": state, "reason": reason, "kind": exc.kind},
                    )
                    if exc.kind in REAL_FAILURE_KINDS:
                        engine_failure = True
                    continue
                except subprocess.TimeoutExpired:
                    engine_states[eng] = _eng_state("failed", reason=f"{eng} timed out", kind="timeout")
                    event_bus.publish(scan.id, "engine_status", {"engine": eng, "state": "failed", "reason": f"{eng} timed out", "kind": "timeout"})
                    engine_failure = True
                    continue
                except Exception as exc:  # noqa: BLE001
                    reason = redact_text(_sanitize_reason(f"{eng} failed: {str(exc)[:200]}"))
                    log.warning(reason)
                    engine_states[eng] = _eng_state("failed", reason=reason, kind="execution")
                    event_bus.publish(scan.id, "engine_status", {"engine": eng, "state": "failed", "reason": reason, "kind": "execution"})
                    engine_failure = True
                    continue
                findings.extend(found)
                completed.add(eng)
                degraded_reason = redact_text(getattr(scanner, "degraded_reason", "") or "")
                engine_states[eng] = _eng_state(
                    "done",
                    findings=len(found),
                    reason=degraded_reason,
                    kind="degraded" if degraded_reason else "",
                )
                event_bus.publish(
                    scan.id, "engine_status",
                    {
                        "engine": eng,
                        "state": "done",
                        "findings": len(found),
                        "reason": degraded_reason,
                        "kind": "degraded" if degraded_reason else "",
                    },
                )

        for f in findings:
            if workdir is not None:
                f.file_path = _rel_path(f.file_path, workdir)
        findings = _dedup(findings)
        for f in findings:
            if parsed_diff is not None and f.source_type == "sast":
                f.in_pr_diff = _in_pr_diff(parsed_diff, f.file_path, f.line_start, workdir)

        if not self._persist(session, scan, findings, engine_states, detected, workdir):
            return False
        event_bus.publish(scan.id, "findings", {"count": len(findings)})

        if engine_failure:
            raise RuntimeError("one or more scanners failed; see engine coverage for details")
        if not completed:
            raise RuntimeError("no scanner completed successfully; refusing to report an empty result")
        return True

    # ------------------------------------------------------------------ build
    def _build_engine(self, name: str, workdir: Path | None, detected: list[str], scan: _ScanSnapshot):
        spec = REGISTRY.get(name)
        if spec is None:
            return None
        return spec.build(
            EngineContext(
                workdir=workdir,
                detected=detected,
                scan_id=scan.id,
                dast_target=scan.dast_target,
                zap=self._zap_client() if name == "zap" else None,
            )
        )

    # ------------------------------------------------------------------ persist
    def _persist(self, session: Session, scan: _ScanSnapshot, findings: list[RawFinding], engine_states: dict, detected: list[str] | None = None, workdir: Path | None = None) -> bool:
        from sqlalchemy.orm.exc import StaleDataError

        live_scan = session.get(Scan, scan.id)
        if live_scan is None:
            return False
        counts: Counter = Counter()
        for rf in findings:
            # Every untrusted scanner-controlled field is redacted before it
            # is persisted or emitted: snippets, descriptions, remediation,
            # references/URLs (inside raw/evidence), and file paths.
            safe_snippet = redact_text(rf.snippet, rf.redaction_tokens)
            safe_description = redact_text(rf.description, rf.redaction_tokens)
            safe_remediation = redact_text(rf.remediation, rf.redaction_tokens)
            safe_path = redact_text(rf.file_path, rf.redaction_tokens)
            # Normalize severity at ingest so filtering and severity-ranked
            # ordering never miss a scanner reporting "HIGH" or an odd label.
            severity = (rf.severity or "").strip().lower()
            if severity not in SEVERITIES:
                severity = "info"
            rec = Finding(
                scan_id=scan.id,
                project_id=scan.project_id,
                tool=rf.tool,
                source_type=rf.source_type,
                rule_id=rf.rule_id,
                severity=severity,
                cwe=rf.cwe,
                file_path=safe_path,
                line_start=rf.line_start,
                line_end=rf.line_end,
                snippet=safe_snippet,
                description=safe_description,
                remediation=safe_remediation,
                fingerprint=fingerprint(
                    rf.tool, rf.rule_id, safe_path, rf.line_start, safe_snippet
                ),
                status="new",
                in_pr_diff=getattr(rf, "in_pr_diff", False),
                evidence=json.dumps(build_evidence(rf, workdir)),
            )
            session.add(rec)
            counts[severity] += 1
        engine_state_counts = Counter(s["state"] for s in engine_states.values())
        summary = {
            "total": len(findings),
            **dict(counts),
            "engines": dict(engine_state_counts),
        }
        if detected:
            summary["languages"] = detected
        live_scan.engine_statuses = json.dumps(engine_states)
        live_scan.summary = json.dumps(summary)
        session.add(live_scan)
        try:
            session.commit()
        except StaleDataError:
            session.rollback()
            return False
        return True

    def _mark(self, scan_id: int, *, status: str, started: bool = False, finished: bool = False, error: str = "") -> bool:
        from sqlalchemy.orm.exc import StaleDataError

        from src.api.database import utcnow

        with Session(engine) as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return False
            scan.status = status
            if started:
                scan.started_at = utcnow()
            if finished:
                scan.finished_at = utcnow()
            if error:
                scan.error = error
            session.add(scan)
            try:
                session.commit()
            except StaleDataError:
                session.rollback()
                return False
        return True


# ------------------------------------------------------------------ helpers
def _cleanup_scan_workdir(scan: _ScanSnapshot) -> None:
    if scan.ref_type not in ("upload", "folder", "branch", "pr"):
        return
    workdir = SCAN_WORK_DIR / f"p{scan.project_id}-s{scan.id}"
    try:
        if workdir.exists():
            shutil.rmtree(workdir)
    except OSError:
        log.warning("unable to remove scan workdir for scan %s", scan.id)


def _snapshot(scan: Scan) -> _ScanSnapshot:
    if scan.id is None:
        raise ValueError("scan must be persisted before execution")
    return _ScanSnapshot(
        id=scan.id,
        project_id=scan.project_id,
        scan_type=scan.scan_type,
        engines=scan.engines,
        ref_type=scan.ref_type,
        ref_name=scan.ref_name,
        commit_sha=scan.commit_sha,
        language_override=scan.language_override,
        dast_target=scan.dast_target,
        dast_target_digest=scan.dast_target_digest,
    )


def _eng_state(state: str, findings: int | None = None, reason: str = "", kind: str = "") -> dict:
    data: dict = {"state": state}
    if findings is not None:
        data["findings"] = findings
    if reason:
        data["reason"] = reason
    if kind:
        data["kind"] = kind
    return data


def _skip_reason(name: str, workdir: Path | None, detected: list[str]) -> str:
    spec = REGISTRY.get(name)
    if spec is None:
        return f"{name} is not applicable to this scan"
    return spec.skip_reason(EngineContext(workdir=workdir, detected=detected))


def _resolve_engines(scan: Scan | _ScanSnapshot) -> list[str]:
    return resolve_engines(scan)


def _rel_path(file_path: str, workdir: Path) -> str:
    """Normalize an engine-reported path to be relative to the scan root so
    findings stay stable across uploads/clones and display cleanly."""
    if not file_path:
        return file_path
    root = Path(workdir).resolve()
    p = Path(file_path)
    candidate = p if p.is_absolute() else root / p
    try:
        return str(candidate.resolve().relative_to(root))
    except (OSError, ValueError):
        return ""


def _in_pr_diff(parsed_diff: ParsedDiff, file_path: str, line_start: int | None, workdir: Path | None) -> bool:
    """Whether a finding's file/line falls inside the PR diff ranges.

    Engines report paths differently (absolute, relative, workdir-prefixed), so
    normalise against the checkout root before matching the diff.
    """
    if line_start is None or not file_path:
        return False
    p = Path(file_path)
    rel = file_path
    if workdir is not None:
        try:
            rel = str(p.relative_to(workdir))
        except ValueError:
            rel = str(p)
    return parsed_diff.is_line_changed(rel, line_start) or parsed_diff.is_line_changed(p.name, line_start)


def _dedup(findings: list[RawFinding]) -> list[RawFinding]:
    seen: set[str] = set()
    out: list[RawFinding] = []
    for f in findings:
        fp = fingerprint(f.tool, f.rule_id, f.file_path, f.line_start, f.snippet)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    return out


def _project_of(session: Session, project_id: int):
    from src.api.database import Project

    return session.get(Project, project_id)


def _sanitize_reason(text: str) -> str:
    """Strip the configured scan-workdir prefix from an error reason so absolute
    host paths never persist or are published, while preserving the rest of the
    diagnostic and the failure classification."""
    if not text:
        return text
    out = text
    for prefix in (str(SCAN_WORK_DIR.resolve()), str(SCAN_WORK_DIR)):
        if prefix:
            out = out.replace(prefix, "<workdir>")
    return out
