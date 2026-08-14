from __future__ import annotations

import json
import logging
import shutil
import subprocess
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from sqlmodel import Session, select

from src.api.database import engine, Finding, Scan
from src.api.events import event_bus
from src.config import MAX_CONCURRENT_ENGINES, SCAN_WORK_DIR
from src.dast.zap_client import ZapClient
from src.integrations.bitbucket_client import BitbucketClient
from src.integrations.diff_parser import ParsedDiff, parse_diff
from src.scanners.bandit_adapter import BanditAdapter
from src.scanners.base import RawFinding
from src.scanners.gitleaks_adapter import GitleaksAdapter
from src.scanners.opengrep_adapter import OpengrepAdapter
from src.scanners.trivy_adapter import TrivyAdapter
from src.util.fingerprint import fingerprint
from src.util.language import detect_languages, opengrep_languages

log = logging.getLogger(__name__)

SAST_ENGINES = ("bandit", "opengrep")
ALL_ENGINES = ("bandit", "opengrep", "trivy", "gitleaks", "zap")

# engine name -> (scan_type bits it satisfies)
ENGINE_SOURCE_TYPE = {
    "bandit": "sast",
    "opengrep": "sast",
    "trivy": "sca",
    "gitleaks": "secrets",
    "zap": "dast",
}


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
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            self._mark(session, scan, status="running", started=True)
            event_bus.publish(scan_id, "scan_status", {"status": "running"})
            try:
                self._execute(session, scan)
                self._mark(session, scan, status="succeeded", finished=True)
                event_bus.publish(scan_id, "scan_status", {"status": "succeeded"})
            except Exception as exc:  # noqa: BLE001
                log.exception("scan %s failed", scan_id)
                self._mark(session, scan, status="failed", error=str(exc)[:500], finished=True)
                event_bus.publish(scan_id, "scan_status", {"status": "failed", "error": str(exc)[:500]})

    def _execute(self, session: Session, scan: Scan) -> None:
        project = _project_of(session, scan.project_id)
        workdir: Path | None = None
        parsed_diff: ParsedDiff | None = None

        engines = _resolve_engines(scan)
        # Uploaded archives don't touch Bitbucket at all, so skip instantiating
        # the client (which requires a token).
        need_bb = scan.ref_type == "pr" or (scan.ref_type != "upload" and scan.scan_type != "dast")
        bb = self._bb() if need_bb else None

        if scan.ref_type == "pr":
            diff_text = bb.get_pull_request_diff(project.workspace, project.repo_slug, scan.ref_name)
            parsed_diff = parse_diff(diff_text)
            scan.commit_sha = bb.pull_request_head_sha(project.workspace, project.repo_slug, scan.ref_name)
            session.add(scan)
            session.commit()

        if scan.scan_type == "dast":
            # DAST runs against ZAP; there is no local checkout to stage.
            workdir = None
        elif scan.ref_type == "upload":
            # Repository ZIP already staged into the workdir by the upload handler.
            # Require the readiness marker so a missing/partial extraction fails
            # loudly instead of producing a false "clean" scan.
            workdir = SCAN_WORK_DIR / f"p{project.id}-s{scan.id}"
            if not (workdir / ".ready").exists():
                raise RuntimeError("uploaded repository was not staged correctly (.ready missing)")
            event_bus.publish(scan.id, "clone", {"status": "running", "note": "Preparing uploaded repository..."})
            event_bus.publish(scan.id, "clone", {"status": "done"})
        else:
            workdir = SCAN_WORK_DIR / f"p{project.id}-s{scan.id}"
            if workdir.exists():
                shutil.rmtree(workdir, ignore_errors=True)
            ref = scan.commit_sha or scan.ref_name
            event_bus.publish(scan.id, "clone", {"status": "running"})
            bb.clone_repo(project.workspace, project.repo_slug, ref, str(workdir))
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
                futures[pool.submit(scanner.run)] = eng

            for fut in as_completed(futures):
                eng = futures[fut]
                try:
                    found = fut.result()
                except subprocess.TimeoutExpired:
                    reason = f"{eng} timed out"
                    engine_states[eng] = _eng_state("timeout", reason=reason)
                    event_bus.publish(scan.id, "engine_status", {"engine": eng, "state": "timeout", "reason": reason})
                    continue
                except Exception as exc:  # noqa: BLE001
                    reason = f"{eng} failed: {str(exc)[:200]}"
                    log.warning(reason)
                    engine_states[eng] = _eng_state("failed", reason=reason)
                    event_bus.publish(scan.id, "engine_status", {"engine": eng, "state": "failed", "reason": reason})
                    continue
                findings.extend(found)
                completed.add(eng)
                engine_states[eng] = _eng_state("done", findings=len(found))
                event_bus.publish(
                    scan.id, "engine_status",
                    {"engine": eng, "state": "done", "findings": len(found)},
                )

        findings = _dedup(findings)
        for f in findings:
            if workdir is not None:
                f.file_path = _rel_path(f.file_path, workdir)
            if parsed_diff is not None and f.source_type == "sast":
                f.in_pr_diff = _in_pr_diff(parsed_diff, f.file_path, f.line_start, workdir)

        self._persist(session, scan, findings, engine_states, detected)
        event_bus.publish(scan.id, "findings", {"count": len(findings)})

        if not completed:
            raise RuntimeError("no scanner completed successfully; refusing to report an empty result")

    # ------------------------------------------------------------------ build
    def _build_engine(self, name: str, workdir: Path | None, detected: list[str], scan: Scan):
        if name == "bandit":
            if workdir is None or "python" not in detected:
                return None
            return BanditAdapter(workdir)
        if name == "opengrep":
            if workdir is None:
                return None
            adapter = OpengrepAdapter(workdir, languages=opengrep_languages(detected))
            if not adapter.rule_files():
                return None
            return adapter
        if name == "trivy":
            if workdir is None:
                return None
            return TrivyAdapter(workdir)
        if name == "gitleaks":
            if workdir is None:
                return None
            return GitleaksAdapter(workdir)
        if name == "zap":
            zap = self._zap_client()
            if not zap.available():
                return None
            return _DastScanner(zap, scan)
        return None

    # ------------------------------------------------------------------ persist
    def _persist(self, session: Session, scan: Scan, findings: list[RawFinding], engine_states: dict, detected: list[str] | None = None) -> None:
        counts: Counter = Counter()
        for rf in findings:
            rec = Finding(
                scan_id=scan.id,
                project_id=scan.project_id,
                tool=rf.tool,
                source_type=rf.source_type,
                rule_id=rf.rule_id,
                severity=rf.severity,
                cwe=rf.cwe,
                file_path=rf.file_path,
                line_start=rf.line_start,
                line_end=rf.line_end,
                snippet=rf.snippet,
                description=rf.description,
                remediation=rf.remediation,
                fingerprint=fingerprint(rf.tool, rf.rule_id, rf.file_path, rf.line_start, rf.snippet),
                status="new",
                in_pr_diff=getattr(rf, "in_pr_diff", False),
            )
            session.add(rec)
            counts[rf.severity] += 1
        engine_state_counts = Counter(s["state"] for s in engine_states.values())
        summary = {
            "total": len(findings),
            **dict(counts),
            "engines": dict(engine_state_counts),
        }
        if detected:
            summary["languages"] = detected
        scan.engine_statuses = json.dumps(engine_states)
        scan.summary = json.dumps(summary)
        session.add(scan)
        session.commit()

    def _mark(self, session: Session, scan: Scan, *, status: str, started: bool = False, finished: bool = False, error: str = "") -> None:
        from sqlalchemy.exc import PendingRollbackError
        from sqlalchemy.orm.exc import StaleDataError

        from src.api.database import utcnow

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
        except (StaleDataError, PendingRollbackError):
            # scan row was removed concurrently (e.g. DB reset while a scan thread
            # was still draining); nothing left to record.
            session.rollback()


class _DastScanner:
    """Adapter wrapper so ZAP DAST runs inside the same engine machinery."""

    name = "zap"

    def __init__(self, zap: ZapClient, scan: Scan) -> None:
        self._zap = zap
        self._scan = scan

    def available(self) -> bool:
        # `_build_engine` only constructs this wrapper when ZAP is reachable.
        return True

    def run(self) -> list[RawFinding]:
        from src.api.database import Target

        with Session(engine) as session:
            target = None
            if self._scan.dast_target:
                target = session.exec(
                    select(Target).where(Target.id == self._scan.dast_target)
                ).first()
        if target is None:
            raise ZapErrorShim("DAST scan has no configured target")

        def progress(stage: str, percent: int, note: str) -> None:
            event_bus.publish(
                self._scan.id, "zap_progress",
                {"stage": stage, "percent": percent, "note": note},
            )

        return self._zap.run_dast(
            scan_id=self._scan.id,
            target_url=target.url,
            auth_mode=target.auth_mode,
            login_url=target.login_url,
            username_field=target.username_field,
            password_field=target.password_field,
            auth_username=target.auth_username,
            auth_password=target.auth_password,
            context_file_path=target.context_file_path,
            on_progress=progress,
        )


class ZapErrorShim(Exception):
    pass


# ------------------------------------------------------------------ helpers
def _eng_state(state: str, findings: int | None = None, reason: str = "") -> dict:
    data: dict = {"state": state}
    if findings is not None:
        data["findings"] = findings
    if reason:
        data["reason"] = reason
    return data


def _skip_reason(name: str, workdir: Path | None, detected: list[str]) -> str:
    if name == "zap":
        return "zap is not reachable (is ZAP running at the configured API URL?)"
    if workdir is None:
        return f"{name} requires a local checkout"
    if name == "bandit":
        return "bandit is skipped: no Python files detected"
    if name == "opengrep":
        return "opengrep is skipped: no matching local rules for the detected languages"
    return f"{name} is not applicable to this scan"


def _resolve_engines(scan: Scan) -> list[str]:
    if scan.engines:
        return [e for e in scan.engines.split(",") if e in ENGINE_SOURCE_TYPE]
    if scan.scan_type == "full":
        return ["bandit", "opengrep", "trivy", "gitleaks"]
    if scan.scan_type == "dast":
        return ["zap"]
    if scan.scan_type == "sca":
        return ["trivy"]
    if scan.scan_type == "secrets":
        return ["gitleaks"]
    return list(SAST_ENGINES)


def _rel_path(file_path: str, workdir: Path) -> str:
    """Normalize an engine-reported path to be relative to the scan root so
    findings stay stable across uploads/clones and display cleanly."""
    if not file_path:
        return file_path
    p = Path(file_path)
    try:
        return str(p.relative_to(workdir))
    except ValueError:
        return file_path


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
