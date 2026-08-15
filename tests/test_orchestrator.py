import json
import shutil

from sqlmodel import Session, select

from src.api.database import Finding, Project, Scan, engine
from src.api.events import event_bus
from src.config import SCAN_WORK_DIR
from src.scanners.base import RawFinding
from src.scanners.opengrep_adapter import OpengrepAdapter
from src.scanners.orchestrator import ScanRunner, _sanitize_reason, _snapshot
from src.util.fingerprint import fingerprint
from tests.fakes import FakeBitbucket


def make_project(session, workspace="miraworkspace", repo="demo"):
    project = Project(name="demo", workspace=workspace, repo_slug=repo, default_branch="main")
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


def make_scan(session, project, scan_type="sast", ref_type="branch", ref_name="main", engines="", **kw):
    scan = Scan(
        project_id=project.id,
        scan_type=scan_type,
        engines=engines,
        ref_type=ref_type,
        ref_name=ref_name,
        **kw,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def test_sast_scan_full_pass(fixture_repo, tmp_env):
    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project, scan_type="sast", engines="bandit,opengrep,trivy,gitleaks")

    bitbucket = FakeBitbucket(fixture_repo)
    runner = ScanRunner(FakeBitbucket(fixture_repo))
    runner.run_scan(scan.id)

    with Session(engine) as session:
        scan = session.get(Scan, scan.id)
        assert scan.status == "succeeded"
        summary = json.loads(scan.summary)
        assert summary["total"] >= 5  # bandit(3) + opengrep(2) + trivy(9) + gitleaks(1) after dedup overlap
        assert "high" in summary
        findings = session.exec(select(Finding).where(Finding.scan_id == scan.id)).all()
        assert findings
        # dedup: same fingerprint only once
        fps = [f.fingerprint for f in findings]
        assert len(fps) == len(set(fps))
        # snippet present for file-based findings
        app_findings = [f for f in findings if f.file_path.endswith("app.py")]
        assert all(f.snippet for f in app_findings)


def test_sast_scan_pr_marks_changed_lines(fixture_repo, fixture_diff, tmp_env):
    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project, scan_type="sast", ref_type="pr", ref_name="5",
                         engines="bandit")

    runner = ScanRunner(FakeBitbucket(fixture_repo, diff_text=fixture_diff))
    runner.run_scan(scan.id)

    with Session(engine) as session:
        scan = session.get(Scan, scan.id)
        assert scan.status == "succeeded"
        assert scan.commit_sha.startswith("aabbccdd")
        findings = session.exec(select(Finding).where(Finding.scan_id == scan.id)).all()
        assert findings
        # all bandit findings in app.py lines 6,9,15 fall within the PR diff ranges
        assert all(f.in_pr_diff for f in findings if f.tool == "bandit")


def test_upload_scan_uses_staged_workdir_without_bitbucket(fixture_repo, tmp_env):
    """ref_type='upload' scans run against a pre-staged workdir and never
    touch Bitbucket (no token/client required)."""
    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project, scan_type="sast", ref_type="upload", ref_name="my upload",
                         engines="bandit,opengrep,trivy,gitleaks")
        project_id, scan_id = project.id, scan.id

    workdir = SCAN_WORK_DIR / f"p{project_id}-s{scan_id}"
    shutil.rmtree(workdir, ignore_errors=True)
    shutil.copytree(fixture_repo, workdir)
    (workdir / ".ready").write_text("ok", encoding="utf-8")

    runner = ScanRunner()  # no bitbucket client injected
    runner.run_scan(scan_id)

    with Session(engine) as session:
        scan = session.get(Scan, scan.id)
        assert scan.status == "succeeded"
        summary = json.loads(scan.summary)
        assert summary["total"] >= 5
        findings = session.exec(select(Finding).where(Finding.scan_id == scan.id)).all()
        assert findings
        # uploaded scans have no PR diff context
        assert all(not f.in_pr_diff for f in findings)


def test_full_scan_with_no_engines_available_degrades(fixture_repo, tmp_env, monkeypatch):
    # make every engine binary undetectable -> every engine is unavailable and
    # the scan must fail loudly rather than report a false "clean" result.
    monkeypatch.setattr("src.scanners.base.which_in_path", lambda _n: None)

    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project, engines="bandit,opengrep,trivy,gitleaks")

    runner = ScanRunner(FakeBitbucket(fixture_repo))
    runner.run_scan(scan.id)

    with Session(engine) as session:
        scan = session.get(Scan, scan.id)
        assert scan.status == "failed"  # no engine completed; never report empty as clean
        states = json.loads(scan.engine_statuses)
        assert set(states) == {"bandit", "opengrep", "trivy", "gitleaks"}
        assert all(states[e]["state"] == "unavailable" for e in states)


def test_build_engine_opengrep_registry_fallback(monkeypatch, tmp_path, tmp_env):
    """The registry fallback is reachable through _build_engine only when
    explicitly enabled; otherwise OpenGrep is skipped (offline-safe)."""
    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project)

    runner = ScanRunner()
    monkeypatch.setenv("SCP_RULES_PACK_DIR", str(tmp_path))
    monkeypatch.delenv("SCP_OPENGREP_ALLOW_REGISTRY", raising=False)
    assert runner._build_engine("opengrep", tmp_path, ["python"], scan) is None

    monkeypatch.setenv("SCP_OPENGREP_ALLOW_REGISTRY", "1")
    built = runner._build_engine("opengrep", tmp_path, ["python"], scan)
    assert isinstance(built, OpengrepAdapter)


def test_scan_fails_when_engine_produces_malformed_output(fixture_repo, tmp_env, monkeypatch):
    from src.scanners.errors import ScannerMalformedOutputError

    def boom(self):
        raise ScannerMalformedOutputError("bandit", "synthetic malformed output")

    monkeypatch.setattr("src.scanners.bandit_adapter.BanditAdapter._run", boom)

    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project, scan_type="sast", engines="bandit")

    ScanRunner(FakeBitbucket(fixture_repo)).run_scan(scan.id)

    with Session(engine) as session:
        scan = session.get(Scan, scan.id)
        assert scan.status == "failed"
        states = json.loads(scan.engine_statuses)
        assert states["bandit"]["state"] == "failed"
        assert states["bandit"]["kind"] == "malformed_output"


def test_scan_fails_when_one_engine_fails_but_others_succeed(fixture_repo, tmp_env, monkeypatch):
    from src.scanners.errors import ScannerMalformedOutputError

    def boom(self):
        raise ScannerMalformedOutputError("bandit", "synthetic malformed output")

    monkeypatch.setattr("src.scanners.bandit_adapter.BanditAdapter._run", boom)

    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project, scan_type="sast", engines="bandit,gitleaks")

    ScanRunner(FakeBitbucket(fixture_repo)).run_scan(scan.id)

    with Session(engine) as session:
        scan = session.get(Scan, scan.id)
        assert scan.status == "failed"
        states = json.loads(scan.engine_statuses)
        assert states["bandit"]["state"] == "failed"
        assert states["gitleaks"]["state"] == "done"
        # findings from the healthy engine are still persisted
        findings = session.exec(select(Finding).where(Finding.scan_id == scan.id)).all()
        assert any(f.tool == "gitleaks" for f in findings)


def test_trivy_offline_fallback_persists_degraded_coverage(fixture_repo, tmp_env, monkeypatch):
    from src.scanners.trivy_adapter import TrivyAdapter

    def degraded(self):
        self.degraded_reason = "Maven rate limit; offline fallback used with reduced dependency coverage."
        return []

    monkeypatch.setattr(TrivyAdapter, "available", lambda self: True)
    monkeypatch.setattr(TrivyAdapter, "_run", degraded)
    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project, scan_type="sca", engines="trivy")

    ScanRunner(FakeBitbucket(fixture_repo)).run_scan(scan.id)

    with Session(engine) as session:
        scan = session.get(Scan, scan.id)
        assert scan.status == "succeeded"
        states = json.loads(scan.engine_statuses)
        assert states["trivy"]["state"] == "done"
        assert states["trivy"]["kind"] == "degraded"
        assert "reduced dependency coverage" in states["trivy"]["reason"]


def test_persist_redacts_secret_snippet_and_fingerprint_input(tmp_env):
    secret = "sk_live_1234567890abcdef"
    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project, scan_type="secrets", engines="gitleaks")

    snap = _snapshot(scan)
    rf = RawFinding(
        tool="gitleaks",
        source_type="secrets",
        rule_id="stripe-access-token",
        severity="high",
        file_path="app.py",
        line_start=3,
        snippet=f'api_key = "{secret}"',
        redaction_tokens=[secret],
    )
    ScanRunner()._persist(Session(engine), snap, [rf], {"gitleaks": {"state": "done"}})

    with Session(engine) as session:
        rec = session.exec(select(Finding).where(Finding.scan_id == scan.id)).one()
        assert secret not in rec.snippet
        assert "[REDACTED]" in rec.snippet
        # A plain SHA-256 fingerprint must not become an offline verifier for a
        # low-entropy secret. Deduplicate on the redacted representation.
        assert rec.fingerprint == fingerprint(
            "gitleaks", "stripe-access-token", "app.py", 3, rec.snippet
        )
        assert rec.fingerprint != fingerprint(
            "gitleaks", "stripe-access-token", "app.py", 3, rf.snippet
        )


def test_sanitize_reason_strips_workdir_prefix(tmp_env):
    prefix = str(SCAN_WORK_DIR)
    assert _sanitize_reason(f"failed reading {prefix}/p1-s2/app.py") == "failed reading <workdir>/p1-s2/app.py"
    assert _sanitize_reason("no path here") == "no path here"
    assert _sanitize_reason("") == ""


def test_engine_error_reason_sanitized_in_state_and_events(fixture_repo, tmp_env, monkeypatch):
    from src.scanners.errors import ScannerExecutionError

    prefix = str(SCAN_WORK_DIR)

    def boom(self):
        raise ScannerExecutionError("bandit", f"bandit failed reading {prefix}/p1-s2/app.py")

    monkeypatch.setattr("src.scanners.bandit_adapter.BanditAdapter._run", boom)
    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project, scan_type="sast", engines="bandit")
        scan_id = scan.id

    ScanRunner(FakeBitbucket(fixture_repo)).run_scan(scan_id)

    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan.status == "failed"
        states = json.loads(scan.engine_statuses)
        assert prefix not in states["bandit"]["reason"]
        assert "<workdir>" in states["bandit"]["reason"]

    evs, _ = event_bus.events_since(scan_id)
    engine_events = [e for e in evs if e[1] == "engine_status" and e[2].get("state") == "failed"]
    assert engine_events
    assert all(prefix not in e[2].get("reason", "") for e in engine_events)


def test_scan_failure_reason_sanitizes_workdir_path(tmp_env, monkeypatch, caplog):
    prefix = str(SCAN_WORK_DIR)

    def boom(self, session, scan):
        raise RuntimeError(f"exploded at {prefix}/p1-s2/app.py")

    monkeypatch.setattr(ScanRunner, "_execute", boom)
    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project, scan_type="sast", engines="bandit")
        scan_id = scan.id

    ScanRunner().run_scan(scan_id)

    assert prefix not in caplog.text

    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan.status == "failed"
        assert prefix not in scan.error

    evs, _ = event_bus.events_since(scan_id)
    status_events = [e for e in evs if e[1] == "scan_status" and e[2].get("status") == "failed"]
    assert status_events
    assert all(prefix not in e[2].get("error", "") for e in status_events)


def test_run_scan_cancels_cleanly_when_row_deleted(fixture_repo, tmp_env):
    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project, scan_type="sast", engines="bandit")
        scan_id = scan.id
        session.delete(scan)
        session.commit()

    # deleted row -> worker re-query returns None and cancels without raising
    ScanRunner(FakeBitbucket(fixture_repo)).run_scan(scan_id)

    with Session(engine) as session:
        assert session.get(Scan, scan_id) is None


def test_run_scan_handles_row_deleted_during_engine_execution(fixture_repo, tmp_env, monkeypatch, recwarn):
    import threading

    from src.scanners.bandit_adapter import BanditAdapter

    started = threading.Event()
    release = threading.Event()
    escaped = []

    def blocked(self):
        started.set()
        release.wait(timeout=3)
        return []

    monkeypatch.setattr(BanditAdapter, "_run", blocked)
    with Session(engine) as session:
        project = make_project(session)
        scan = make_scan(session, project, scan_type="sast", engines="bandit")
        scan_id = scan.id

    runner = ScanRunner(FakeBitbucket(fixture_repo))

    def invoke():
        try:
            runner.run_scan(scan_id)
        except Exception as exc:  # the worker boundary must contain ORM races
            escaped.append(exc)

    thread = threading.Thread(target=invoke)
    thread.start()
    assert started.wait(timeout=2)
    with Session(engine) as session:
        row = session.get(Scan, scan_id)
        assert row is not None
        session.delete(row)
        session.commit()
    release.set()
    thread.join(timeout=4)

    assert not thread.is_alive()
    assert escaped == []
    assert not any("Session's state has been changed" in str(item.message) for item in recwarn)
    with Session(engine) as session:
        assert session.get(Scan, scan_id) is None