import json
import shutil

from sqlmodel import Session, select

from src.api.database import Finding, Project, Scan, engine
from src.config import SCAN_WORK_DIR
from src.scanners.orchestrator import ScanRunner
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