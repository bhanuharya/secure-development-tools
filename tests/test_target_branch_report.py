"""A pull request scan also reports its target branch from the baseline scan (reports.sh)."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "integrations" / "jenkins" / "resources" / "sdt" / "reports.sh"

# Stands in for python3: records each call, says whether --src-root held the target branch's files, and
# writes the --out file the real report command would write.
FAKE_PYTHON = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$CALLS"
args=("$@")
for i in "${!args[@]}"; do
  case "${args[$i]}" in
    --src-root) [ -f "${args[$((i + 1))]}/pom.xml" ] && echo "src-root has pom.xml" >> "$CALLS" ;;
    --out) printf 'docx' > "${args[$((i + 1))]}" ;;
  esac
done
"""


def git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def scan(tmp_path: Path, baseline: bool = True, **extra) -> tuple[subprocess.CompletedProcess, Path, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "python3").write_text(FAKE_PYTHON, encoding="utf-8")
    (bin_dir / "python3").chmod(0o755)
    src = tmp_path / "src"
    if not src.exists():
        src.mkdir()
        git("init", "-q", "-b", "main", cwd=src)
        (src / "pom.xml").write_text("<project/>\n", encoding="utf-8")
        git("add", ".", cwd=src)
        git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "base", cwd=src)
        git("update-ref", "refs/remotes/origin/release/2.0", "HEAD", cwd=src)
    out = tmp_path / "out"
    (out / "sdt").mkdir(parents=True, exist_ok=True)
    (out / "base").mkdir(exist_ok=True)
    (out / "sdt" / "findings.json").write_text('{"findings": []}\n', encoding="utf-8")
    (out / "base" / "findings.json").unlink(missing_ok=True)
    if baseline:  # scan.sh writes it for a pull request (no baseline: no verdict, and no target report)
        (out / "base" / "findings.json").write_text('{"findings": []}\n', encoding="utf-8")
    (out / "sdt" / "run-manifest.json").write_text('{"tasks": []}\n', encoding="utf-8")
    calls = tmp_path / "calls.log"
    calls.unlink(missing_ok=True)
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "CALLS": str(calls), "SRC": str(src), "OUT": str(out),
           "REPO_SLUG": "shop", "WORKSPACE_NAME": "ws", "PR_ID": "42", "PR_BASE": "release/2.0",
           "SDT_HOME": str(ROOT), **extra}
    done = subprocess.run(["bash", str(REPORTS)], env=env, capture_output=True, text=True, check=False)
    return done, out, calls.read_text() if calls.exists() else ""


def test_pull_request_scan_writes_a_target_branch_report_from_the_baseline(tmp_path):
    done, out, calls = scan(tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    reports = list((out / "target-branch").glob("*.docx"))
    assert len(reports) == 1 and reports[0].name.startswith("SAST Report - shop - PR 42 - target release_2.0 - ")
    call = next(line for line in calls.splitlines() if str(out / "base" / "findings.json") in line)
    commit = git("rev-parse", "HEAD", cwd=tmp_path / "src")
    assert f"--branch release/2.0" in call and f"--commit {commit}" in call and "--project-name shop" in call
    assert "src-root has pom.xml" in calls  # the target branch's files, for excerpts and the Maven parent
    assert not (out / "target-branch-src").exists()
    # The pull request's own report stays where the comment and the publisher look for it.
    assert len(list(out.glob("SAST Report - shop - PR 42 - *.docx"))) == 1


def test_target_branch_report_can_be_turned_off_and_needs_a_baseline(tmp_path):
    done, out, calls = scan(tmp_path, SDT_PR_BASE_REPORT="0")
    assert done.returncode == 0 and not (out / "target-branch").exists()
    done, out, calls = scan(tmp_path, baseline=False)
    assert done.returncode == 0 and not list((out / "target-branch").glob("*.docx"))


def test_branch_scan_writes_no_target_branch_report(tmp_path):
    done, out, calls = scan(tmp_path, PR_ID="", BRANCH="main")
    assert done.returncode == 0, done.stderr
    assert not (out / "target-branch").exists() and str(out / "base" / "findings.json") not in calls
