"""Fix-rate measures over a synthetic scan history with known answers (tools/sdt_fix_rate.py)."""
from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import sdt_fix_rate  # noqa: E402
import sdt_to_docx  # noqa: E402


def code(key, level, *findings):
    return {"key": key, "kind": "code", "level": level, "class": "C1", "label": "Account takeover", "size": 1,
            "findings": list(findings)}


def secret(key, level):
    return {"key": key, "kind": "secret", "level": level, "class": "C1", "label": "Secret leak", "size": 1}


def write(history: Path, repo: str, branch: str, day: str, actions=None, decided=(), latest=False):
    state = {"version": 1, "source": "SDT", "generatedAt": f"{day}T12:00:00+07:00", "findings": {}}
    if actions is not None:
        state["actions"], state["decided"] = actions, list(decided)
    folder = history / repo / branch
    (folder / "states").mkdir(parents=True, exist_ok=True)
    (folder / "states" / f"{day.replace('-', '')}T050000Z.json").write_text(json.dumps(state))
    if latest:
        (folder / "report-state.json").write_text(json.dumps(state))


def build_history(root: Path) -> Path:
    history = root / "history"
    # alpha/main: A and B at P1 on day 0; B is gone on day 10 (and was marked Safe); A is gone on day 40,
    # when D first appears. C stays at P2, S is a P1 secret.
    write(history, "alpha", "main", "2026-01-01", [code("A", "P1", "f1", "f2"), code("B", "P1", "f3"),
                                                  code("C", "P2", "f4"), secret("S", "P1")])
    write(history, "alpha", "main", "2026-01-11", [code("A", "P1", "f1", "f2"), code("C", "P2", "f4"),
                                                  secret("S", "P1")],
          decided=[{"finding": "f3", "status": "Safe", "level": "P1"}])
    write(history, "alpha", "main", "2026-02-10", [code("C", "P2", "f4"), secret("S", "P1"), code("D", "P1", "f5")],
          decided=[{"finding": "f3", "status": "Safe", "level": "P1"},
                   {"finding": "f1", "status": "Fixed", "level": "P1"}], latest=True)
    # beta/develop: a state from before the measure (no actions); E closes after 20 days as a false positive.
    write(history, "beta", "develop", "2025-12-27")
    write(history, "beta", "develop", "2026-01-01", [code("E", "P1", "f6"), secret("F", "P2")])
    write(history, "beta", "develop", "2026-01-21", [secret("F", "P2")],
          decided=[{"finding": "f6", "status": "False positive", "level": "P1"}])
    write(history, "beta", "develop", "2026-02-05", [], latest=True)
    return history


def test_measures_per_repository_and_overall(tmp_path):
    history = build_history(tmp_path)
    rows = {(r, b): sdt_fix_rate.measure(r, b, *sdt_fix_rate.load_series(d), None)
            for r, b, d in sdt_fix_rate.discover(history)}
    alpha, beta = rows[("alpha", "main")], rows[("beta", "develop")]

    assert (alpha.scans, alpha.skipped, alpha.reported) == (3, 0, 3)  # the latest copy is not a fourth scan
    assert (alpha.closed[14], alpha.eligible[14]) == (1, 2)  # B closed after 10 days; D is too new to count
    assert (alpha.closed[30], alpha.eligible[30]) == (1, 2)  # A closed after 40 days
    assert (alpha.p1_findings, alpha.dismissed) == (4, 1)  # f1 Fixed, f2 and f5 open, f3 Safe
    assert alpha.rows == [4, 3, 3]

    assert (beta.scans, beta.skipped, beta.reported) == (3, 1, 1)
    assert (beta.closed[14], beta.eligible[14], beta.closed[30], beta.eligible[30]) == (0, 1, 1, 1)
    assert (beta.p1_findings, beta.dismissed) == (1, 1)
    assert beta.rows == [2, 1, 0]

    total = sdt_fix_rate.overall(list(rows.values()))
    assert (total.reported, total.closed[14], total.eligible[14], total.closed[30], total.eligible[30]) == (4, 1, 3, 2, 3)
    assert (total.p1_findings, total.dismissed) == (5, 2)
    assert sdt_fix_rate._median(total.rows) == 2.5


def test_window_counts_only_actions_first_reported_since(tmp_path):
    history = build_history(tmp_path)
    alpha_dir = history / "alpha" / "main"
    m = sdt_fix_rate.measure("alpha", "main", *sdt_fix_rate.load_series(alpha_dir), date(2026, 1, 5))
    assert (m.scans, m.reported) == (2, 1)  # only D is first reported in the window
    assert (m.eligible[14], m.eligible[30]) == (0, 0)  # D appeared on the last scan
    assert (m.p1_findings, m.dismissed) == (4, 1)
    assert m.rows == [3, 3]


def test_cli_writes_markdown_and_json(tmp_path, capsys):
    history = build_history(tmp_path)
    out = tmp_path / "out" / "fix-rate.md"
    assert sdt_fix_rate.main(["--history", str(history), "--out", str(out)]) == 0
    text = out.read_text()
    assert "| alpha | main | 3 | 3 | 1/2 (50%) | 1/2 (50%) | 1/4 (25%) | 3 |" in text
    assert "| beta | develop | 3 | 1 | 0/1 (0%) | 1/1 (100%) | 1/1 (100%) | 1 |" in text
    assert "| All repositories | - | 6 | 4 | 1/3 (33%) | 2/3 (67%) | 2/5 (40%) | 2.5 |" in text
    assert "1 older report states carry no action data" in text
    doc = json.loads(out.with_suffix(".json").read_text())
    assert doc["overall"]["p1Actions"] == {"reported": 4, "closedWithin14": 1, "closedWithin30": 2,
                                          "eligible14": 3, "eligible30": 3}
    assert sdt_fix_rate.main(["--history", str(tmp_path / "missing")]) == 2


def _bola(rule: str, line: int) -> sdt_to_docx.Group:
    return sdt_to_docx.Group(rule, "BOLA", "Finding", "High", occurrences=[
        sdt_to_docx.Occurrence("src/UserController.java", line, "PUT /api/users/{id}/pin", "Not reviewed", "",
                               impact="account-takeover", endpoint="PUT /api/users/{id}/pin")])


def test_report_state_actions_keep_their_key_across_line_moves_and_sources():
    def state(rule: str, line: int, resolved=None) -> dict:
        report = sdt_to_docx.Report("app", "ws/app", "main", "", "abc", "SDT", [_bola(rule, line)], [], [], [],
                                    date(2026, 11, 25), resolved=resolved)
        sdt_to_docx.prioritize(report)
        return sdt_to_docx.action_state(report, None)

    first = state("endpoints:scp.endpoints.bola-unscoped-object-access", 20)
    moved = state("endpoints:scp.endpoints.bola-unscoped-object-access", 31)
    sonar = state("external_sdt-endpoints:scp.endpoints.bola-unscoped-object-access", 20)
    assert [(a["kind"], a["level"], a["label"]) for a in first["actions"]] == [("code", "P1", "Account takeover")]
    assert first["actions"][0]["key"] == moved["actions"][0]["key"] == sonar["actions"][0]["key"]
    assert len(first["actions"][0]["findings"]) == 1 and first["decided"] == []

    decided_group = _bola("endpoints:scp.endpoints.bola-unscoped-object-access", 40)
    decided_group.occurrences[0].status = "Safe"
    with_decision = state("endpoints:scp.endpoints.bola-unscoped-object-access", 20,
                          resolved={"code": [decided_group], "secret": [], "dependency": [], "config": []})
    assert [(d["status"], d["level"]) for d in with_decision["decided"]] == [("Safe", "P1")]


def test_state_out_lists_code_actions_from_the_report_command(tmp_path, monkeypatch):
    finding = {"rule": {"id": "scp.endpoints.bola-unscoped-object-access", "name": "BOLA", "help": "Scope it."},
               "scanner": {"adapter": "endpoints"}, "category": "sast", "severity": {"canonical": "high"},
               "message": "PUT /api/users/{id}/pin accepts object parameter {id}",
               "location": {"path": "src/UserController.java", "startLine": 20, "endLine": 30},
               "metadata": {"impact": "account-takeover", "endpoint": "PUT /api/users/{id}/pin"}}
    (tmp_path / "findings.json").write_text(json.dumps({"findings": [finding]}))
    state = tmp_path / "report-state.json"
    monkeypatch.setattr(sys, "argv", ["sdt_to_docx.py", "--findings", str(tmp_path / "findings.json"),
                                      "--out", str(tmp_path / "r.docx"), "--state-out", str(state)])
    assert sdt_to_docx.main() == 0
    doc = json.loads(state.read_text())
    assert [(a["kind"], a["level"], a["label"]) for a in doc["actions"]] == [("code", "P1", "Account takeover")]
    assert doc["decided"] == [] and doc["version"] == 1 and doc["findings"]["code"]


def test_reports_sh_keeps_a_dated_copy_of_each_report_state(tmp_path):
    import os
    import subprocess

    root = Path(__file__).resolve().parent.parent
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_py = bin_dir / "python3"  # writes the --state-out file the real report command would write
    fake_py.write_text('#!/usr/bin/env bash\nwhile [ $# -gt 0 ]; do [ "$1" = --state-out ] && '
                       'echo \'{"version": 1, "actions": []}\' > "$2"; shift; done\n', encoding="utf-8")
    fake_py.chmod(0o755)
    out = tmp_path / "out"
    (out / "sdt").mkdir(parents=True)
    (out / "sdt" / "findings.json").write_text('{"findings": []}\n', encoding="utf-8")
    (out / "sdt" / "run-manifest.json").write_text('{"tasks": []}\n', encoding="utf-8")
    (out / "sonar-project-key").write_text("example-service\n", encoding="utf-8")  # history is kept with SonarQube
    (tmp_path / "src").mkdir()
    history = tmp_path / "history"
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "SRC": str(tmp_path / "src"), "OUT": str(out),
           "REPO_SLUG": "example-service", "BRANCH": "release/2.0", "SDT_HOME": str(root),
           "SDT_HISTORY_DIR": str(history), "SONAR_TOKEN": "test", "SONAR_HOST_URL": "http://sonar.invalid",
           "SDT_AI_TRIAGE": "0"}
    res = subprocess.run(["bash", str(root / "integrations/jenkins/resources/sdt/reports.sh")], env=env,
                         capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stderr
    branch = history / "example-service" / "release_2.0"
    dated = list((branch / "states").glob("*.json"))
    assert len(dated) == 1 and dated[0].read_text() == (branch / "report-state.json").read_text()
    assert [(r, b) for r, b, _ in sdt_fix_rate.discover(history)] == [("example-service", "release_2.0")]
