"""CLI tests: run src/cli.py commands against an in-process app."""

import json

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from src.api.database import Finding, Project, Scan, engine
from src.cli import Client, main


@pytest.fixture()
def asgi_base(monkeypatch):
    from src.api.main import app

    monkeypatch.setenv("SCP_URL", "http://testserver")
    tc = TestClient(app)

    class TestBackedClient(Client):
        def __init__(self, base_url: str) -> None:
            self.http = tc

    monkeypatch.setattr("src.cli.Client", TestBackedClient)
    return "http://testserver"


@pytest.fixture()
def seeded():
    with Session(engine) as session:
        project = Project(name="cli", workspace="w", repo_slug="r", default_branch="main")
        session.add(project)
        session.commit()
        session.refresh(project)
        scan = Scan(project_id=project.id, scan_type="sast", ref_type="branch", ref_name="main")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        f = Finding(
            project_id=project.id, scan_id=scan.id, tool="bandit", source_type="sast",
            rule_id="B101", severity="high", file_path="app.py", line_start=1,
            snippet="x", fingerprint="fp-cli-1",
        )
        session.add(f)
        session.commit()
        session.refresh(f)
        return {"finding_id": f.id, "scan_id": scan.id}


def test_cli_projects_list_json(asgi_base, capsys):
    main(["--json", "projects", "list"])
    out = json.loads(capsys.readouterr().out)
    assert isinstance(out, list)


def test_cli_findings_list_json(asgi_base, seeded, capsys):
    main(["--json", "findings", "list", "--severity-gte", "high"])
    out = json.loads(capsys.readouterr().out)
    assert len(out) == 1
    assert out[0]["rule_id"] == "B101"


def test_cli_findings_bulk_triage(asgi_base, seeded, capsys):
    fid = seeded["finding_id"]
    main(["--json", "findings", "bulk-triage", str(fid), "false_positive", "--reason", "fp"])
    out = json.loads(capsys.readouterr().out)
    assert out == {"changed": 1, "missing": []}

    from sqlmodel import Session

    with Session(engine) as session:
        f = session.get(Finding, fid)
        assert f.status == "false_positive"


def test_cli_scans_list_table(asgi_base, seeded, capsys):
    main(["scans", "list"])
    out = capsys.readouterr().out
    assert "succeeded" in out or "pending" in out
    assert "id" in out


def test_cli_invalid_status_exits_nonzero(asgi_base, seeded):
    with pytest.raises(SystemExit) as exc:
        main(["findings", "triage", "1", "bogus"])
    assert exc.value.code != 0
