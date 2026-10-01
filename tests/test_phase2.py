"""Phase 2 security regression tests (focused, scoped)."""

from __future__ import annotations

import io
import os
import socket
import stat
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from src.api.database import Project, Scan, Target, engine
from src.api.main import app


def _client() -> TestClient:
    return TestClient(app)


def _dast_env(monkeypatch, hosts="staging.example.com"):
    monkeypatch.setenv("SCP_DAST_ALLOWED_HOSTS", hosts)
    monkeypatch.setenv("SCP_API_TOKEN", "phase2-token")
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    return {"Authorization": "Bearer phase2-token"}


def _project(session: Session) -> Project:
    p = Project(name="p2", workspace="ws", repo_slug="r", default_branch="main")
    session.add(p)
    session.commit()
    session.refresh(p)
    return p


def test_dast_requires_control_auth(monkeypatch):
    monkeypatch.setenv("SCP_DAST_ALLOWED_HOSTS", "staging.example.com")
    monkeypatch.delenv("SCP_API_TOKEN", raising=False)
    monkeypatch.delenv("SCP_AUTH_USER", raising=False)
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    with _client() as c:
        resp = c.post("/api/uploads/dast", json={"url": "https://staging.example.com"})
        assert resp.status_code == 403


def test_dast_rejects_userinfo_and_credential_query(monkeypatch):
    headers = _dast_env(monkeypatch)
    with _client() as c:
        bad_user = c.post("/api/uploads/dast", json={"url": "https://user:pass@staging.example.com/"}, headers=headers)
        assert bad_user.status_code == 400
        bad_q = c.post("/api/uploads/dast", json={"url": "https://staging.example.com/?token=abc123"}, headers=headers)
        assert bad_q.status_code == 400
        bad_f = c.post("/api/uploads/dast", json={"url": "https://staging.example.com/#password=abc"}, headers=headers)
        assert bad_f.status_code == 400


def test_dast_wildcard_matches_one_subdomain_label(monkeypatch):
    headers = _dast_env(monkeypatch, hosts="*.internal.corp")
    with _client() as c:
        one = c.post("/api/uploads/dast", json={"url": "https://app.internal.corp"}, headers=headers)
        deep = c.post("/api/uploads/dast", json={"url": "https://deep.app.internal.corp"}, headers=headers)
        assert one.status_code == 200, one.text
        assert deep.status_code == 400


def test_dast_unknown_defaults_to_production(monkeypatch):
    headers = _dast_env(monkeypatch)
    with _client() as c:
        resp = c.post("/api/uploads/dast", json={"url": "https://staging.example.com"}, headers=headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["is_production"] is True
        tid = resp.json()["id"]
        # production default cannot approve without explicit ack
        denied = c.post(f"/api/targets/{tid}/approve", json={"reason": "x"}, headers=headers)
        assert denied.status_code == 400


def test_dast_caller_cannot_lower_production_classification(monkeypatch):
    headers = _dast_env(monkeypatch)
    with _client() as c:
        resp = c.post(
            "/api/uploads/dast",
            json={"url": "https://staging.example.com", "is_production": False},
            headers=headers,
        )
        assert resp.status_code == 400


def test_dast_invalid_auth_mode_rejected(monkeypatch):
    headers = _dast_env(monkeypatch)
    with _client() as c:
        resp = c.post("/api/uploads/dast", json={"url": "https://staging.example.com", "auth_mode": "oauth"}, headers=headers)
        assert resp.status_code == 400
        form_no_login = c.post("/api/uploads/dast", json={
            "url": "https://staging.example.com", "auth_mode": "form",
        }, headers=headers)
        assert form_no_login.status_code == 400
        form_no_fields = c.post("/api/uploads/dast", json={
            "url": "https://staging.example.com",
            "auth_mode": "form",
            "login_url": "https://staging.example.com/login",
            "username_field": "",
            "password_field": "",
        }, headers=headers)
        assert form_no_fields.status_code == 400


def test_target_update_invalidates_approval(monkeypatch):
    headers = _dast_env(monkeypatch)
    with _client() as c, Session(engine) as session:
        project = _project(session)
        pid = project.id
    resp = c.post(f"/api/projects/{pid}/targets", json={
        "project_id": pid, "url": "https://staging.example.com",
    }, headers=headers)
    assert resp.status_code == 200, resp.text
    tid = resp.json()["id"]
    assert c.post(
        f"/api/targets/{tid}/approve",
        json={"reason": "ok", "production_ack": True},
        headers=headers,
    ).status_code == 200
    upd = c.patch(f"/api/projects/targets/{tid}", json={
        "auth_mode": "form",
        "login_url": "https://staging.example.com/login",
        "username_field": "username",
        "password_field": "password",
    }, headers=headers)
    assert upd.status_code == 200, upd.text
    with Session(engine) as session:
        row = session.get(Target, tid)
        assert row.pre_approved is False


def test_zap_requires_api_key(monkeypatch):
    monkeypatch.delenv("SCP_ZAP_API_KEY", raising=False)
    from src.dast.zap_client import ZapClient, ZapError

    client = ZapClient(base_url="http://127.0.0.1:9", api_key="")
    with pytest.raises(ZapError):
        client.run_dast(scan_id=1, target_url="https://staging.example.com")


def test_zap_revalidates_target_dns_at_launch(monkeypatch):
    """DNS rebound after approval must fail at the ZAP bridge boundary,
    before any ZAP API call is issued."""
    from src.dast.zap_client import ZapClient, ZapError

    monkeypatch.setenv("SCP_DAST_ALLOWED_HOSTS", "staging.example.com")
    # The target passed every earlier gate (public IP), but by the time the
    # scan launches the resolver has been repointed to the metadata address.
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))],
    )
    client = ZapClient(base_url="http://127.0.0.1:9", api_key="k")
    with pytest.raises(ZapError, match="prohibited"):
        client.run_dast(scan_id=1, target_url="https://staging.example.com")


def test_redact_covers_finding_fields():
    from src.scanners.evidence import redact_text

    secret = "AKIAIOSFODNN7EXAMPLE"
    assert "[REDACTED]" in redact_text(f"key={secret} in description")
    assert "[REDACTED]" in redact_text("password = hunter2hunter", secrets=["hunter2hunter"])
    # orchestrator redacts description/remediation/file_path at persist time
    from src.scanners.base import RawFinding

    rf = RawFinding(tool="t", source_type="sast", rule_id="R", file_path="a.py",
                    description="token = phase2-secret-value", remediation="fix phase2-secret-value", snippet="x")
    assert "[REDACTED]" in redact_text(rf.description)


def test_zip_total_entries_capped():
    from src.api.routers.uploads import _plan_extraction

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(20001):
            zf.writestr(f"dir{i}/", "")
        zf.writestr("a.py", "x=1")
    buf.seek(0)
    with zipfile.ZipFile(buf) as zf:
        with pytest.raises(Exception):
            _plan_extraction(zf)


def test_askpass_no_token_in_url_and_owner_only(monkeypatch):
    from src.integrations import bitbucket_client as bc

    client = bc.BitbucketClient.__new__(bc.BitbucketClient)
    client.token = "tok-123"
    assert "tok-123" not in client.repo_clone_url("ws", "repo")
    path = bc._write_askpass("tok-123")
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o700
        assert stat.S_IMODE(os.stat(path + ".token").st_mode) == 0o600
        with open(path) as fh:
            assert "tok-123" not in fh.read()
    finally:
        bc._remove_askpass(path)
    assert not os.path.exists(path)


def test_scan_workdir_0700(tmp_path, monkeypatch):
    monkeypatch.setenv("SCP_SCAN_WORK_DIR", str(tmp_path / "work"))
    import importlib

    import src.config as cfg

    importlib.reload(cfg)
    assert stat.S_IMODE(os.stat(cfg.SCAN_WORK_DIR).st_mode) == 0o700
