"""Auth (HTTP Basic) + security headers tests.

Auth is opt-in via SCP_AUTH_USER / SCP_AUTH_PASS env vars, read at request
time, so every test builds a fresh TestClient after monkeypatching env.
"""

import base64

from fastapi.testclient import TestClient

from src.api.main import app


def _auth_header(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _client() -> TestClient:
    return TestClient(app)


def test_auth_disabled_default(monkeypatch):
    monkeypatch.delenv("SCP_AUTH_USER", raising=False)
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    with _client() as c:
        assert c.get("/api/health").status_code == 200
        assert c.get("/").status_code == 200


def test_health_public_when_auth_on(monkeypatch):
    monkeypatch.setenv("SCP_AUTH_USER", "admin")
    monkeypatch.setenv("SCP_AUTH_PASS", "s3cret")
    with _client() as c:
        assert c.get("/api/health").status_code == 200


def test_api_requires_auth(monkeypatch):
    monkeypatch.setenv("SCP_AUTH_USER", "admin")
    monkeypatch.setenv("SCP_AUTH_PASS", "s3cret")
    with _client() as c:
        assert c.get("/api/projects").status_code == 401
        assert c.get("/api/projects", headers=_auth_header("admin", "s3cret")).status_code == 200
        assert c.get("/api/projects", headers=_auth_header("admin", "wrong")).status_code == 401
        assert c.get("/api/projects", headers=_auth_header("nobody", "s3cret")).status_code == 401


def test_dashboard_requires_auth(monkeypatch):
    monkeypatch.setenv("SCP_AUTH_USER", "admin")
    monkeypatch.setenv("SCP_AUTH_PASS", "s3cret")
    with _client() as c:
        assert c.get("/").status_code == 401
        assert c.get("/", headers=_auth_header("admin", "s3cret")).status_code == 200
        assert c.get("/css/base.css", headers=_auth_header("admin", "s3cret")).status_code == 200


def test_security_headers_present(monkeypatch):
    monkeypatch.delenv("SCP_AUTH_USER", raising=False)
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    with _client() as c:
        for path in ("/", "/css/base.css", "/api/health"):
            resp = c.get(path)
            assert resp.status_code == 200, path
            headers = resp.headers
            assert headers["content-security-policy"].startswith("default-src 'self'")
            assert "script-src 'self' 'unsafe-inline'" in headers["content-security-policy"]
            assert headers["x-content-type-options"] == "nosniff"
            assert headers["x-frame-options"] == "DENY"
            assert headers["referrer-policy"] == "no-referrer"
            assert headers["permissions-policy"].startswith("camera=()")
