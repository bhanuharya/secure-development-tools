"""Auth (HTTP Basic) + security headers tests.

Auth is opt-in via SCP_AUTH_USER / SCP_AUTH_PASS env vars, read at request
time, so every test builds a fresh TestClient after monkeypatching env.
"""

import base64
import time

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.security import auth_enabled
from src.config import ConfigurationError


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


# ------------------------------------------------------ localhost-only default

def _asgi_request(method: str, path: str, peer: tuple[str, int], **kwargs) -> "httpx.Response":
    """Issue a request against the app with an explicit ASGI peer address, as
    uvicorn would report it for a TCP connection from that host."""
    import asyncio

    import httpx

    async def call() -> "httpx.Response":
        transport = httpx.ASGITransport(app=app, client=peer)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            return await c.request(method, path, **kwargs)

    return asyncio.run(call())


REMOTE_PEER = ("203.0.113.7", 40000)


def test_unauthenticated_remote_peer_rejected(monkeypatch):
    """Without credentials the control plane is localhost-only, regardless of
    the bind address: remote peers get 403 on every path, health included."""
    monkeypatch.delenv("SCP_AUTH_USER", raising=False)
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    monkeypatch.delenv("SCP_API_TOKEN", raising=False)
    for path in ("/api/health", "/", "/api/projects"):
        resp = _asgi_request("GET", path, REMOTE_PEER)
        assert resp.status_code == 403, path
        assert "localhost" in resp.json()["detail"]
    resp = _asgi_request("POST", "/api/projects", REMOTE_PEER, json={"workspace": "w", "repo_slug": "r"})
    assert resp.status_code == 403


def test_remote_peer_allowed_with_basic_auth(monkeypatch):
    monkeypatch.setenv("SCP_AUTH_USER", "admin")
    monkeypatch.setenv("SCP_AUTH_PASS", "s3cret")
    assert _asgi_request("GET", "/api/projects", REMOTE_PEER).status_code == 401
    assert _asgi_request("GET", "/api/projects", REMOTE_PEER, headers=_auth_header("admin", "s3cret")).status_code == 200


def test_remote_peer_allowed_with_token(monkeypatch):
    monkeypatch.delenv("SCP_AUTH_USER", raising=False)
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    monkeypatch.setenv("SCP_API_TOKEN", "bot-token-123")
    resp = _asgi_request("GET", "/api/projects", REMOTE_PEER, headers={"Authorization": "Bearer bot-token-123"})
    assert resp.status_code == 200


def test_loopback_peer_accepted_without_auth(monkeypatch):
    monkeypatch.delenv("SCP_AUTH_USER", raising=False)
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    assert _asgi_request("GET", "/api/projects", ("127.0.0.1", 40000)).status_code == 200


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


def test_auth_enabled_partial_config_raises(monkeypatch):
    monkeypatch.setenv("SCP_AUTH_USER", "admin")
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    with pytest.raises(ConfigurationError):
        auth_enabled()

    monkeypatch.delenv("SCP_AUTH_USER", raising=False)
    monkeypatch.setenv("SCP_AUTH_PASS", "s3cret")
    with pytest.raises(ConfigurationError):
        auth_enabled()


def test_partial_auth_config_fails_closed(monkeypatch):
    # exactly one credential set -> deny requests rather than silently allow
    monkeypatch.setenv("SCP_AUTH_USER", "admin")
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    with _client() as c:
        assert c.get("/").status_code == 401
        assert c.get("/api/health").status_code == 200  # public health stays open


# ------------------------------------------------------------------ API token

def test_bearer_token_grants_access(monkeypatch):
    monkeypatch.delenv("SCP_AUTH_USER", raising=False)
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    monkeypatch.setenv("SCP_API_TOKEN", "bot-token-123")
    with _client() as c:
        assert c.get("/api/projects").status_code == 401
        assert c.get(
            "/api/projects", headers={"Authorization": "Bearer bot-token-123"}
        ).status_code == 200
        assert c.get(
            "/api/projects", headers={"Authorization": "Bearer wrong-token"}
        ).status_code == 401


def test_bearer_token_covers_dashboard(monkeypatch):
    monkeypatch.delenv("SCP_AUTH_USER", raising=False)
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    monkeypatch.setenv("SCP_API_TOKEN", "bot-token-123")
    with _client() as c:
        assert c.get("/", headers={"Authorization": "Bearer bot-token-123"}).status_code == 200


def test_basic_still_works_alongside_token(monkeypatch):
    monkeypatch.setenv("SCP_AUTH_USER", "admin")
    monkeypatch.setenv("SCP_AUTH_PASS", "s3cret")
    monkeypatch.setenv("SCP_API_TOKEN", "bot-token-123")
    with _client() as c:
        assert c.get("/api/projects", headers=_auth_header("admin", "s3cret")).status_code == 200
        assert c.get(
            "/api/projects", headers={"Authorization": "Bearer bot-token-123"}
        ).status_code == 200
        assert c.get("/api/projects").status_code == 401


def test_token_only_enables_auth(monkeypatch):
    """A token alone (no Basic creds) enforces auth — not an open instance."""
    monkeypatch.delenv("SCP_AUTH_USER", raising=False)
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    monkeypatch.setenv("SCP_API_TOKEN", "bot-token-123")
    assert auth_enabled() is True


@pytest.fixture(autouse=True)
def _clear_failure_state():
    # auth throttling keeps per-IP state in the middleware module; reset it so
    # one test's failed attempts cannot lock out the next test
    import src.api.security as security

    security._FAILURES.clear()
    yield
    security._FAILURES.clear()


def test_cross_site_state_change_rejected(monkeypatch):
    monkeypatch.delenv("SCP_AUTH_USER", raising=False)
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    with _client() as c:
        # modern browsers: Sec-Fetch-Site
        resp = c.post(
            "/api/projects",
            json={"workspace": "w", "repo_slug": "r"},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert resp.status_code == 403
        # older browsers: mismatched Origin
        resp = c.post(
            "/api/projects",
            json={"workspace": "w", "repo_slug": "r"},
            headers={"Origin": "https://evil.example"},
        )
        assert resp.status_code == 403
        # same-origin + no-header (curl/CLI) still pass
        assert c.post(
            "/api/projects",
            json={"workspace": "w", "repo_slug": "r"},
            headers={"Sec-Fetch-Site": "same-origin"},
        ).status_code == 200
        assert c.post(
            "/api/projects", json={"workspace": "w2", "repo_slug": "r2"}
        ).status_code == 200


def test_cross_site_get_allowed(monkeypatch):
    monkeypatch.delenv("SCP_AUTH_USER", raising=False)
    monkeypatch.delenv("SCP_AUTH_PASS", raising=False)
    with _client() as c:
        resp = c.get("/api/projects", headers={"Sec-Fetch-Site": "cross-site"})
        assert resp.status_code == 200


def test_failed_auth_lockout(monkeypatch):
    import src.api.security as security

    monkeypatch.setenv("SCP_AUTH_USER", "admin")
    monkeypatch.setenv("SCP_AUTH_PASS", "s3cret")
    monkeypatch.setattr(security, "AUTH_LOCKOUT_SECONDS", 30.0)
    with _client() as c:
        for _ in range(security.AUTH_MAX_FAILURES):
            # the final failure arms the lockout but still answers 401
            assert c.get("/api/projects", headers=_auth_header("admin", "wrong")).status_code == 401
        # everything during the lockout window is throttled, even valid creds
        assert c.get("/api/projects", headers=_auth_header("admin", "s3cret")).status_code == 429
        assert c.get("/api/projects", headers=_auth_header("admin", "wrong")).status_code == 429
        # ...and recover once the window passes (expired by hand, no sleep)
        import time as _time

        security._FAILURES["testclient"]["blocked_until"] = _time.monotonic() - 1
        assert c.get("/api/projects", headers=_auth_header("admin", "s3cret")).status_code == 200


def test_success_resets_failure_counter(monkeypatch):
    import src.api.security as security

    monkeypatch.setenv("SCP_AUTH_USER", "admin")
    monkeypatch.setenv("SCP_AUTH_PASS", "s3cret")
    with _client() as c:
        for _ in range(security.AUTH_MAX_FAILURES - 1):
            c.get("/api/projects", headers=_auth_header("admin", "wrong"))
        assert c.get("/api/projects", headers=_auth_header("admin", "s3cret")).status_code == 200
        # counter was reset, so failures start from zero again
        for _ in range(security.AUTH_MAX_FAILURES - 1):
            assert c.get("/api/projects", headers=_auth_header("admin", "wrong")).status_code == 401
