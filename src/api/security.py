"""HTTP Basic auth + security headers middleware for the control plane.

Auth is OPT-IN: it only enforces credentials when both SCP_AUTH_USER and
SCP_AUTH_PASS are set in the environment. Credentials are read at request time
so tests can toggle them per-test and the live service can be reconfigured by
restarting with different env vars.

Security headers are applied to every response, including static dashboard
assets and error responses. The CSP intentionally allows inline scripts/styles
because the dashboard (vanilla JS) uses inline event handlers and style
attributes.
"""

from __future__ import annotations

import base64
import hmac
import os
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from src.config import ConfigurationError

# Paths that stay public even when auth is enabled.
PUBLIC_PATHS = {"/api/health"}

# Brute-force throttling for failed auth attempts, per client IP.
AUTH_MAX_FAILURES = 5
AUTH_LOCKOUT_SECONDS = 30.0
_FAILURES: dict[str, dict] = {}  # ip -> {failures, blocked_until, last}

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; font-src 'self'; base-uri 'self'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}


def auth_enabled() -> bool:
    """Auth is enforced when HTTP Basic credentials are configured OR an API
    token is set.

    Partial Basic configuration (exactly one credential set) fails closed by
    raising :class:`ConfigurationError`: it is never safe to silently run
    without auth when the operator clearly intended to configure it.
    """
    user = os.getenv("SCP_AUTH_USER", "")
    password = os.getenv("SCP_AUTH_PASS", "")
    has_user = bool(user)
    has_pass = bool(password)
    if has_user != has_pass:
        raise ConfigurationError(
            "partial HTTP Basic auth configuration: exactly one of "
            "SCP_AUTH_USER / SCP_AUTH_PASS is set; set both or neither"
        )
    token = os.getenv("SCP_API_TOKEN", "")
    return (has_user and has_pass) or bool(token)


def _credentials_ok(user: str, password: str) -> bool:
    expected_user = os.getenv("SCP_AUTH_USER", "")
    expected_pass = os.getenv("SCP_AUTH_PASS", "")
    return hmac.compare_digest(user, expected_user) and hmac.compare_digest(
        password, expected_pass
    )


def _token_ok(token: str) -> bool:
    expected = os.getenv("SCP_API_TOKEN", "")
    if not expected:
        return False
    return hmac.compare_digest(token, expected)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _throttled(ip: str) -> float:
    """Return remaining lockout seconds for an over-failing client, else 0."""
    state = _FAILURES.get(ip)
    if not state:
        return 0.0
    now = time.monotonic()
    if state["blocked_until"] > now:
        return state["blocked_until"] - now
    if now - state["last"] > AUTH_LOCKOUT_SECONDS * 10:
        _FAILURES.pop(ip, None)  # idle entry: stop the dict growing forever
    return 0.0


def _record_failure(ip: str) -> None:
    state = _FAILURES.get(ip) or {"failures": 0, "blocked_until": 0.0, "last": 0.0}
    state["failures"] += 1
    state["last"] = time.monotonic()
    if state["failures"] >= AUTH_MAX_FAILURES:
        state["blocked_until"] = state["last"] + AUTH_LOCKOUT_SECONDS
    _FAILURES[ip] = state


def _record_success(ip: str) -> None:
    _FAILURES.pop(ip, None)


def _cross_site(request: Request) -> bool:
    """Best-effort CSRF detection for state-changing requests.

    Modern browsers send Sec-Fetch-Site; when present, anything other than
    same-origin/same-site/none is cross-site. Older browsers fall back to an
    Origin header comparison against the request host. Requests with neither
    header (curl, CLI bots) pass — non-browser clients are not CSRF subjects.
    """
    if request.method in SAFE_METHODS:
        return False
    site = request.headers.get("sec-fetch-site")
    if site:
        return site not in ("same-origin", "same-site", "none")
    origin = request.headers.get("origin")
    if origin:
        host = request.headers.get("host", "")
        return host not in (origin.removeprefix("https://").removeprefix("http://"),)
    return False


class AuthMiddleware(BaseHTTPMiddleware):
    """HTTP Basic auth + optional Bearer API token + CSRF + throttling.

    Covers API routers AND the static dashboard mount because it runs at the
    app level. Cross-site state-changing requests are rejected even when auth
    is disabled: multipart/form-data endpoints (e.g. the ZIP upload) are
    simple requests that browsers would otherwise send cross-site with ambient
    Basic credentials.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if _cross_site(request):
            return JSONResponse(
                status_code=403, content={"detail": "cross-site request rejected"}
            )
        try:
            enabled = auth_enabled()
        except ConfigurationError as exc:
            # Partial auth configuration: fail closed. Health stays public so
            # operators can still observe the misconfigured instance.
            if request.url.path in PUBLIC_PATHS:
                return await call_next(request)
            return JSONResponse(
                status_code=401,
                content={"detail": f"misconfigured auth: {exc}"},
                headers={"WWW-Authenticate": 'Basic realm="Secure SDLC"'},
            )
        if not enabled or request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        ip = _client_ip(request)
        remaining = _throttled(ip)
        if remaining > 0:
            return JSONResponse(
                status_code=429,
                content={"detail": f"too many failed attempts; retry in {remaining:.0f}s"},
                headers={"Retry-After": str(int(remaining) + 1)},
            )

        header = request.headers.get("authorization", "")
        ok = False
        if header.startswith("Basic "):
            try:
                decoded = base64.b64decode(header[6:].strip()).decode(
                    "utf-8", errors="replace"
                )
                user, _, password = decoded.partition(":")
                ok = _credentials_ok(user, password)
            except Exception:  # noqa: BLE001 - malformed header -> deny
                ok = False
        elif header.startswith("Bearer "):
            ok = _token_ok(header[7:].strip())
        if ok:
            _record_success(ip)
        else:
            _record_failure(ip)
            return JSONResponse(
                status_code=401,
                content={"detail": "unauthorized"},
                headers={"WWW-Authenticate": 'Basic realm="Secure SDLC"'},
            )
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach hardening headers to every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response
