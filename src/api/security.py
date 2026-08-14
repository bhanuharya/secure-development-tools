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

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# Paths that stay public even when auth is enabled.
PUBLIC_PATHS = {"/api/health"}

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
    """Auth is enforced only when both credential env vars are set."""
    return bool(os.getenv("SCP_AUTH_USER", "")) and bool(os.getenv("SCP_AUTH_PASS", ""))


def _credentials_ok(user: str, password: str) -> bool:
    expected_user = os.getenv("SCP_AUTH_USER", "")
    expected_pass = os.getenv("SCP_AUTH_PASS", "")
    return hmac.compare_digest(user, expected_user) and hmac.compare_digest(
        password, expected_pass
    )


class AuthMiddleware(BaseHTTPMiddleware):
    """HTTP Basic authentication. Covers API routers AND the static dashboard
    mount because it runs at the app level."""

    async def dispatch(self, request: Request, call_next) -> Response:
        if not auth_enabled() or request.url.path in PUBLIC_PATHS:
            return await call_next(request)

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
        if not ok:
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
