"""DAST target host allowlist.

``SCP_DAST_ALLOWED_HOSTS`` (comma-separated) restricts which hostnames may be
registered as DAST targets, mirroring the ``SCP_LOCAL_SCAN_ROOTS`` design:
empty = no hosts allowed (fail closed), a set
entry of ``*.example.com`` allows any single-level subdomain, and a bare
``example.com`` matches exactly that host. Read at call time so tests can
toggle it per-test.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from pathlib import Path
from urllib.parse import urlsplit


def allowed_hosts() -> tuple[str, ...]:
    return tuple(
        h.strip().lower()
        for h in os.getenv("SCP_DAST_ALLOWED_HOSTS", "").split(",")
        if h.strip()
    )


def _host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[2:]
        suffix_with_dot = "." + suffix
        # The documented wildcard is exactly one additional label, not an
        # arbitrary-depth descendant wildcard.
        return (
            bool(suffix)
            and host.endswith(suffix_with_dot)
            and host.count(".") == suffix.count(".") + 1
        )
    return host == pattern


# Credential material must never ride in a DAST URL query/fragment (it would
# persist in the DB, logs, and ZAP scope). Match key=value pairs for common
# credential names.
_CREDENTIAL_QUERY_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth|session|"
    r"sessionid|access[_-]?token|client[_-]?secret)\s*="
)

AUTH_MODES = ("none", "form", "context_file")


def validate_auth_mode(mode: str) -> str:
    """Validate the ZAP authentication mode."""
    if mode not in AUTH_MODES:
        raise ValueError(f"auth_mode must be one of {list(AUTH_MODES)}")
    return mode


def validate_dast_auth_fields(
    auth_mode: str,
    login_url: str = "",
    context_file_path: str = "",
    username_field: str = "username",
    password_field: str = "password",
) -> None:
    """Validate login_url/context_file_path coherence for an auth mode.

    form requires a validated login_url; context_file requires a validated
    context path; none forbids both so credentials cannot linger on an
    allegedly unauthenticated target.
    """
    validate_auth_mode(auth_mode)
    if auth_mode == "form":
        if not login_url:
            raise ValueError("login_url is required when auth_mode=form")
        if not username_field or not password_field:
            raise ValueError("username_field and password_field are required when auth_mode=form")
        validate_dast_url(login_url)
    elif auth_mode == "context_file":
        if not context_file_path:
            raise ValueError("context_file_path is required when auth_mode=context_file")
    else:  # none
        if login_url:
            raise ValueError("login_url must be empty when auth_mode=none")
        if context_file_path:
            raise ValueError("context_file_path must be empty when auth_mode=none")


def require_dast_control_auth() -> None:
    """Fail closed when DAST is requested on an unauthenticated service.

    Active DAST is an attack primitive: it must never be operable on a
    control plane without authentication (HTTP Basic or API token).
    """
    from src.api.security import auth_enabled

    try:
        enabled = auth_enabled()
    except Exception as exc:
        raise ValueError(f"misconfigured auth: {exc}") from exc
    if not enabled:
        raise ValueError(
            "DAST requires control-plane authentication: set SCP_AUTH_USER/SCP_AUTH_PASS or SCP_API_TOKEN"
        )


def validate_dast_url(url: str) -> str:
    """Validate a DAST target URL against the allowlist; return its hostname.

    Rejects URL userinfo (credentials in the authority) and credential-bearing
    query/fragment material, then enforces the host allowlist and DNS safety.
    Raises ``ValueError`` with an operator-friendly message on any violation.
    """
    if not url or not isinstance(url, str):
        raise ValueError("target URL must be an absolute http(s) URL")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"target URL must be an absolute http(s) URL: {url!r}")
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        raise ValueError("target URL must not contain userinfo/credentials")
    haystack = f"{parts.query or ''}\n{parts.fragment or ''}"
    if haystack.strip() and _CREDENTIAL_QUERY_RE.search(haystack):
        raise ValueError("target URL must not carry credentials in query/fragment")
    host = parts.hostname.lower()
    patterns = allowed_hosts()
    if not patterns or not any(_host_matches(host, p) for p in patterns):
        raise ValueError(
            f"target host {host!r} is not in SCP_DAST_ALLOWED_HOSTS (allowlist required)"
        )
    # Validate every resolved address, not just the hostname (DNS rebinding and
    # cloud metadata endpoints must never be reachable by ZAP).
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise ValueError(f"target host {host!r} cannot be resolved") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        blocked = (ip.is_private or ip.is_loopback or ip.is_link_local or
                   ip.is_reserved or ip.is_unspecified or
                   ip in ipaddress.ip_network("100.64.0.0/10"))
        if blocked:
            raise ValueError(f"target host {host!r} resolves to a prohibited address")
        if ip in ipaddress.ip_network("169.254.169.254/32") or ip in ipaddress.ip_network("100.100.100.0/24"):
            raise ValueError(f"target host {host!r} resolves to a metadata address")
    return host


def validate_dast_context(path: str) -> str:
    """Allow context imports only from explicitly configured roots."""
    if not path:
        raise ValueError("context_file_path is required")
    roots = tuple(p for p in os.getenv("SCP_DAST_CONTEXT_ROOTS", "").split(os.pathsep) if p)
    if not roots:
        raise ValueError("context imports are disabled: set SCP_DAST_CONTEXT_ROOTS")
    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file() or candidate.is_symlink():
            raise ValueError("context file must be a regular, non-symlink file")
        if not any(resolved.is_relative_to(Path(root).expanduser().resolve()) for root in roots):
            raise ValueError("context file is outside SCP_DAST_CONTEXT_ROOTS")
    except OSError as exc:
        raise ValueError("context file is not accessible") from exc
    return str(resolved)
