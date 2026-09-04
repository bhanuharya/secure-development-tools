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
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def validate_dast_url(url: str) -> str:
    """Validate a DAST target URL against the allowlist; return its hostname.

    Raises ``ValueError`` with an operator-friendly message on any violation.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"target URL must be an absolute http(s) URL: {url!r}")
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
