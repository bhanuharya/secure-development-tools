"""DAST scanner adapter wrapping the OWASP ZAP client.

Lives in its own module so the engine registry can reference it without a
circular import, and so DAST failures are classified through the normal
:class:`ScannerError` taxonomy instead of a generic ``Exception``.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile

from sqlmodel import Session, select

from src.api.database import Scan, Target, engine
from src.api.events import event_bus
from src.scanners.base import RawFinding
from src.scanners.errors import ScannerExecutionError
from src.util.dastgate import (
    require_dast_control_auth,
    validate_auth_mode,
    validate_dast_auth_fields,
    validate_dast_context,
    validate_dast_url,
)
from src.util.secretbox import decrypt_secret


class DastScanner:
    """Adapter wrapper so ZAP DAST runs inside the same engine machinery."""

    name = "zap"
    source_type = "dast"

    def __init__(self, zap, scan_id: int | None, dast_target: str | None) -> None:
        self._zap = zap
        self._scan_id = scan_id
        self._dast_target = dast_target
        self.degraded_reason: str = ""

    def available(self) -> bool:
        # The registry only constructs this wrapper when ZAP is reachable.
        return True

    def run(self) -> list[RawFinding]:
        if self._scan_id is None:
            raise ScannerExecutionError("zap", "DAST scan has no scan id")
        try:
            require_dast_control_auth()
            target = self._load_authorized_target()
        except ValueError as exc:
            raise ScannerExecutionError("zap", str(exc)) from exc
        if target is None:
            raise ScannerExecutionError("zap", "DAST scan has no configured target")

        def progress(stage: str, percent: int, note: str) -> None:
            event_bus.publish(
                self._scan_id,
                "zap_progress",
                {"stage": stage, "percent": percent, "note": note},
            )

        try:
            return self._zap.run_dast(
                scan_id=self._scan_id,
                target_url=target["url"],
                auth_mode=target["auth_mode"],
                login_url=target["login_url"],
                username_field=target["username_field"],
                password_field=target["password_field"],
                auth_username=target["auth_username"],
                auth_password=target["auth_password"],
                context_file_path=target["context_file_path"],
                on_progress=progress,
            )
        finally:
            context_snapshot = target.get("_context_snapshot")
            if context_snapshot:
                try:
                    os.remove(context_snapshot)
                except OSError:
                    pass

    def _load_authorized_target(self) -> dict | None:
        if not self._dast_target:
            return None
        with Session(engine) as session:
            target = session.exec(
                select(Target).where(Target.id == self._dast_target)
            ).first()
            scan = session.get(Scan, self._scan_id)
            if target is None or scan is None:
                return None
            if not target.pre_approved:
                raise ValueError("DAST target approval was revoked before launch")
            if target.is_production and not target.production_confirmed:
                raise ValueError("DAST production acknowledgement was revoked before launch")
            if scan.dast_target_digest != _target_digest(target):
                raise ValueError("DAST target configuration changed after approval")
            validate_dast_url(target.url)
            validate_auth_mode(target.auth_mode)
            validate_dast_auth_fields(
                target.auth_mode,
                target.login_url,
                target.context_file_path,
                target.username_field,
                target.password_field,
            )
            if target.login_url:
                validate_dast_url(target.login_url)
            context_path = target.context_file_path
            context_snapshot = ""
            if context_path:
                context_path = validate_dast_context(context_path)
                context_snapshot = _snapshot_context(context_path)
            try:
                # Copy only validated scalar fields before closing the session;
                # the ZAP call must not reload mutable ORM state after this
                # boundary.
                return {
                    "url": target.url,
                    "auth_mode": target.auth_mode,
                    "login_url": target.login_url,
                    "username_field": target.username_field,
                    "password_field": target.password_field,
                    "auth_username": target.auth_username,
                    "auth_password": decrypt_secret(target.auth_password),
                    "context_file_path": context_snapshot or context_path,
                    "_context_snapshot": context_snapshot,
                }
            except Exception:
                if context_snapshot:
                    try:
                        os.remove(context_snapshot)
                    except OSError:
                        pass
                raise


def _snapshot_context(path: str) -> str:
    fd, snapshot = tempfile.mkstemp(prefix="sdt-dast-context-", suffix=".context")
    try:
        os.fchmod(fd, 0o600)
        source_fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(source_fd, "rb") as source:
            data = source.read(10 * 1024 * 1024 + 1)
        if len(data) > 10 * 1024 * 1024:
            raise ValueError("DAST context file exceeds the 10 MiB limit")
        with os.fdopen(fd, "wb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        return snapshot
    except OSError as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.remove(snapshot)
        except OSError:
            pass
        raise ValueError("DAST context file could not be snapshotted") from exc
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.remove(snapshot)
        except OSError:
            pass
        raise


def _target_digest(target: Target) -> str:
    values = {
        k: getattr(target, k, "")
        for k in (
            "url", "is_production", "auth_mode", "login_url", "username_field",
            "password_field", "auth_username", "auth_password", "context_file_path",
            "production_confirmed", "pre_approved",
        )
    }
    return hashlib.sha256(json.dumps(values, sort_keys=True, default=str).encode()).hexdigest()
