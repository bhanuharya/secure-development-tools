"""DAST scanner adapter wrapping the OWASP ZAP client.

Lives in its own module so the engine registry can reference it without a
circular import, and so DAST failures are classified through the normal
:class:`ScannerError` taxonomy instead of a generic ``Exception``.
"""

from __future__ import annotations

from sqlmodel import Session, select

from src.api.database import Target, engine
from src.api.events import event_bus
from src.scanners.base import RawFinding
from src.scanners.errors import ScannerExecutionError
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
        target = self._load_target()
        if target is None:
            raise ScannerExecutionError("zap", "DAST scan has no configured target")

        def progress(stage: str, percent: int, note: str) -> None:
            event_bus.publish(
                self._scan_id,
                "zap_progress",
                {"stage": stage, "percent": percent, "note": note},
            )

        return self._zap.run_dast(
            scan_id=self._scan_id,
            target_url=target.url,
            auth_mode=target.auth_mode,
            login_url=target.login_url,
            username_field=target.username_field,
            password_field=target.password_field,
            auth_username=target.auth_username,
            auth_password=decrypt_secret(target.auth_password),
            context_file_path=target.context_file_path,
            on_progress=progress,
        )

    def _load_target(self):
        if not self._dast_target:
            return None
        with Session(engine) as session:
            return session.exec(
                select(Target).where(Target.id == self._dast_target)
            ).first()
