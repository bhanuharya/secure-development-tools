from __future__ import annotations

import abc
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from src.config import ENGINE_BINARIES
from src.scanners.errors import (
    ScannerExecutionError,
    ScannerTimeoutError,
    ScannerUnavailableError,
)

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}


def which_in_path(name: str) -> str | None:
    """Like shutil.which but also checks the current interpreter's bin dir
    (so engines installed into the venv are found without PATH tweaks)."""
    candidates = []
    interpreter_dir = Path(sys.executable).parent
    candidates.append(interpreter_dir / name)
    seen = os.environ.get("PATH", "")
    for entry in seen.split(os.pathsep):
        if entry:
            candidates.append(Path(entry) / name)
    for cand in candidates:
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return None


@dataclass
class RawFinding:
    tool: str
    source_type: str  # sast | sca | secrets | dast
    rule_id: str
    severity: str = "info"
    cwe: str = ""
    file_path: str = ""
    line_start: int | None = None
    line_end: int | None = None
    col_start: int | None = None
    col_end: int | None = None
    snippet: str = ""
    description: str = ""
    remediation: str = ""
    raw: dict = field(default_factory=dict)
    # Transient values used only to redact source context. Hidden from repr and
    # never copied into the Finding row/evidence document.
    redaction_tokens: list[str] = field(default_factory=list, repr=False)


def normalize_severity(value: str | None) -> str:
    v = (value or "").strip().lower()
    mapping = {
        "critical": "critical", "high": "high", "error": "high", "medium": "medium",
        "moderate": "medium", "warning": "medium", "low": "low", "info": "info",
        "informational": "info", "note": "info", "unknown": "info",
    }
    return mapping.get(v, "low")


class Scanner(abc.ABC):
    """Base class for a scanning engine. Runs against a local checkout."""

    name: str = "base"
    source_type: str = "sast"
    workdir: Path

    def __init__(self, workdir: Path) -> None:
        self.workdir = Path(workdir)

    @property
    def binary(self) -> str | None:
        configured = ENGINE_BINARIES.get(self.name, self.name)
        return which_in_path(configured)

    def available(self) -> bool:
        return self.binary is not None

    def run(self) -> list[RawFinding]:
        if not self.available():
            raise ScannerUnavailableError(self.name, f"{self.name} executable not found")
        return self._run()

    @abc.abstractmethod
    def _run(self) -> list[RawFinding]:
        ...

    def _exec(self, args: list[str], cwd: str | None = None, timeout: int | None = None) -> subprocess.CompletedProcess:
        if self.binary is None:
            raise ScannerUnavailableError(self.name, f"{self.name} executable not found")
        cmd = [self.binary, *args]
        try:
            return subprocess.run(
                cmd,
                cwd=cwd or str(self.workdir),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerTimeoutError(
                self.name, f"{self.name} timed out after {timeout}s"
            ) from exc
        except OSError as exc:
            raise ScannerExecutionError(
                self.name, f"{self.name} failed to execute: {exc}"
            ) from exc
