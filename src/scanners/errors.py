from __future__ import annotations


class ScannerError(Exception):
    """Base class for truthful scanner failures.

    A scanner that cannot run, or cannot produce valid output, must raise a
    typed error instead of silently returning ``[]`` so the orchestrator can
    record real coverage and mark the scan ``failed``.
    """

    kind = "error"

    def __init__(self, engine: str, message: str) -> None:
        self.engine = engine
        self.message = message
        super().__init__(f"[{engine}] {message}")


class ScannerUnavailableError(ScannerError):
    """The engine executable is not installed / not discoverable."""

    kind = "unavailable"


class ScannerTimeoutError(ScannerError):
    """The engine exceeded its time budget."""

    kind = "timeout"


class ScannerExecutionError(ScannerError):
    """The engine ran but failed (non-zero exit, crashed, or could not start)."""

    kind = "execution"


class ScannerMalformedOutputError(ScannerError):
    """The engine produced output that could not be parsed / was missing."""

    kind = "malformed_output"


class ScannerRuleError(ScannerError):
    """The engine could not load/validate its rules or configuration."""

    kind = "rule_config"


# Kinds that represent a real engine failure (as opposed to an expected
# "unavailable" or "skipped" condition). Any of these flips the scan terminal
# status to ``failed``.
REAL_FAILURE_KINDS = frozenset(
    {"timeout", "execution", "malformed_output", "rule_config"}
)
