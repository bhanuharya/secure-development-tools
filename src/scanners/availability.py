from __future__ import annotations

from src.scanners.registry import REGISTRY


def engine_statuses() -> dict:
    """Availability + version for every registered engine.

    Iterates the engine registry so new engines are reported automatically.
    """
    return {name: spec.status() for name, spec in REGISTRY.items()}
