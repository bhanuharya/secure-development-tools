from __future__ import annotations

import json
import threading
from collections import defaultdict, deque
from typing import Any

_MAX_BUFFER = 2000


class EventBus:
    """Thread-safe per-scan event buffer consumed by SSE streams.

    Writers are orchestrator threads; readers are asyncio SSE streams. A
    bounded deque per scan + a monotonic sequence number keeps them decoupled
    without cross-thread asyncio queue plumbing.
    """

    def __init__(self) -> None:
        self._buf: dict[int, deque[tuple[int, str, dict]]] = defaultdict(deque)
        self._seq: dict[int, int] = defaultdict(int)
        self._lock = threading.Lock()

    def publish(self, scan_id: int, event_type: str, data: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._seq[scan_id] += 1
            self._buf[scan_id].append((self._seq[scan_id], event_type, data or {}))
            while len(self._buf[scan_id]) > _MAX_BUFFER:
                self._buf[scan_id].popleft()

    def events_since(self, scan_id: int, after_seq: int = 0) -> tuple[list[tuple[int, str, dict]], int]:
        with self._lock:
            evs = [e for e in self._buf.get(scan_id, []) if e[0] > after_seq]
            last = self._seq.get(scan_id, 0)
        return evs, last

    def latest(self, scan_id: int) -> tuple[str, dict] | None:
        with self._lock:
            buf = self._buf.get(scan_id)
            if not buf:
                return None
            return buf[-1][1], buf[-1][2]


event_bus = EventBus()


def sse_format(event_type: str, data: dict) -> str:
    payload = json.dumps(data, default=str)
    return f"event: {event_type}\ndata: {payload}\n\n"
