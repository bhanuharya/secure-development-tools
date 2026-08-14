from __future__ import annotations

import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable

from src.config import MAX_CONCURRENT_SCANS, MAX_QUEUED_SCANS

log = logging.getLogger(__name__)

ScanFn = Callable[[int], None]


class ScanCapacityError(RuntimeError):
    """The bounded scan worker+queue capacity is exhausted."""


class ScanExecutor:
    """Boundary for running scan workers.

    Only an immutable ``scan_id`` and a callable cross this boundary; no
    long-lived SQLModel entity is passed. The worker re-queries its row inside
    a fresh session and treats a missing row as a clean cancellation.
    """

    def submit(self, scan_id: int, fn: ScanFn) -> Any:
        raise NotImplementedError


class NullScanExecutor(ScanExecutor):
    """No-op executor for tests that only inspect the created scan record."""

    def submit(self, scan_id: int, fn: ScanFn) -> None:
        return None


class SyncScanExecutor(ScanExecutor):
    """Runs the worker inline for deterministic tests."""

    def submit(self, scan_id: int, fn: ScanFn) -> None:
        fn(scan_id)
        return None


class ThreadedScanExecutor(ScanExecutor):
    """Bounded executor replacing unbounded per-request daemon threads.

    A fixed worker pool caps concurrent scans, and the wrapper never lets an
    unhandled exception escape the worker thread (which would otherwise trip
    pytest's ``PytestUnhandledThreadExceptionWarning``).
    """

    def __init__(self, max_workers: int | None = None, max_queue: int | None = None) -> None:
        workers = max_workers or MAX_CONCURRENT_SCANS
        queued = MAX_QUEUED_SCANS if max_queue is None else max_queue
        if workers < 1 or queued < 0:
            raise ValueError("scan executor workers must be >= 1 and queue must be >= 0")
        self._pool = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="scan-worker",
        )
        self._capacity = threading.BoundedSemaphore(workers + queued)
        self._lock = threading.Lock()
        self._running: set[int] = set()

    def submit(self, scan_id: int, fn: ScanFn) -> Future:
        if not self._capacity.acquire(blocking=False):
            raise ScanCapacityError("scan executor capacity is full")
        with self._lock:
            if scan_id in self._running:
                self._capacity.release()
                raise RuntimeError(f"scan {scan_id} is already running")
            self._running.add(scan_id)
        try:
            future = self._pool.submit(self._run, scan_id, fn)
        except Exception:
            self._forget(scan_id)
            raise
        future.add_done_callback(lambda _f: self._forget(scan_id))
        return future

    def _run(self, scan_id: int, fn: ScanFn) -> None:
        try:
            fn(scan_id)
        except Exception:  # noqa: BLE001
            log.exception("scan worker %s raised an unhandled error", scan_id)

    def _forget(self, scan_id: int) -> None:
        with self._lock:
            self._running.discard(scan_id)
        self._capacity.release()

    def shutdown(self, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait)


_executor: ScanExecutor | None = None


def get_executor() -> ScanExecutor:
    global _executor
    if _executor is None:
        _executor = ThreadedScanExecutor()
    return _executor


def set_executor(executor: ScanExecutor | None) -> None:
    global _executor
    _executor = executor
