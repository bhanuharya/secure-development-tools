from src.scanners.executor import (
    NullScanExecutor,
    SyncScanExecutor,
    ThreadedScanExecutor,
)


def test_sync_executor_runs_inline():
    calls = []
    SyncScanExecutor().submit(42, calls.append)
    assert calls == [42]


def test_null_executor_does_nothing():
    calls = []
    NullScanExecutor().submit(42, calls.append)
    assert calls == []


def test_threaded_executor_swallows_worker_exception():
    ex = ThreadedScanExecutor(max_workers=1)
    try:
        def raiser(scan_id):
            raise ValueError("boom")

        future = ex.submit(1, raiser)
        assert future.result() is None  # exception swallowed, not propagated
    finally:
        ex.shutdown(wait=True)


def test_threaded_executor_rejects_duplicate_scan():
    import time

    ex = ThreadedScanExecutor(max_workers=1)
    try:
        started = []

        def slow(scan_id):
            started.append(scan_id)
            time.sleep(0.2)

        ex.submit(7, slow)
        time.sleep(0.05)
        try:
            ex.submit(7, slow)
            raise AssertionError("duplicate submit should raise")
        except RuntimeError:
            pass
    finally:
        ex.shutdown(wait=True)


def test_threaded_executor_rejects_when_capacity_is_full():
    import threading

    release = threading.Event()
    started = threading.Event()
    ex = ThreadedScanExecutor(max_workers=1, max_queue=0)
    try:
        def blocked(scan_id):
            started.set()
            release.wait(timeout=2)

        first = ex.submit(1, blocked)
        assert started.wait(timeout=1)
        try:
            ex.submit(2, blocked)
            raise AssertionError("submission beyond worker+queue capacity must raise")
        except RuntimeError as exc:
            assert "capacity" in str(exc).lower()
        release.set()
        assert first.result(timeout=2) is None
    finally:
        release.set()
        ex.shutdown(wait=True)
