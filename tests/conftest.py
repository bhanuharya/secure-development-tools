import os
import tempfile
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="scp-test-"))
os.environ["SCP_DATABASE_URL"] = f"sqlite:///{_TMP / 'test.db'}"
os.environ["SCP_SCAN_WORK_DIR"] = str(_TMP / "scan_work")
os.environ["SCP_REPORT_DIR"] = str(_TMP / "reports")
# Use the committed local rule pack so OpenGrep/Semgrep scans stay offline and
# deterministic in tests.
os.environ["SCP_RULES_DIR"] = str(Path(__file__).resolve().parent.parent / "rules")

import src.api.database as db  # noqa: E402
from src.api.database import Finding, Project, Scan, Target, engine, init_db  # noqa: E402


@pytest.fixture(autouse=True)
def clean_db():
    init_db()
    with db.Session(engine) as session:
        # truncate between tests for isolation
        for table in (Finding, Scan, Target, Project):
            session.exec(table.__table__.delete())
        session.commit()
    yield
    db.Session(engine).close()


@pytest.fixture(autouse=True)
def no_background_scans():
    """Run no background scan threads during tests by default.

    Routers hand scans to the swappable executor; tests use a no-op executor so
    API calls never spawn threads that outlive the test (which would race with
    DB teardown). Tests that need synchronous execution opt in via
    ``set_executor(SyncScanExecutor())``.
    """
    from src.scanners.executor import NullScanExecutor, set_executor

    set_executor(NullScanExecutor())
    yield
    set_executor(None)


@pytest.fixture
def fixture_repo():
    return Path(__file__).resolve().parent.parent / "fixtures" / "vulnapp"


@pytest.fixture
def fixture_bare_repo():
    return Path(__file__).resolve().parent.parent / "fixtures" / "test-repo.git"


@pytest.fixture
def fixture_diff():
    return (Path(__file__).resolve().parent.parent / "fixtures" / "pr-diff.txt").read_text()


@pytest.fixture(scope="session")
def tmp_env():
    return _TMP