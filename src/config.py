import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("SCP_DATA_DIR", PROJECT_ROOT / "data"))
SCAN_WORK_DIR = Path(os.getenv("SCP_SCAN_WORK_DIR", PROJECT_ROOT / "scan_work"))
REPORT_DIR = Path(os.getenv("SCP_REPORT_DIR", DATA_DIR / "reports"))
RULES_DIR = Path(os.getenv("SCP_RULES_DIR", PROJECT_ROOT / "rules"))

for _d in (DATA_DIR, SCAN_WORK_DIR, REPORT_DIR, RULES_DIR):
    _d.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv("SCP_DATABASE_URL", f"sqlite:///{DATA_DIR / 'controlplane.db'}")

BITBUCKET_ACCESS_TOKEN = os.getenv("BITBUCKET_ACCESS_TOKEN", "")
BITBUCKET_WORKSPACE = os.getenv("BITBUCKET_WORKSPACE", "")
BITBUCKET_API_BASE = os.getenv("BITBUCKET_API_BASE", "https://api.bitbucket.org/2.0")

# Per-engine binary/URL overrides (empty => rely on PATH / defaults)
ENGINE_BINARIES = {
    "bandit": os.getenv("SCP_BANDIT_BIN", "bandit"),
    "opengrep": os.getenv("SCP_OPENGREP_BIN", "opengrep"),
    "semgrep": os.getenv("SCP_SEMGREP_BIN", "semgrep"),
    "trivy": os.getenv("SCP_TRIVY_BIN", "trivy"),
    "gitleaks": os.getenv("SCP_GITLEAKS_BIN", "gitleaks"),
}
ZAP_API_URL = os.getenv("SCP_ZAP_API_URL", "http://127.0.0.1:8080")
ZAP_API_KEY = os.getenv("SCP_ZAP_API_KEY", "")

MAX_CONCURRENT_ENGINES = int(os.getenv("SCP_MAX_CONCURRENT_ENGINES", "4"))

# Upload archive limits (source ZIP scans)
MAX_UPLOAD_BYTES = int(os.getenv("SCP_MAX_UPLOAD_BYTES", str(100 * 1024 * 1024)))
MAX_EXPANDED_BYTES = int(os.getenv("SCP_MAX_EXPANDED_BYTES", str(500 * 1024 * 1024)))
MAX_FILES = int(os.getenv("SCP_MAX_FILES", "20000"))
MAX_FILE_BYTES = int(os.getenv("SCP_MAX_FILE_BYTES", str(50 * 1024 * 1024)))
MAX_COMPRESSION_RATIO = int(os.getenv("SCP_MAX_COMPRESSION_RATIO", "100"))

# Offline local OpenGrep/Semgrep rule pack (relative to PROJECT_ROOT).
RULES_PACK_DIR = Path(os.getenv("SCP_RULES_PACK_DIR", RULES_DIR / "opengrep-rules"))
