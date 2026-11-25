"""scan.sh gives SonarQube's Dart sensor a placeholder pubspec.yaml when Dart files have none at the root."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN = ROOT / "integrations" / "jenkins" / "resources" / "sdt" / "scan.sh"

FAKE_SDT = """#!/usr/bin/env bash
# Stands in for the sdt engine: an empty, complete scan.
out=""; while [ $# -gt 0 ]; do [ "$1" = --output ] && out=$2; shift; done
mkdir -p "$out"; echo '{"findings": []}' > "$out/findings.json"; echo '{"tasks": []}' > "$out/run-manifest.json"
"""
# Records what the Dart sensor would see, then fails (the test stops at the analysis step).
FAKE_SCANNER = """#!/usr/bin/env bash
if [ -f pubspec.yaml ]; then echo "pubspec: $(head -1 pubspec.yaml)" > "$RECORD"; else echo "pubspec: none" > "$RECORD"; fi
exit "${SCANNER_EXIT:-1}"
"""


def run(tmp_path: Path, files: dict[str, str], scanner_exit: int = 1) -> tuple[subprocess.CompletedProcess, Path, str]:
    home = tmp_path / "sdt-home"
    (home / "examples" / "fleet").mkdir(parents=True)
    (home / "examples" / "fleet" / "scan-config.yaml").write_text("apiVersion: secure-dev/v1alpha1\n")
    (home / "tools").symlink_to(ROOT / "tools")
    (home / "sdt").write_text(FAKE_SDT); (home / "sdt").chmod(0o755)
    bin_dir = tmp_path / "bin"; bin_dir.mkdir()
    (bin_dir / "sonar-scanner").write_text(FAKE_SCANNER); (bin_dir / "sonar-scanner").chmod(0o755)
    (bin_dir / "curl").write_text("#!/usr/bin/env bash\necho 404\n"); (bin_dir / "curl").chmod(0o755)  # no such project yet
    src = tmp_path / "src"
    for name, text in files.items():
        (src / name).parent.mkdir(parents=True, exist_ok=True)
        (src / name).write_text(text)
    out = tmp_path / "out"
    record = tmp_path / "record"
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "SRC": str(src), "OUT": str(out), "REPO_SLUG": "shop",
           "SONAR_HOST_URL": "http://127.0.0.1:9", "SONAR_TOKEN": "t", "SDT_HOME": str(home), "BRANCH": "main",
           "SBOM": "0", "RECORD": str(record), "SCANNER_EXIT": str(scanner_exit), "HOME": str(tmp_path)}
    done = subprocess.run(["bash", str(SCAN)], env=env, capture_output=True, text=True, timeout=120)
    return done, src, record.read_text().strip() if record.exists() else ""


def test_dart_files_without_a_root_pubspec_get_a_placeholder_for_the_analysis_only(tmp_path):
    done, src, seen = run(tmp_path, {"testdata/app/lib/main.dart": "void main() {}\n", "README.md": "x\n"})
    assert seen == "pubspec: name: sdt_scan_placeholder"
    assert not (src / "pubspec.yaml").exists()  # removed again, also when the analysis fails
    assert done.returncode == 1 and "sonar-scanner failed" in done.stdout
    assert "a placeholder lets SonarQube's Dart sensor run" in done.stdout


def test_a_repository_pubspec_is_left_alone_and_no_dart_means_no_placeholder(tmp_path):
    done, src, seen = run(tmp_path / "a", {"pubspec.yaml": "name: shop\n", "lib/main.dart": "void main() {}\n"})
    assert seen == "pubspec: name: shop" and (src / "pubspec.yaml").read_text() == "name: shop\n"
    done, src, seen = run(tmp_path / "b", {"main.go": "package main\n"})
    assert seen == "pubspec: none" and not (src / "pubspec.yaml").exists()
