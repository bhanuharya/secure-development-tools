#!/usr/bin/env bash
# CI smoke test: the engine must still block a known-vulnerable app and finalize
# its artifacts.
#
# Runs the documented demo scan (examples/sample-run/demo.secure-dev.yaml against
# the deliberately vulnerable fixtures/vulnapp) and asserts the contract:
#   * exit 1 (policy_failed) — a detected-but-blocked result, not a crash (3/5);
#   * the four artifacts exist and are non-empty;
#   * the summary reports policy_failed;
#   * the expected SAST rule IDs are still detected.
#
# Deliberately does NOT assert finding totals or fingerprints: the dependency
# CVEs come from a live Trivy database and legitimately move between runs, while
# the SAST detections are pinned by rule bytes in this repository.
#
# Requires: go, and sdt's scanner binaries (opengrep, gitleaks, trivy) on PATH.
# Usage: scripts/ci_gate_smoke.sh [run-dir]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${1:-$(mktemp -d)}"
mkdir -p "$RUN_DIR/reports" "$RUN_DIR/cache"
cd "$ROOT"

echo "== build =="
go build -o "$RUN_DIR/sdt" ./cmd/sdt

echo "== scan (demo target: fixtures/vulnapp) =="
set +e
SDT_RULES_PACK_DIR="$ROOT/rules/opengrep-rules" "$RUN_DIR/sdt" scan \
  --profile full \
  --config examples/sample-run/demo.secure-dev.yaml \
  --cache "$RUN_DIR/cache" \
  --output "$RUN_DIR/reports" >"$RUN_DIR/console.log" 2>&1
rc=$?
set -e
cat "$RUN_DIR/console.log"

if [ "$rc" -ne 1 ]; then
  echo "FAIL: expected exit 1 (policy_failed), got $rc." >&2
  echo "      2=invalid_input, 3=execution_failed, 4=inconclusive, 5=internal_error." >&2
  exit 1
fi

echo "== artifacts =="
for f in findings.json findings.sarif run-manifest.json summary.txt; do
  if [ ! -s "$RUN_DIR/reports/$f" ]; then
    echo "FAIL: artifact missing or empty: $f" >&2
    exit 1
  fi
  echo "  ok $f"
done

grep -q 'status=policy_failed' "$RUN_DIR/reports/summary.txt" || {
  echo "FAIL: summary.txt does not report policy_failed" >&2
  exit 1
}

echo "== expected detections =="
python3 - "$RUN_DIR/reports/findings.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
if report.get("status") != "policy_failed":
    raise SystemExit(f"FAIL: report status is {report.get('status')!r}")

seen = {f["rule"]["id"] for f in report["findings"]}
# Rule IDs carry a language prefix derived from the rule file's path (e.g.
# python.scp.python.crypto.weak-md5), so match on the stable tail.
wanted = (
    "scp.python.exec.eval",        # eval() on a dynamic string
    "scp.python.crypto.weak-md5",  # MD5 used for hashing
)
missing = [w for w in wanted if not any(w in rule_id for rule_id in seen)]
print(f"  findings: {len(report['findings'])}; distinct rule IDs: {len(seen)}")
for rule_id in sorted(seen):
    print(f"    {rule_id}")
if missing:
    raise SystemExit(f"FAIL: expected detections missing: {missing}")
print("OK: engine blocked the vulnerable fixture with the expected SAST detections")
PY
