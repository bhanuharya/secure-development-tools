#!/usr/bin/env bash
# SDT Jenkins worker: doctor -> plan -> scan -> offline PDF.
# Advisory-first: exit codes are mapped by the caller (Jenkinsfile/groovy),
# this script ALWAYS writes reports/ and echoes a machine-readable tail line.
#
# Required env (set by Jenkinsfile / vars/sdtScan.groovy):
#   SDT_BIN            absolute path to `sdt` binary (go build -o sdt ./cmd/sdt)
#   SDT_RULES_DIR      absolute path to rules/opengrep-rules (pinned checkout)
# Optional env (sane Phase-1 defaults):
#   SDT_PROFILE        pr|full|release (default: full — parameterized one-shot
#                      scans have no merge-base, so `pr` would fail closed)
#   SDT_BASE/HEAD      revisions (default: HEAD, no base for full mode)
#   SDT_TOOL_PDF       absolute path to tools/sdt_to_pdf.py (default: <rules>/../../tools/sdt_to_pdf.py)
#   TRIVY_DB_REPOSITORY  (default: ghcr.io/aquasecurity/trivy-db:2)
#   TRIVY_OFFLINE_SCAN   (default: true — avoids Maven Central 429s seen in Phase 1;
#                      set SDT_TRIVY_ONLINE=true to allow remote dep resolution)
#   SDT_PROJECT        label for PDF cover (default: basename of WORKSPACE)
set -euo pipefail

: "${SDT_BIN:?set SDT_BIN to the sdt binary}"
: "${SDT_RULES_DIR:?set SDT_RULES_DIR to rules/opengrep-rules}"
: "${SDT_PROFILE:=full}"
: "${WORKSPACE:=$PWD}"

export SDT_RULES_PACK_DIR="$SDT_RULES_DIR"
export SDT_DEFAULT_RULES_DIR="$SDT_RULES_DIR"
export TRIVY_DB_REPOSITORY="${TRIVY_DB_REPOSITORY:-ghcr.io/aquasecurity/trivy-db:2}"
if [ "${SDT_TRIVY_ONLINE:-}" = "true" ]; then
  unset TRIVY_OFFLINE_SCAN || true
else
  export TRIVY_OFFLINE_SCAN="${TRIVY_OFFLINE_SCAN:-true}"
fi
export TRIVY_SKIP_VERSION_CHECK=true

PDF_TOOL="${SDT_TOOL_PDF:-$(cd "$(dirname "$SDT_RULES_DIR")/../tools" 2>/dev/null && pwd)/sdt_to_pdf.py}"
PROJECT="${SDT_PROJECT:-$(basename "$WORKSPACE")}"

echo "=== sdt doctor ==="
"$SDT_BIN" doctor || echo "WARN: doctor reported blockers (git/config only fail the gate)"

echo "=== sdt plan --profile $SDT_PROFILE ==="
"$SDT_BIN" plan --profile "$SDT_PROFILE" ${SDT_BASE:+--base "$SDT_BASE"} --head "${SDT_HEAD:-HEAD}" | tee plan.json

echo "=== sdt scan --profile $SDT_PROFILE ==="
set +e
"$SDT_BIN" scan --profile "$SDT_PROFILE" ${SDT_BASE:+--base "$SDT_BASE"} --head "${SDT_HEAD:-HEAD}" \
  --output reports --cache .cache/sdt
SDT_CODE=$?
set -e
echo "sdt exit=$SDT_CODE"

echo "=== offline PDF ==="
if [ -f "reports/findings.json" ] && [ -f "$PDF_TOOL" ]; then
  if python3 "$PDF_TOOL" --from reports/findings.json \
      --manifest reports/run-manifest.json \
      --out reports/security-report.pdf \
      --project "$PROJECT" --profile "$SDT_PROFILE" \
      --src-root "$WORKSPACE"; then
    echo "PDF ok"
  else
    echo "WARN: PDF build failed (non-blocking; reports/ still archived)"
  fi
else
  echo "WARN: PDF skipped (missing reports/findings.json or $PDF_TOOL)"
fi

echo "=== artifacts ==="
ls -lh reports/ || true
cat reports/summary.txt 2>/dev/null || true

# Machine-readable tail for Jenkins `sh(returnStdout)` parsing.
echo "SDT_RESULT code=$SDT_CODE profile=$SDT_PROFILE"
exit "$SDT_CODE"
