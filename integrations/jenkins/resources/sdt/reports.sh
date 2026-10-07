#!/usr/bin/env bash
# Reports for one scan: the SAST report (.docx, from SonarQube), the Excel register and
# fleet summary, and (with FLEET_DATABASE) the fleet store update:
# ingest this run, then copy review decisions made in SonarQube back into it.
#
# Required: SRC, OUT, REPO_SLUG, SONAR_HOST_URL, SONAR_TOKEN (after scan.sh ran)
# Optional: BRANCH / PR_ID, WORKSPACE_NAME, SCOPE_URL, SDT_HOME, FLEET_DATABASE,
#           SDT_STATE_DIR (kept between scans: scan history and AI verdict memory live under it)
set -euo pipefail
set +x
: "${SRC:?}" "${OUT:?}" "${REPO_SLUG:?}"
SDT_HOME="${SDT_HOME:-/opt/sdt}"
WORKSPACE_NAME="${WORKSPACE_NAME:-workspace}"
[ -n "${SDT_STATE_DIR:-}" ] && : "${SDT_HISTORY_DIR:=$SDT_STATE_DIR/history}"
COMMIT=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo "")
log() { printf '[sdt] %s\n' "$*"; }
status=0

# The SAST report reads SonarQube, so it shows each hotspot's review state and assignee.
TRIAGE=()
if [ -f "$OUT/sonar-project-key" ] && [ -n "${SONAR_TOKEN:-}" ]; then
  # Same scope scan.sh analysed: no branch parameter for the main branch.
  SCOPE=()
  [ -n "$(cat "$OUT/sonar-scope-query" 2>/dev/null)" ] && SCOPE=(--branch "${BRANCH:-}")
  [ -n "${PR_ID:-}" ] && SCOPE=(--pull-request "$PR_ID")
  # Optional AI-assisted review (advisory): only when Codex is installed and SDT_AI_TRIAGE!=0.
  # Bounded by per-call timeouts, SDT_CODEX_BUDGET and this outer timeout; never fails the build.
  timeout "$(( ${SDT_CODEX_BUDGET:-600} + 120 ))" python3 "$SDT_HOME/tools/sdt_triage_codex.py" \
    --sonar-url "$SONAR_HOST_URL" --project-key "$(cat "$OUT/sonar-project-key")" "${SCOPE[@]}" \
    --src-root "$SRC" --out "$OUT/triage.json" --budget "${SDT_CODEX_BUDGET:-600}" \
    || log "AI review skipped (error or timeout); normal report"
  [ -s "$OUT/triage.json" ] && TRIAGE=(--triage "$OUT/triage.json")
  # Opt-in: mark the clearest false positives Safe in SonarQube, with the review's evidence as the
  # comment (two agreeing reviews, a named line, review priority below High). Hotspots only.
  if [ "${SDT_AI_AUTOCLOSE:-0}" = 1 ] && [ -s "$OUT/triage.json" ]; then
    python3 "$SDT_HOME/tools/sdt_sonar_autoclose.py" --sonar-url "$SONAR_HOST_URL" \
      --project-key "$(cat "$OUT/sonar-project-key")" "${SCOPE[@]}" --triage "$OUT/triage.json" \
      || log "automatic Safe marking skipped (error); findings stay To review"
  fi
  TRIAGE+=(--coverage "$OUT/coverage.txt")
  # Trend against the previous scan of this repository and branch (needs a persistent SDT_HISTORY_DIR).
  HISTORY=""
  if [ -n "${SDT_HISTORY_DIR:-}" ] && [ -z "${PR_ID:-}" ]; then
    HISTORY="$SDT_HISTORY_DIR/$REPO_SLUG/$(printf '%s' "${BRANCH:-main}" | tr '/' '_')"
    PREVIOUS="$HISTORY/findings.json"
    # A branch scanned for the first time (a new release branch) is compared with the most recently
    # scanned other branch of the repository, so the report still says what was fixed since then.
    [ -s "$PREVIOUS" ] || PREVIOUS=$(ls -t "$SDT_HISTORY_DIR/$REPO_SLUG"/*/findings.json 2>/dev/null | head -1 || true)
    [ -n "$PREVIOUS" ] && [ -s "$PREVIOUS" ] && TRIAGE+=(--previous-findings "$PREVIOUS")
  fi
  # A pull request reports only what it adds (scan.sh wrote findings-new.json from the baseline).
  REPORT_FINDINGS="$OUT/sdt/findings.json"
  [ -n "${PR_ID:-}" ] && [ -s "$OUT/sdt/findings-new.json" ] && REPORT_FINDINGS="$OUT/sdt/findings-new.json"
  # Code security from SonarQube (review states); secrets and dependencies from SDT (commits, versions, reachability).
  python3 "$SDT_HOME/tools/sdt_to_docx.py" --sonar-url "$SONAR_HOST_URL" --project-key "$(cat "$OUT/sonar-project-key")" \
    "${SCOPE[@]}" --findings "$REPORT_FINDINGS" --src-root "$SRC" \
    --repository "$WORKSPACE_NAME/$REPO_SLUG" --scope-url "${SCOPE_URL:-}" \
    --commit "$COMMIT" "${TRIAGE[@]}" --out "$OUT/SAST Report - $REPO_SLUG.docx" || { log "DOCX report failed"; status=1; }
else
  # SonarQube was not reached (stage failed): report straight from the SDT findings.
  python3 "$SDT_HOME/tools/sdt_to_docx.py" --findings "$OUT/sdt/findings.json" --src-root "$SRC" \
    --repository "$WORKSPACE_NAME/$REPO_SLUG" --project-name "$REPO_SLUG" --scope-url "${SCOPE_URL:-}" \
    --commit "$COMMIT" --out "$OUT/SAST Report - $REPO_SLUG.docx" || { log "DOCX report failed"; status=1; }
fi

# Opt-in, pull requests only: an AI read of the changed lines for what rules miss (missing permission
# checks, unvalidated input, weakened settings). Advice for the reviewer; never blocks, never enters SonarQube.
if [ "${SDT_AI_DIFF_REVIEW:-0}" = 1 ] && [ -n "${PR_ID:-}" ] && [ -n "${PR_BASE:-}" ]; then
  timeout "$(( ${SDT_CODEX_BUDGET:-600} + 120 ))" python3 "$SDT_HOME/tools/sdt_review_diff.py" --src-root "$SRC" \
    --base "origin/$PR_BASE" --out "$OUT/ai-change-review.json" --markdown "$OUT/ai-change-review.md" \
    --budget "${SDT_CODEX_BUDGET:-600}" || log "AI change review skipped (error or timeout)"
fi

[ -n "${HISTORY:-}" ] && mkdir -p "$HISTORY" && cp "$OUT/sdt/findings.json" "$HISTORY/findings.json"

# The fleet register: the same inputs the nightly fleet report uses, for one repository.
mkdir -p "$OUT/fleet/repositories/$REPO_SLUG"
cp "$OUT/sdt/findings.json" "$OUT/sdt/run-manifest.json" "$OUT/fleet/repositories/$REPO_SLUG/"
python3 "$SDT_HOME/tools/sdt_repo_manifest.py" --findings "$OUT/fleet/repositories/$REPO_SLUG/findings.json" \
  --run-manifest "$OUT/fleet/repositories/$REPO_SLUG/run-manifest.json" --slug "$REPO_SLUG" \
  --branch "${BRANCH:-pr-${PR_ID:-}}" --workspace "$WORKSPACE_NAME" --commit "$COMMIT" --out "$OUT/fleet/fleet-manifest.json"
( cd "$OUT/fleet" && python3 "$SDT_HOME/tools/sdt_fleet_report.py" --from fleet-manifest.json ) || { log "fleet report failed"; status=1; }

if [ -n "${FLEET_DATABASE:-}" ] && [ -z "${PR_ID:-}" ]; then
  python3 "$SDT_HOME/tools/sdt_fleet_ingest.py" --run-dir "$OUT/fleet" --database "$FLEET_DATABASE" || status=1
  if [ -f "$OUT/sonar-project-key" ]; then
    SONAR_BRANCH_ARG=()
    [ -n "$(cat "$OUT/sonar-scope-query" 2>/dev/null)" ] && SONAR_BRANCH_ARG=(--sonar-branch "$BRANCH")
    python3 "$SDT_HOME/tools/sdt_sonar_sync.py" --sonar-url "$SONAR_HOST_URL" --project-key "$(cat "$OUT/sonar-project-key")" \
      --branch "$BRANCH" "${SONAR_BRANCH_ARG[@]}" --repository "$REPO_SLUG" --database "$FLEET_DATABASE" || status=1
  fi
fi
exit $status
