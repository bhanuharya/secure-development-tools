#!/usr/bin/env bash
# Reports for one scan: the SAST report (.docx, from SonarQube), the Excel register and
# fleet summary, and (with FLEET_DATABASE) the fleet store update:
# ingest this run, then copy review decisions made in SonarQube back into it.
#
# Required: SRC, OUT, REPO_SLUG, SONAR_HOST_URL, SONAR_TOKEN (after scan.sh ran)
# Optional: BRANCH / PR_ID, WORKSPACE_NAME, SCOPE_URL, SDT_HOME, FLEET_DATABASE,
#           SDT_STATE_DIR (kept between scans: scan history and AI verdict memory live under it),
#           SDT_SCAN_NICE (priority of everything this script starts, as in scan.sh),
#           SDT_INVENTORY (repository inventory for finding priority; default $SDT_STATE_DIR/inventory.tsv when present),
#           SDT_KEV_FILE (optional local CISA KEV catalog JSON; allows P1 on imported vulnerable packages),
#           PR_BASE + SDT_PR_BASE_REPORT (0|1: a pull request scan also reports its target branch, from the
#           baseline scan, in out/target-branch/; off by default, sdtScan reports the source branch instead)
set -euo pipefail
set +x
: "${SRC:?}" "${OUT:?}" "${REPO_SLUG:?}"
SDT_HOME="${SDT_HOME:-/opt/sdt}"
WORKSPACE_NAME="${WORKSPACE_NAME:-workspace}"
[ -n "${SDT_STATE_DIR:-}" ] && : "${SDT_HISTORY_DIR:=$SDT_STATE_DIR/history}"
# The SAST report reads SDT_INVENTORY itself; in an image the state volume is where an inventory can live.
if [ -z "${SDT_INVENTORY:-}" ] && [ -n "${SDT_STATE_DIR:-}" ] && [ -f "$SDT_STATE_DIR/inventory.tsv" ]; then
  export SDT_INVENTORY="$SDT_STATE_DIR/inventory.tsv"
fi
COMMIT=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo "")
log() { printf '[sdt] %s\n' "$*"; }
status=0
# The same priority as the scan itself (see scan.sh), for the AI review and the report tools.
[ -z "${SDT_SCAN_NICE:-}" ] || renice -n "$SDT_SCAN_NICE" $$ >/dev/null 2>&1 || true
# Seconds per step, continuing the file scan.sh started.
TIMINGS="$OUT/timings.tsv"; STEP_START=$SECONDS
timing() { printf '%s\t%s\n' "$1" "$((SECONDS - STEP_START))" >> "$TIMINGS"; STEP_START=$SECONDS; }

# The SAST report reads SonarQube, so it shows each hotspot's review state and assignee.
TRIAGE=()
KEV_ARG=()
[ -n "${SDT_KEV_FILE:-}" ] && KEV_ARG=(--kev "$SDT_KEV_FILE")
# 'SAST Report - <repo>[ - PR <id>] - <ddmmyy-hhmm>.docx': branch and pull request reports and their scan
# times are told apart in downloads. One report per build: an older one in OUT would be picked up instead.
rm -f "$OUT"/SAST\ Report\ -\ *.docx
REPORT_DOCX="$OUT/SAST Report - $REPO_SLUG${PR_ID:+ - PR $PR_ID} - $(date +%d%m%y-%H%M).docx"
if [ -f "$OUT/sonar-project-key" ] && [ -n "${SONAR_TOKEN:-}" ]; then
  # Same scope scan.sh analysed: no branch parameter for the main branch.
  SCOPE=()
  [ -n "$(cat "$OUT/sonar-scope-query" 2>/dev/null)" ] && SCOPE=(--branch "${BRANCH:-}")
  [ -n "${PR_ID:-}" ] && SCOPE=(--pull-request "$PR_ID")
  # Optional AI-assisted review (advisory): only when Codex is installed and SDT_AI_TRIAGE!=0.
  # Bounded by per-call timeouts, SDT_CODEX_BUDGET and this outer timeout; never fails the build.
  # The scan's findings carry each finding's evidence (e.g. the security rule that makes a route public).
  FINDINGS_ARG=()
  [ -s "$OUT/sdt/findings.json" ] && FINDINGS_ARG=(--findings "$OUT/sdt/findings.json")
  timeout "$(( ${SDT_CODEX_BUDGET:-600} + 120 ))" python3 "$SDT_HOME/tools/sdt_triage_codex.py" \
    --sonar-url "$SONAR_HOST_URL" --project-key "$(cat "$OUT/sonar-project-key")" "${SCOPE[@]}" \
    --src-root "$SRC" --out "$OUT/triage.json" --budget "${SDT_CODEX_BUDGET:-600}" "${FINDINGS_ARG[@]}" \
    || log "AI review skipped (error or timeout); normal report"
  timing ai-review
  [ -s "$OUT/triage.json" ] && TRIAGE=(--triage "$OUT/triage.json")
  # Opt-in: mark the clearest false positives Safe in SonarQube, with the review's evidence as the
  # comment (two agreeing reviews, a named line, review priority below High). Hotspots only.
  if [ "${SDT_AI_AUTOCLOSE:-0}" = 1 ] && [ -s "$OUT/triage.json" ]; then
    python3 "$SDT_HOME/tools/sdt_sonar_autoclose.py" --sonar-url "$SONAR_HOST_URL" \
      --project-key "$(cat "$OUT/sonar-project-key")" "${SCOPE[@]}" --triage "$OUT/triage.json" \
      || log "automatic Safe marking skipped (error); findings stay To review"
  fi
  TRIAGE+=(--coverage "$OUT/coverage.txt")
  # Trend against the previous report of this repository and branch (needs a persistent SDT_HISTORY_DIR):
  # each report writes what it lists, SonarQube's own findings included, for the next one to compare with.
  HISTORY=""
  if [ -n "${SDT_HISTORY_DIR:-}" ] && [ -z "${PR_ID:-}" ]; then
    HISTORY="$SDT_HISTORY_DIR/$REPO_SLUG/$(printf '%s' "${BRANCH:-main}" | tr '/' '_')"
    PREVIOUS="$HISTORY/report-state.json"
    # A branch scanned for the first time (a new release branch) is compared with the most recently
    # scanned other branch of the repository, so the report still says what was fixed since then.
    [ -s "$PREVIOUS" ] || PREVIOUS=$(ls -t "$SDT_HISTORY_DIR/$REPO_SLUG"/*/report-state.json 2>/dev/null | head -1 || true)
    [ -n "$PREVIOUS" ] && [ -s "$PREVIOUS" ] && TRIAGE+=(--previous-state "$PREVIOUS")
    TRIAGE+=(--state-out "$OUT/report-state.json")
  fi
  # A pull request reports only what it adds (scan.sh wrote findings-new.json from the baseline).
  REPORT_FINDINGS="$OUT/sdt/findings.json"
  [ -n "${PR_ID:-}" ] && [ -s "$OUT/sdt/findings-new.json" ] && REPORT_FINDINGS="$OUT/sdt/findings-new.json"
  # Code security from SonarQube (review states); secrets and dependencies from SDT (commits, versions, reachability).
  python3 "$SDT_HOME/tools/sdt_to_docx.py" --sonar-url "$SONAR_HOST_URL" --project-key "$(cat "$OUT/sonar-project-key")" \
    "${SCOPE[@]}" --findings "$REPORT_FINDINGS" --src-root "$SRC" \
    --repository "$WORKSPACE_NAME/$REPO_SLUG" --scope-url "${SCOPE_URL:-}" \
    --commit "$COMMIT" "${TRIAGE[@]}" "${KEV_ARG[@]}" --out "$REPORT_DOCX" || { log "DOCX report failed"; status=1; }
else
  # SonarQube was not reached (stage failed): report straight from the SDT findings.
  python3 "$SDT_HOME/tools/sdt_to_docx.py" --findings "$OUT/sdt/findings.json" --src-root "$SRC" \
    --repository "$WORKSPACE_NAME/$REPO_SLUG" --project-name "$REPO_SLUG" --scope-url "${SCOPE_URL:-}" \
    --commit "$COMMIT" "${KEV_ARG[@]}" --out "$REPORT_DOCX" || { log "DOCX report failed"; status=1; }
fi
timing report

# Opt-in (SDT_PR_BASE_REPORT=1): scan.sh scanned the target branch for the baseline, so that branch can be
# reported too, from the same scan, with the target branch's files as the source (OpenGrep, Gitleaks and Trivy;
# SonarQube's own rules and review decisions are in that branch's own report). In out/target-branch/, so it is
# never taken for the pull request's report; it never fails the build. Off by default: sdtScan scans and
# reports the pull request's source branch in full (out/source-branch/), which is what a reviewer asks for.
rm -rf "$OUT/target-branch"
if [ -n "${PR_ID:-}" ] && [ -n "${PR_BASE:-}" ] && [ "${SDT_PR_BASE_REPORT:-0}" = 1 ] && [ -s "$OUT/base/findings.json" ]; then
  BASE_TREE="$OUT/target-branch-src"
  rm -rf "$BASE_TREE"; mkdir -p "$BASE_TREE" "$OUT/target-branch"
  BASE_SRC_ARGS=()
  if git -C "$SRC" archive "origin/$PR_BASE" 2>/dev/null | tar -x -C "$BASE_TREE" 2>/dev/null; then
    BASE_SRC_ARGS=(--src-root "$BASE_TREE")
  else
    log "target branch files not extracted; its report has no code excerpts"
  fi
  BASE_COMMIT=$(git -C "$SRC" rev-parse "origin/$PR_BASE^{commit}" 2>/dev/null || true)
  BASE_DOCX="$OUT/target-branch/SAST Report - $REPO_SLUG - PR $PR_ID - target $(printf '%s' "$PR_BASE" | tr -c 'A-Za-z0-9._-' '_') - $(date +%d%m%y-%H%M).docx"
  python3 "$SDT_HOME/tools/sdt_to_docx.py" --findings "$OUT/base/findings.json" "${BASE_SRC_ARGS[@]}" \
    --repository "$WORKSPACE_NAME/$REPO_SLUG" --project-name "$REPO_SLUG" --branch "$PR_BASE" \
    ${BASE_COMMIT:+--commit "$BASE_COMMIT"} "${KEV_ARG[@]}" --out "$BASE_DOCX" \
    || log "target branch report failed (the pull request report is complete)"
  rm -rf "$BASE_TREE"
  timing target-branch-report
fi

# Opt-in, pull requests only: an AI read of the changed lines for what rules miss (missing permission
# checks, unvalidated input, weakened settings). Advice for the reviewer; never blocks, never enters SonarQube.
if [ "${SDT_AI_DIFF_REVIEW:-0}" = 1 ] && [ -n "${PR_ID:-}" ] && [ -n "${PR_BASE:-}" ]; then
  DIFF_EP_ARGS=()
  [ -s "$OUT/sdt/endpoints.json" ] && DIFF_EP_ARGS=(--endpoints "$OUT/sdt/endpoints.json")
  # Remembered per repository under $SDT_STATE_DIR: a file whose change is unchanged since the last
  # scan keeps its earlier review instead of being asked again (the model words it differently each time).
  DIFF_PROJECT=$(cat "$OUT/sonar-project-key" 2>/dev/null || true)
  timeout "$(( ${SDT_CODEX_BUDGET:-600} + 120 ))" python3 "$SDT_HOME/tools/sdt_review_diff.py" --src-root "$SRC" \
    --base "origin/$PR_BASE" "${DIFF_EP_ARGS[@]}" --out "$OUT/ai-change-review.json" --markdown "$OUT/ai-change-review.md" \
    --project-key "${DIFF_PROJECT:-${WORKSPACE_NAME:-}_${REPO_SLUG:-repository}}" --scope "pr-$PR_ID" \
    --budget "${SDT_CODEX_BUDGET:-600}" || log "AI change review skipped (error or timeout)"
  timing ai-change-review
fi

if [ -n "${HISTORY:-}" ]; then
  mkdir -p "$HISTORY" && cp "$OUT/sdt/findings.json" "$HISTORY/findings.json"
  [ -s "$OUT/report-state.json" ] && cp "$OUT/report-state.json" "$HISTORY/report-state.json"
  # One dated copy per scan for tools/sdt_fix_rate.py (digests only, a few KB each), kept 400 days.
  if [ -s "$OUT/report-state.json" ]; then
    { mkdir -p "$HISTORY/states" && cp "$OUT/report-state.json" "$HISTORY/states/$(date -u +%Y%m%dT%H%M%SZ).json"; } \
      || log "dated report state not kept"
    find "$HISTORY/states" -name '*.json' -mtime +400 -delete 2>/dev/null || true
  fi
fi

# The fleet register: the same inputs the nightly fleet report uses, for one repository.
mkdir -p "$OUT/fleet/repositories/$REPO_SLUG"
cp "$OUT/sdt/findings.json" "$OUT/sdt/run-manifest.json" "$OUT/fleet/repositories/$REPO_SLUG/"
python3 "$SDT_HOME/tools/sdt_repo_manifest.py" --findings "$OUT/fleet/repositories/$REPO_SLUG/findings.json" \
  --run-manifest "$OUT/fleet/repositories/$REPO_SLUG/run-manifest.json" --slug "$REPO_SLUG" \
  --branch "${BRANCH:-pr-${PR_ID:-}}" --workspace "$WORKSPACE_NAME" --commit "$COMMIT" --out "$OUT/fleet/fleet-manifest.json"
( cd "$OUT/fleet" && python3 "$SDT_HOME/tools/sdt_fleet_report.py" --from fleet-manifest.json ) || { log "fleet report failed"; status=1; }
timing fleet-register

if [ -n "${FLEET_DATABASE:-}" ] && [ -z "${PR_ID:-}" ]; then
  python3 "$SDT_HOME/tools/sdt_fleet_ingest.py" --run-dir "$OUT/fleet" --database "$FLEET_DATABASE" || status=1
  if [ -f "$OUT/sonar-project-key" ]; then
    SONAR_BRANCH_ARG=()
    [ -n "$(cat "$OUT/sonar-scope-query" 2>/dev/null)" ] && SONAR_BRANCH_ARG=(--sonar-branch "$BRANCH")
    python3 "$SDT_HOME/tools/sdt_sonar_sync.py" --sonar-url "$SONAR_HOST_URL" --project-key "$(cat "$OUT/sonar-project-key")" \
      --branch "$BRANCH" "${SONAR_BRANCH_ARG[@]}" --repository "$REPO_SLUG" --database "$FLEET_DATABASE" || status=1
  fi
  timing fleet-store
fi
log "seconds per step: $(awk -F'\t' '{ printf "%s%s %s", (NR > 1 ? ", " : ""), $1, $2 }' "$TIMINGS")"
exit $status
