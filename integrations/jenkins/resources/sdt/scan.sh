#!/usr/bin/env bash
# SDT scan of one checkout -> SonarQube, for a branch or a pull request.
#
# Runs inside the scanner image (docker/Dockerfile) or on an agent with the same tools.
# Everything comes from the environment; nothing is read from a home directory.
#
# Required:  SRC (checkout dir), OUT (artifact dir), REPO_SLUG, SONAR_HOST_URL, SONAR_TOKEN
# Scope:     BRANCH, or PR_ID + PR_BRANCH + PR_BASE for a pull request
# Optional:  WORKSPACE_NAME (Bitbucket workspace, used in the project key), MAIN_BRANCHES ("main master"),
#            SDT_HOME (/opt/sdt), SDT_CONFIG, RULES_DIR, SONAR_SCANNER (sonar-scanner), FLUTTER_HOME,
#            QUALITY_GATE_ENFORCE (0|1), SBOM (1|0),
#            FLEET_DATABASE (fleet store: reviewed false positives are applied to this scan),
#            SONAR_CARRY_DECISIONS (1|0: copy review decisions from the project's other branches),
#            SONAR_TEST_PATTERNS (comma-separated globs of test code; empty analyses tests as application code)
set -euo pipefail
set +x  # never trace: SONAR_TOKEN is in the environment

: "${SRC:?}" "${OUT:?}" "${REPO_SLUG:?}" "${SONAR_HOST_URL:?}" "${SONAR_TOKEN:?}"
SDT_HOME="${SDT_HOME:-/opt/sdt}"
SDT_CONFIG="${SDT_CONFIG:-$SDT_HOME/examples/fleet/scan-config.yaml}"
RULES_DIR="${RULES_DIR:-$SDT_HOME/rules/opengrep-rules}"
SONAR_SCANNER="${SONAR_SCANNER:-sonar-scanner}"
WORKSPACE_NAME="${WORKSPACE_NAME:-workspace}"
MAIN_BRANCHES=" ${MAIN_BRANCHES:-main master} "
QUALITY_GATE_ENFORCE="${QUALITY_GATE_ENFORCE:-0}"
SBOM="${SBOM:-1}"
SONAR_TEST_PATTERNS="${SONAR_TEST_PATTERNS-**/test/**,**/tests/**,**/__tests__/**,**/*.test.*,**/*.spec.*,**/*_test.go,**/*_test.dart}"
mkdir -p "$OUT/sdt" "$OUT/cache"
log() { printf '[sdt] %s\n' "$*"; }

# ---------------------------------------------------------------- 1. SDT scan
export SDT_RULES_PACK_DIR="$RULES_DIR" SDT_DEFAULT_RULES_DIR="$RULES_DIR"
PROFILE=full; BASE_ARGS=()
if [ -n "${PR_ID:-}" ]; then
  PROFILE=pr; BASE_ARGS=(--base "origin/${PR_BASE:?PR_BASE is required for a pull request}")
fi
REPORT_FINDINGS="$OUT/sdt/findings.json"
# Findings a reviewer already judged false positive (on any branch of this repository) become
# exceptions for this scan. Best effort: without them the scan just reports everything again.
if [ -n "${FLEET_DATABASE:-}" ]; then
  if [ -e "$SRC/.secure-dev/exceptions.yaml" ] || grep -q '^exceptions:' "$SDT_CONFIG"; then
    log "reviewed false positives not applied: the repository or the scan configuration has its own exceptions file"
  elif python3 "$SDT_HOME/tools/sdt_fleet_exceptions.py" --database "$FLEET_DATABASE" --repository "$REPO_SLUG" \
         --out "$OUT/reviewed-exceptions.yaml"; then
    { cat "$SDT_CONFIG"; printf '\nexceptions:\n  file: %s\n' "$OUT/reviewed-exceptions.yaml"; } > "$OUT/scan-config.yaml"
    SDT_CONFIG="$OUT/scan-config.yaml"
  else
    log "reviewed false positives not applied (no decisions exported; a first scan has none yet)"
  fi
fi
if [ -n "${PR_ID:-}" ]; then
  # Baseline from the target branch: whatever already exists there is "existing", so only
  # what this pull request adds is "new" -- for the policy gate, SonarQube and the report.
  log "baseline: full scan of origin/$PR_BASE"
  rm -rf "$OUT/base-src"; git -C "$SRC" worktree add -q --detach "$OUT/base-src" "origin/$PR_BASE"
  ( cd "$OUT/base-src" && "$SDT_HOME/sdt" scan --config "$SDT_CONFIG" --profile full --offline \
      --output "$OUT/base" --cache "$OUT/cache" ) >/dev/null || true
  test -f "$OUT/base/findings.json"  # no baseline, no PR verdict
  git -C "$SRC" worktree remove --force "$OUT/base-src"
  ( cd "$SRC" && "$SDT_HOME/sdt" baseline create --config "$SDT_CONFIG" --from "$OUT/base/findings.json" )
fi
log "SDT scan (profile $PROFILE)"
( cd "$SRC" && "$SDT_HOME/sdt" scan --config "$SDT_CONFIG" --profile "$PROFILE" --offline "${BASE_ARGS[@]}" \
    --output "$OUT/sdt" --cache "$OUT/cache" ) || log "sdt exit $? (policy findings exit 1; the report is still complete)"
test -f "$OUT/sdt/findings.json"
# What goes to SonarQube: not the findings an exception covers (they stay in findings.json, marked),
# and for a pull request only what it adds.
REPORT_FINDINGS="$OUT/sdt/findings-report.json"
[ -n "${PR_ID:-}" ] && REPORT_FINDINGS="$OUT/sdt/findings-new.json"
python3 - "$OUT/sdt/findings.json" "$REPORT_FINDINGS" "${PR_ID:-}" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
total = len(report["findings"])
report["findings"] = [f for f in report["findings"] if not f.get("suppression")]
if total != len(report["findings"]):
    print(f"[sdt] {total - len(report['findings'])} of {total} findings are covered by an exception and left out of SonarQube")
if sys.argv[3]:
    kept = len(report["findings"])
    report["findings"] = [f for f in report["findings"] if f.get("baselineState") != "existing"]
    print(f"[sdt] pull request adds {len(report['findings'])} of {kept} findings (the rest already exist on the target branch)")
json.dump(report, open(sys.argv[2], "w"), indent=2)
PY

# ------------------------------------------------------------------- 2. SBOM
if [ "$SBOM" = 1 ] && command -v trivy >/dev/null; then
  trivy fs --quiet --format cyclonedx --output "$OUT/sbom.cdx.json" "$SRC" || log "SBOM generation failed (continuing)"
fi

# ------------------------------------------------------- 3. Dart / Flutter lint
# Private git dependencies (pubspec.yaml) are declared as https URLs but resolve over the
# SSH key Jenkins forwards. GIT_CONFIG_* applies the rewrite to this process tree only.
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.git@bitbucket.org:${WORKSPACE_NAME}/.insteadOf" \
       GIT_CONFIG_VALUE_0="https://bitbucket.org/${WORKSPACE_NAME}/"
DART_REPORT="$OUT/dart-analyze.txt"; : > "$DART_REPORT"
: > "$OUT/coverage.txt"  # what this scan could not cover; shown in the report
DART_BIN="${FLUTTER_HOME:+$FLUTTER_HOME/bin/}dart"; FLUTTER_BIN="${FLUTTER_HOME:+$FLUTTER_HOME/bin/}flutter"
if [ -f "$SRC/pubspec.yaml" ] && command -v "$DART_BIN" >/dev/null; then
  command -v "$FLUTTER_BIN" >/dev/null || FLUTTER_BIN="$DART_BIN"
  # Exit code only: grepping the log for "error" matched package names (gql_error_link).
  if ( cd "$SRC" && "$FLUTTER_BIN" pub get ) > "$OUT/pub-get.log" 2>&1; then
    ( cd "$SRC" && "$DART_BIN" analyze --format=machine ) > "$DART_REPORT" 2>/dev/null || true
    if ! python3 - "$DART_REPORT" <<'PY'
import sys
rows = [line.rstrip("\n").split("|") for line in open(sys.argv[1]) if line.count("|") >= 7]
unresolved = sum(1 for row in rows if row[2].upper() == "URI_DOES_NOT_EXIST"
                 or row[2].upper().startswith("UNDEFINED_"))
# sonar-flutter throws on a zero-length span (e.g. FILE_NAMES at 1:1) and fails the whole
# upload: give it one character when the line has one, else drop the diagnostic.
kept, fixed, dropped = [], 0, 0
for row in rows:
    if row[6].strip() in ("", "0"):
        try:
            text = open(row[3], encoding="utf-8", errors="replace").read().splitlines()[int(row[4]) - 1]
        except (OSError, IndexError, ValueError):
            text = ""
        if len(text) >= int(row[5] or 1):
            row[6] = "1"; fixed += 1
        else:
            dropped += 1; continue
    kept.append("|".join(row))
open(sys.argv[1], "w").write("\n".join(kept) + ("\n" if kept else ""))
print(f"[sdt] dart analyze: {len(rows)} diagnostics, {unresolved} unresolved-dependency, {fixed} zero-length fixed, {dropped} dropped")
sys.exit(3 if unresolved >= 25 and unresolved >= len(rows) * 0.25 else 0)
PY
    then
      log "unresolved-dependency flood: not importing dart diagnostics"; : > "$DART_REPORT"
      echo "Dart lint not imported: most diagnostics were unresolved imports (dependencies incomplete)." >> "$OUT/coverage.txt"
    fi
  else
    tail -5 "$OUT/pub-get.log"; log "pub get failed: skipping dart analyze (no phantom import)"
    echo "Dart lint skipped: dependencies did not resolve with the scanner's Flutter SDK; security rules still ran." >> "$OUT/coverage.txt"
  fi
fi

# ------------------------------------------------------ 4. SonarQube analysis
# OpenGrep, secrets and dependencies go through sonar-opengrep-dart as native rules;
# only what it cannot represent (misconfigurations, image scans) is an external issue.
python3 "$SDT_HOME/tools/sdt_to_sonar.py" --from "$REPORT_FINDINGS" --out "$OUT/sonar-external.json" \
  --repo-root "$SRC" --skip-adapter opengrep --skip-adapter gitleaks --skip-adapter trivy-fs
SUFFIX=$(printf '%s' "$WORKSPACE_NAME/$REPO_SLUG" | sha256sum | cut -c1-10)
PROJECT_KEY="sdt_$(printf '%s' "${WORKSPACE_NAME}_$REPO_SLUG" | tr '.-' '__' | cut -c1-160)_$SUFFIX"
echo "$PROJECT_KEY" > "$OUT/sonar-project-key"
sonar_api() { printf 'user = "%s:"\n' "$SONAR_TOKEN" | curl -sS -K - "$SONAR_HOST_URL$1"; }
EXISTS=$(printf 'user = "%s:"\n' "$SONAR_TOKEN" | curl -s -o /dev/null -w '%{http_code}' -K - \
  "$SONAR_HOST_URL/api/components/show?component=$PROJECT_KEY")
SCOPE_ARGS=(); SCOPE_QUERY=""
if [ -n "${PR_ID:-}" ]; then
  SCOPE_ARGS=(-Dsonar.pullrequest.key="$PR_ID" -Dsonar.pullrequest.branch="${PR_BRANCH:?}" -Dsonar.pullrequest.base="$PR_BASE")
  SCOPE_QUERY="&pullRequest=$PR_ID"
elif [ "$EXISTS" = 200 ] && [[ "$MAIN_BRANCHES" != *" ${BRANCH:?} "* ]]; then
  # The first analysis of a project must not name a branch (it becomes the main branch).
  SCOPE_ARGS=(-Dsonar.branch.name="$BRANCH"); SCOPE_QUERY="&branch=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$BRANCH")"
fi
echo "$SCOPE_QUERY" > "$OUT/sonar-scope-query"
# Test code is analysed as test code: SonarQube's security rules for application code (hard-coded
# credentials, weak hashing, ...) do not report fixtures and negative test inputs. SDT's own scanners
# still cover these files, so a real secret in a test is reported all the same.
TEST_ARGS=(-Dsonar.tests=)
if [ -n "$SONAR_TEST_PATTERNS" ]; then
  TEST_ARGS=(-Dsonar.tests=. -Dsonar.test.inclusions="$SONAR_TEST_PATTERNS" -Dsonar.exclusions="$SONAR_TEST_PATTERNS")
  # That is only right if tests are not shipped. Say so when an image build would include them.
  if [ -f "$SRC/Dockerfile" ]; then
    for dir in test tests __tests__; do
      [ -d "$SRC/$dir" ] || continue
      grep -qxE "/?$dir(/|/\*\*)?" "$SRC/.dockerignore" 2>/dev/null \
        || echo "Test directory '$dir' is not excluded in .dockerignore: it may ship in the image, but SonarQube analysed it as test code only." >> "$OUT/coverage.txt"
    done
  fi
fi
log "SonarQube analysis of $PROJECT_KEY"
( cd "$SRC" && "$SONAR_SCANNER" -Dsonar.host.url="$SONAR_HOST_URL" -Dsonar.projectKey="$PROJECT_KEY" \
    -Dsonar.projectName="$WORKSPACE_NAME/$REPO_SLUG" -Dsonar.sources=. "${TEST_ARGS[@]}" \
    -Dsonar.externalIssuesReportPaths="$OUT/sonar-external.json" \
    -Dsonar.opengrep.reportPaths="$REPORT_FINDINGS" -Dsonar.xml.file.suffixes=.xml,.plist \
    -Dsonar.dart.analyzer.mode=MANUAL -Dsonar.dart.analyzer.report.mode=MACHINE \
    -Dsonar.dart.analyzer.report.path="$DART_REPORT" -Dsonar.dart.analyzer.options.override=false \
    -Dsonar.working.directory="$OUT/scannerwork" "${SCOPE_ARGS[@]}" ) > "$OUT/sonar-scanner.log" 2>&1 \
  || { tail -30 "$OUT/sonar-scanner.log"; log "sonar-scanner failed"; exit 1; }
grep -E "OpenGrep:" "$OUT/sonar-scanner.log" || true

TASK=$(grep -oE 'api/ce/task[?]id=[A-Za-z0-9_-]+' "$OUT/sonar-scanner.log" | head -1 | cut -d= -f2)
[ -n "$TASK" ] || { log "no Compute Engine task id (upload failed?)"; exit 1; }
for _ in $(seq 1 120); do
  STATUS=$(sonar_api "/api/ce/task?id=$TASK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["task"]["status"])')
  case "$STATUS" in SUCCESS) log "SonarQube import confirmed"; break ;; FAILED|CANCELED) log "import $STATUS"; exit 1 ;; esac
  sleep 5
done
[ "$STATUS" = SUCCESS ] || { log "import unconfirmed after 10 minutes"; exit 1; }

# A review decision made on another branch of this project (Safe, False positive, Accepted) holds
# here too, for the same rule on the same line of code. Best effort; SONAR_CARRY_DECISIONS=0 turns it off.
if [ "${SONAR_CARRY_DECISIONS:-1}" = 1 ]; then
  CARRY_SCOPE=()
  if [ -n "${PR_ID:-}" ]; then CARRY_SCOPE=(--pull-request "$PR_ID")
  elif [ -n "$SCOPE_QUERY" ]; then CARRY_SCOPE=(--branch "$BRANCH"); fi
  python3 "$SDT_HOME/tools/sdt_sonar_carry.py" --sonar-url "$SONAR_HOST_URL" --project-key "$PROJECT_KEY" \
    "${CARRY_SCOPE[@]}" || log "review decisions were not carried over from other branches"
fi

# ------------------------------------------------------------ 5. quality gate
GATE=$(sonar_api "/api/qualitygates/project_status?projectKey=$PROJECT_KEY$SCOPE_QUERY" \
  | python3 -c 'import json,sys; s=json.load(sys.stdin)["projectStatus"]; print(s["status"]); [print("  ", c["metricKey"], c["status"], c.get("actualValue","")) for c in s.get("conditions",[]) if c["status"]!="OK"]')
printf '%s\n' "$GATE" > "$OUT/quality-gate.txt"
log "quality gate: $(head -1 "$OUT/quality-gate.txt")"
if [ "$QUALITY_GATE_ENFORCE" = 1 ] && [ "$(head -1 "$OUT/quality-gate.txt")" = ERROR ]; then
  sed 1d "$OUT/quality-gate.txt"; exit 2
fi
