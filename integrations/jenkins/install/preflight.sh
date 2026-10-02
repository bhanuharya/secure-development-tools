#!/usr/bin/env bash
# Check that an SDT scanner install can run a scan, before the first job does.
#
# Run it where scans run: inside the scanner image, or on the agent that has the tools.
# It changes nothing. Each line is OK, WARN (works, but a feature is off or unusual) or
# FAIL (a scan would break); the exit code is 1 when anything failed.
#
#   SONAR_HOST_URL=https://sonar.example.com SONAR_TOKEN=... install/preflight.sh
#
# Optional: SDT_HOME (/opt/sdt), FLEET_DATABASE, SDT_STATE_DIR, SDT_HISTORY_DIR,
#           BITBUCKET_REPO (workspace/repository, to prove the SSH key can read it),
#           SDT_AI_TRIAGE / SDT_AI_AUTOCLOSE / SDT_AI_DIFF_REVIEW (to check the AI pieces).
set -uo pipefail
set +x  # never trace: SONAR_TOKEN is in the environment

SDT_HOME="${SDT_HOME:-/opt/sdt}"
SONAR_SCANNER="${SONAR_SCANNER:-sonar-scanner}"
failed=0
ok()   { printf 'OK    %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failed=1; }
have() { command -v "$1" >/dev/null 2>&1; }
first_line() { "$@" 2>&1 | head -1 | cut -c1-80; }

echo "== SDT"
if [ -x "$SDT_HOME/sdt" ]; then ok "sdt: $(first_line "$SDT_HOME/sdt" version)"; else fail "no sdt binary at $SDT_HOME/sdt (set SDT_HOME)"; fi
for part in tools/sdt_to_docx.py tools/sdt_sonar_carry.py rules/opengrep-rules examples/fleet/scan-config.yaml; do
  [ -e "$SDT_HOME/$part" ] || fail "missing $SDT_HOME/$part"
done
[ -d "$SDT_HOME/rules/opengrep-rules" ] && ok "rule pack: $(find "$SDT_HOME/rules/opengrep-rules" -name '*.yaml' | wc -l) rule files"

echo "== tools"
for tool in git python3 opengrep gitleaks trivy; do
  if have "$tool"; then ok "$tool: $(first_line "$tool" --version)"; else fail "$tool is not on PATH"; fi
done
if have "$SONAR_SCANNER"; then ok "sonar-scanner found"; else fail "sonar-scanner is not on PATH (set SONAR_SCANNER)"; fi
if have flutter; then ok "flutter found (Dart repositories get lint results)"; else warn "no flutter: Dart repositories are scanned without Dart lint"; fi
if [ -d "$SDT_HOME/src" ]; then
  if (cd "$SDT_HOME" && python3 -c 'import sqlmodel, src.api.database' >/dev/null 2>&1); then ok "python can load the review store"
  else warn "python cannot import the review store (requirements.txt): SDT_FLEET_DATABASE features will not work"; fi
fi

echo "== SonarQube"
if [ -z "${SONAR_HOST_URL:-}" ] || [ -z "${SONAR_TOKEN:-}" ]; then
  fail "set SONAR_HOST_URL and SONAR_TOKEN to check SonarQube"
else
  sonar() { printf 'user = "%s:"\n' "$SONAR_TOKEN" | curl -sS -m 20 -K - "${SONAR_HOST_URL%/}$1" 2>/dev/null; }
  field() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null; }
  status=$(sonar /api/system/status | field "d['status']+' '+d['version']")
  case "$status" in UP*) ok "SonarQube ${status#UP } is up" ;; *) fail "SonarQube not reachable or not UP at $SONAR_HOST_URL ($status)" ;; esac
  [ "$(sonar /api/authentication/validate | field "d['valid']")" = True ] && ok "token is valid" || fail "SonarQube rejects the token"
  permissions=$(sonar /api/users/current | field "' '.join(d.get('permissions',{}).get('global',[]))")
  case " $permissions " in *" scan "*) ok "token may run analyses" ;; *) fail "token lacks Execute Analysis (has: ${permissions:-none})" ;; esac
  case " $permissions " in *" admin "*) warn "token is a full administrator: use a narrower one for scans" ;; esac
  plugins=$(sonar /api/plugins/installed | field "' '.join(p['key'] for p in d['plugins'])")
  if [ -z "$plugins" ]; then warn "cannot list plugins with this token: check sonar-opengrep-dart and the branch plugin by hand"
  else
    case " $plugins " in *opengrep*) ok "plugin: OpenGrep rules" ;; *) fail "sonar-opengrep-dart is not installed: SDT findings would not be imported" ;; esac
    case " $plugins " in *" dart "*|*flutter*) ok "plugin: Dart/Flutter" ;; *) warn "no Dart plugin: Dart repositories show no Dart code" ;; esac
    edition=$(sonar /api/navigation/global | field "d.get('edition','')")
    case "$edition:$plugins " in
      community:*communityBranchPlugin*) ok "branches and pull requests: community branch plugin" ;;
      community:*) fail "Community Edition without the community branch plugin: release-branch and pull-request scans will fail" ;;
      *) ok "branches and pull requests: built in (${edition:-unknown} edition)" ;;
    esac
  fi
  gate=$(sonar /api/qualitygates/list | field "next(g['name'] for g in d['qualitygates'] if g.get('isDefault'))")
  conditions=$(sonar "/api/qualitygates/show?name=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$gate")" | field "' '.join(c['metric'] for c in d.get('conditions',[]))")
  ok "default quality gate: ${gate:-unknown} (${conditions:-no conditions})"
  for metric in new_coverage new_violations new_duplicated_lines_density; do
    case " $conditions " in *" $metric "*) warn "the gate checks $metric, which is not a security condition: pull requests can fail on it" ;; esac
  done
fi

echo "== Bitbucket"
if ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -T git@bitbucket.org 2>&1 | grep -qi 'authenticated\|logged in'; then ok "SSH key is accepted by bitbucket.org"
else fail "bitbucket.org does not accept this user's SSH key (or no ssh-agent is forwarded)"; fi
if [ -n "${BITBUCKET_REPO:-}" ]; then
  git ls-remote --heads "git@bitbucket.org:$BITBUCKET_REPO.git" >/dev/null 2>&1 && ok "can read $BITBUCKET_REPO" || fail "cannot read $BITBUCKET_REPO"
fi

echo "== state kept between scans"
writable() { mkdir -p "$1" 2>/dev/null && [ -w "$1" ]; }
history="${SDT_HISTORY_DIR:-${SDT_STATE_DIR:+$SDT_STATE_DIR/history}}"
if [ -z "$history" ]; then warn "no SDT_STATE_DIR or SDT_HISTORY_DIR: reports have no 'changes since previous scan'"
elif writable "$history"; then ok "scan history: $history"; else fail "scan history directory is not writable: $history"; fi
if [ -z "${FLEET_DATABASE:-}" ]; then warn "no FLEET_DATABASE: review decisions are not recorded, reviewed false positives are not applied"
elif (cd "$SDT_HOME" && SCP_DATABASE_URL="$FLEET_DATABASE" python3 -c 'from src.api.database import init_db; init_db()' >/dev/null 2>&1); then ok "review store is reachable and initialised"
else fail "cannot open the review store (FLEET_DATABASE)"; fi

echo "== AI review (optional)"
if [ "${SDT_AI_TRIAGE:-1}" = 0 ]; then ok "AI review is switched off (SDT_AI_TRIAGE=0)"
elif ! have "${SDT_CODEX_BIN:-codex}"; then warn "no codex CLI: reports use the built-in advisory; auto-close and change review do nothing"
else
  ok "codex: $(first_line "${SDT_CODEX_BIN:-codex}" --version)"
  "${SDT_CODEX_BIN:-codex}" login status >/dev/null 2>&1 && ok "codex is logged in" || warn "codex is not logged in (mount CODEX_HOME with a login): AI steps will be skipped"
  memory="${SDT_TRIAGE_MEMORY:+$(dirname "$SDT_TRIAGE_MEMORY")}"; memory="${memory:-${SDT_STATE_DIR:+$SDT_STATE_DIR/triage}}"
  if [ -z "$memory" ]; then warn "no SDT_STATE_DIR: AI verdicts are remembered in the home directory, which a container loses"
  elif writable "$memory"; then ok "AI verdict memory: $memory"; else fail "AI verdict memory is not writable: $memory"; fi
  [ "${SDT_AI_AUTOCLOSE:-0}" = 1 ] && warn "SDT_AI_AUTOCLOSE=1: clear false positives are marked Safe without a person"
  [ "${SDT_AI_DIFF_REVIEW:-0}" = 1 ] && ok "pull requests get an AI change review"
fi

echo
[ "$failed" = 0 ] && echo "preflight: ready to scan" || echo "preflight: fix the FAIL lines before the first scan"
exit "$failed"
