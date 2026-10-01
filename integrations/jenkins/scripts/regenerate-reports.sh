#!/usr/bin/env bash
# Rebuild SAST reports from finished Jenkins builds, without rescanning: each build's archived
# findings.json and triage.json, SonarQube as it is now, and the exact scanned commit (for code
# excerpts and Bitbucket links). Use it after changing the report tool.
#
#   JENKINS_URL=https://jenkins.example.com/job/sonarqube-scanner JENKINS_USER=me \
#   JENKINS_API_TOKEN_FILE=~/.jenkins-api-token SONAR_HOST_URL=https://sonar.example.com \
#   SONAR_TOKEN=... WORKSPACE_NAME=my-workspace SDT_HOME=~/secure-development-tools \
#   OUT=./reports scripts/regenerate-reports.sh 25 26 27
#
# Optional: PREVIOUS="17 18 19" (earlier builds of the same repositories) adds the trend section.
set -uo pipefail
: "${JENKINS_URL:?}" "${JENKINS_USER:?}" "${JENKINS_API_TOKEN_FILE:?}" "${SONAR_HOST_URL:?}" "${SONAR_TOKEN:?}"
: "${WORKSPACE_NAME:?}" "${SDT_HOME:?}" "${OUT:?}"
[ $# -gt 0 ] || { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
AUTH="$JENKINS_USER:$(tr -d '\n' < "$JENKINS_API_TOKEN_FILE")"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
get() { printf 'user = "%s"\n' "$AUTH" | curl -sS -K - "$@"; }
params() { get "$JENKINS_URL/$1/api/json?tree=actions%5Bparameters%5Bname,value%5D%5D" | python3 -c '
import json,sys; d=json.load(sys.stdin); p={x["name"]:x["value"] for a in d["actions"] if a and "parameters" in a for x in a["parameters"]}
print(p["reponame"], p["branch"])'; }

declare -A PREV
for n in ${PREVIOUS:-}; do read -r repo _ < <(params "$n"); PREV[$repo]=$n; done

for n in "$@"; do
  read -r repo branch < <(params "$n")
  W="$WORK/$repo"; mkdir -p "$W"
  console="$(get "$JENKINS_URL/$n/consoleText")"
  commit="$(printf '%s' "$console" | grep -m1 -oE 'Checking out Revision [0-9a-f]{40}' | awk '{print $4}')"
  [ -n "$commit" ] || { echo "#$n $repo: scanned commit not found in the log"; continue; }
  get -o "$W/findings.json" "$JENKINS_URL/$n/artifact/out/findings.json"
  get -o "$W/triage.json" "$JENKINS_URL/$n/artifact/triage.json"; head -c1 "$W/triage.json" | grep -q '{' || rm -f "$W/triage.json"
  [ -n "${PREV[$repo]:-}" ] && get -o "$W/previous.json" "$JENKINS_URL/${PREV[$repo]}/artifact/out/findings.json"
  : > "$W/coverage.txt"
  printf '%s' "$console" | grep -q "pub get failed" && \
    echo "Dart lint skipped: dependencies did not resolve with the scanner's Flutter SDK; security rules still ran." > "$W/coverage.txt"
  git clone -q --no-checkout "git@bitbucket.org:$WORKSPACE_NAME/$repo.git" "$W/src" && git -C "$W/src" checkout -q "$commit" \
    || { echo "#$n $repo: checkout failed"; continue; }
  key="sdt_$(printf '%s' "${WORKSPACE_NAME}_$repo" | tr '.-' '__' | cut -c1-160)_$(printf '%s' "$WORKSPACE_NAME/$repo" | sha256sum | cut -c1-10)"
  args=(--sonar-url "$SONAR_HOST_URL" --project-key "$key" --branch "$branch" --findings "$W/findings.json"
        --src-root "$W/src" --repository "$WORKSPACE_NAME/$repo" --commit "${commit:0:12}" --coverage "$W/coverage.txt"
        --scope-url "https://bitbucket.org/$WORKSPACE_NAME/$repo/branch/$branch")
  [ -s "$W/triage.json" ] && args+=(--triage "$W/triage.json")
  [ -s "$W/previous.json" ] && args+=(--previous-findings "$W/previous.json")
  python3 "$SDT_HOME/tools/sdt_to_docx.py" "${args[@]}" --out "$OUT/SAST Report - $repo.docx" | sed "s/^/#$n /"
done
