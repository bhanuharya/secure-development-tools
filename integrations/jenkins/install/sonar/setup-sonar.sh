#!/usr/bin/env bash
# One-time (and re-runnable) SonarQube setup for SDT, after the plugins are installed:
#   1. per language: a "<LANG> + OpenGrep" profile inheriting the language's built-in
#      profile, with every OpenGrep rule active, set as default;
#   2. secrets: "Secrets + SDT" with the sdt rules (secrets, history secrets, dependencies);
#   3. the "SDT Security" quality gate, set as default.
#
#   SONAR_HOST_URL=https://sonar.example.com SONAR_TOKEN=<admin token> install/sonar/setup-sonar.sh [--gate-only]
#
# The token needs "Administer Quality Profiles" and "Administer Quality Gates". It is passed
# to curl on stdin, never on the command line.
set -euo pipefail
HOST="${SONAR_HOST_URL:?}"; : "${SONAR_TOKEN:?}"
api() { local method="$1" path="$2"; shift 2
  printf 'user = "%s:"\n' "$SONAR_TOKEN" | curl -sS --fail-with-body -K - -X "$method" "$HOST$path" "$@"; }
json() { local code="$1"; shift; python3 -c "import json,sys; d=json.load(sys.stdin); $code" "$@"; }

# ------------------------------------------------------------- 1+2. profiles
if [ "${1:-}" != "--gate-only" ]; then
languages=$(api GET /api/rules/repositories | json 'print(" ".join(sorted({r["language"] for r in d["repositories"] if r["key"].startswith("opengrep-") or r["key"]=="sdt"})))')
[ -n "$languages" ] || { echo "no opengrep-* or sdt rule repositories: is sonar-opengrep-dart installed?" >&2; exit 1; }
for lang in $languages; do
  parent=$(api GET /api/qualityprofiles/search --get --data-urlencode "language=$lang" \
    | json 'ps=[p for p in d["profiles"] if p.get("isBuiltIn") and p["name"]!="OpenGrep Security"]; print(ps[0]["name"] if ps else "")')
  if [ -z "$parent" ]; then echo "$lang: no built-in profile to inherit; skipped"; continue; fi
  name="$( [ "$lang" = secrets ] && echo "Secrets + SDT" || echo "$(echo "$lang" | tr a-z A-Z) + OpenGrep")"
  key=$(api GET /api/qualityprofiles/search --get --data-urlencode "language=$lang" \
    | json "print(next((p['key'] for p in d['profiles'] if p['name']==sys.argv[1]), ''))" "$name")
  if [ -z "$key" ]; then
    key=$(api POST /api/qualityprofiles/create --data-urlencode "language=$lang" --data-urlencode "name=$name" \
      | json 'print(d["profile"]["key"])')
  fi
  api POST /api/qualityprofiles/change_parent --data-urlencode "language=$lang" \
    --data-urlencode "qualityProfile=$name" --data-urlencode "parentQualityProfile=$parent" > /dev/null
  activated=$(api POST /api/qualityprofiles/activate_rules --data-urlencode "targetKey=$key" \
    --data-urlencode "repositories=opengrep-$lang,sdt" --data-urlencode "languages=$lang" | json 'print(d.get("succeeded",0))')
  api POST /api/qualityprofiles/set_default --data-urlencode "language=$lang" --data-urlencode "qualityProfile=$name" > /dev/null
  echo "$lang: '$name' (inherits '$parent', +$activated rules) is the default"
done
fi

# ------------------------------------------------------------- 3. quality gate
GATE="SDT Security"
show() { api GET /api/qualitygates/show --get --data-urlencode "name=$GATE"; }
show > /dev/null 2>&1 || api POST /api/qualitygates/create --data-urlencode "name=$GATE" > /dev/null
# New code only: legacy findings are tracked, not blocking; nothing new may add risk.
wanted="new_vulnerabilities:GT:0 new_security_hotspots_reviewed:LT:100 new_security_rating:GT:1"
conditions=$(show | json 'print("\n".join(c["metric"] + " " + str(c["id"]) for c in d.get("conditions",[])))')
for want in $wanted; do
  IFS=: read -r metric op error <<< "$want"
  grep -q "^$metric " <<< "$conditions" || api POST /api/qualitygates/create_condition --data-urlencode "gateName=$GATE" \
    --data-urlencode "metric=$metric" --data-urlencode "op=$op" --data-urlencode "error=$error" > /dev/null
done
# SonarQube creates a gate with its own conditions (coverage, duplication, any new issue). They are
# not security: a pull request must not fail this gate for missing tests.
while read -r metric id; do
  case " $wanted " in *" $metric:"*) continue ;; esac
  [ -z "$id" ] || api POST /api/qualitygates/delete_condition --data-urlencode "id=$id" > /dev/null
done <<< "$conditions"
api POST /api/qualitygates/set_as_default --data-urlencode "name=$GATE" > /dev/null
echo "quality gate '$GATE' is the default: new vulnerabilities = 0, new hotspots 100% reviewed, new security rating A"
