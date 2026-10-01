#!/usr/bin/env bash
# Create a Jenkins API token for your user and save it to a file (mode 600), so scripts
# (install/jenkins/update-jobs.sh, the SDT job script) can call Jenkins without your password.
# The password is read without echo and only sent to Jenkins; the token is never printed.
#
#   install/jenkins/create-api-token.sh --url http://localhost:8081/jenkins --user bhanuharya \
#       --token-file ~/.jenkins-api-token [--name sdt-automation]
set -euo pipefail
URL=""; USER_NAME=""; FILE=""; NAME="sdt-automation"
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="${2%/}"; shift 2 ;; --user) USER_NAME="$2"; shift 2 ;; --token-file) FILE="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;; *) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
  esac
done
[ -n "$URL" ] && [ -n "$USER_NAME" ] && [ -n "$FILE" ] || { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
umask 077
read -r -s -p "Jenkins password for $USER_NAME: " PASSWORD; echo
jar="$(mktemp)"; tmp="$(mktemp "$(dirname "$FILE")/.jenkins-token.XXXXXX")"
trap 'rm -f "$jar" "$tmp"; unset PASSWORD' EXIT
auth() { printf 'user = "%s:%s"\n' "$USER_NAME" "$PASSWORD"; }

crumb=$(auth | curl -sS --fail -K - -c "$jar" "$URL/crumbIssuer/api/json" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["crumbRequestField"] + ":" + d["crumb"])') \
  || { echo "login failed (wrong password, or the user cannot reach $URL)" >&2; exit 1; }
auth | curl -sS --fail -K - -b "$jar" -H "$crumb" -X POST \
    "$URL/user/$USER_NAME/descriptorByName/jenkins.security.ApiTokenProperty/generateNewToken" \
    --data-urlencode "newTokenName=$NAME" \
  | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["data"]["tokenValue"])' > "$tmp"
[ -s "$tmp" ] || { echo "Jenkins returned no token" >&2; exit 1; }

# Prove it works on its own (no password, no session) before keeping it.
code=$(printf 'user = "%s:%s"\n' "$USER_NAME" "$(cat "$tmp")" | curl -s -o /dev/null -w '%{http_code}' -K - "$URL/api/json")
[ "$code" = 200 ] || { echo "the new token was rejected ($code)" >&2; exit 1; }
chmod 600 "$tmp" && mv "$tmp" "$FILE"
echo "Jenkins API token '$NAME' for $USER_NAME saved to $FILE"
