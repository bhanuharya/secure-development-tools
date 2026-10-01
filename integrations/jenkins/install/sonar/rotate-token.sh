#!/usr/bin/env bash
# Rotate a SonarQube user token kept in a file: generate a new token for the same user,
# write it to the file (mode 600), prove it works, then revoke the old token by name.
# The token value is never printed or put on a command line.
#
#   install/sonar/rotate-token.sh --url http://localhost:9000 --token-file ~/.sonar-token \
#       --revoke sdt-fleet [--name sdt-fleet] [--days 90]
#
# --revoke names the token being replaced (see My Account > Security, or
# /api/user_tokens/search). The new token is called "<name>-<date>".
set -euo pipefail
URL=""; FILE=""; REVOKE=""; NAME="sdt"; DAYS=90
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;; --token-file) FILE="$2"; shift 2 ;; --revoke) REVOKE="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;; --days) DAYS="$2"; shift 2 ;;
    *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
  esac
done
[ -n "$URL" ] && [ -n "$FILE" ] && [ -n "$REVOKE" ] || { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ -s "$FILE" ] || { echo "no token in $FILE" >&2; exit 1; }
umask 077

api() { # api TOKEN_FILE METHOD PATH [curl args]
  local file="$1" method="$2" path="$3"; shift 3
  printf 'user = "%s:"\n' "$(tr -d '\n' < "$file")" | curl -sS --fail-with-body -K - -X "$method" "$URL$path" "$@"
}

names=$(api "$FILE" GET /api/user_tokens/search | python3 -c 'import json,sys; print(" ".join(t["name"] for t in json.load(sys.stdin)["userTokens"]))')
case " $names " in *" $REVOKE "*) ;; *) echo "no token named '$REVOKE' for this user (have: $names)" >&2; exit 1 ;; esac

new_name="$NAME-$(date +%Y%m%d-%H%M)"
expires=$(date -d "+$DAYS days" +%Y-%m-%d)
tmp="$(mktemp "$(dirname "$FILE")/.token.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
api "$FILE" POST /api/user_tokens/generate --data-urlencode "name=$new_name" --data-urlencode "type=USER_TOKEN" \
    --data-urlencode "expirationDate=$expires" \
  | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["token"])' > "$tmp"
[ -s "$tmp" ] || { echo "SonarQube returned no token" >&2; exit 1; }

valid=$(api "$tmp" GET /api/authentication/validate | python3 -c 'import json,sys; print(json.load(sys.stdin)["valid"])')
[ "$valid" = True ] || { echo "the new token does not validate; the old one is untouched" >&2; exit 1; }
chmod 600 "$tmp" && mv "$tmp" "$FILE"
trap - EXIT

api "$FILE" POST /api/user_tokens/revoke --data-urlencode "name=$REVOKE" > /dev/null
echo "rotated: '$REVOKE' revoked; '$new_name' (expires $expires) is in $FILE"
