#!/usr/bin/env bash
# Update the SDT checkout that the scan jobs run (SDT_HOME) to a released revision.
#
# The jobs read the sdt binary, tools/, rules/ and examples/ from SDT_HOME. Keeping that a
# separate checkout from the one you develop in means a half-finished edit can never be what
# the next scan runs: a scan changes only when this script is run.
#
#   install/update-sdt.sh --home /opt/sdt [--ref origin/main]
set -euo pipefail
HOME_DIR=""; REF="origin/main"
while [ $# -gt 0 ]; do
  case "$1" in
    --home) HOME_DIR="$2"; shift 2 ;; --ref) REF="$2"; shift 2 ;;
    *) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
  esac
done
[ -n "$HOME_DIR" ] && [ -d "$HOME_DIR/.git" ] || { echo "--home must be a git checkout of SDT" >&2; exit 2; }
cd "$HOME_DIR"
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "$HOME_DIR has local changes; not updating" >&2; exit 1; }
before=$(git rev-parse --short HEAD)
git fetch --quiet origin
git checkout --quiet --detach "$REF"
# Build next to the old binary and swap, so a scan never starts a half-written file.
go build -o sdt.new ./cmd/sdt
mv sdt.new sdt
echo "SDT_HOME $HOME_DIR: $before -> $(git rev-parse --short HEAD) ($(./sdt version 2>/dev/null | head -1))"
