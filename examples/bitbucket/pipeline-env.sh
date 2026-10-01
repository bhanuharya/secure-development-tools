#!/usr/bin/env bash
# Bitbucket edge mapping -> neutral SDT_* context.
set -euo pipefail
if [ -n "${BITBUCKET_PR_ID:-}" ]; then
  export SDT_EVENT=pull_request
  export SDT_BASE="origin/${BITBUCKET_PR_DESTINATION_BRANCH:-main}"
  export SDT_HEAD="${BITBUCKET_COMMIT:-HEAD}"
else
  export SDT_EVENT=push
  export SDT_HEAD="${BITBUCKET_COMMIT:-HEAD}"
fi
export SDT_PROFILE="${SDT_PROFILE:-pr}"
exec bash "$(dirname "$0")/../generic-ci/pipeline.sh"
