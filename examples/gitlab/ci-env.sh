#!/usr/bin/env bash
# GitLab edge mapping -> neutral SDT_* context.
set -euo pipefail
if [ -n "${CI_MERGE_REQUEST_IID:-}" ]; then
  export SDT_EVENT=pull_request
  export SDT_BASE="origin/${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-main}"
  export SDT_HEAD="${CI_COMMIT_SHA:-HEAD}"
else
  export SDT_EVENT=push
  export SDT_HEAD="${CI_COMMIT_SHA:-HEAD}"
fi
export SDT_PROFILE="${SDT_PROFILE:-pr}"
exec bash "$(dirname "$0")/../generic-ci/pipeline.sh"
