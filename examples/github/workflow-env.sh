#!/usr/bin/env bash
# GitHub edge mapping -> neutral SDT_* context (provider at the edge, PRD P-04).
# Map github.event_name / base / head into SDT_EVENT / SDT_BASE / SDT_HEAD,
# then invoke the generic container exactly once.
set -euo pipefail
export SDT_EVENT=pull_request
export SDT_BASE="origin/${BASE_REF:-main}"
export SDT_HEAD="${GITHUB_SHA:-HEAD}"
export SDT_PROFILE="${SDT_PROFILE:-pr}"
exec bash "$(dirname "$0")/../generic-ci/pipeline.sh"
