#!/usr/bin/env bash
# Generic CI wrapper: checkout, neutral context, pinned image, retain artifacts.
# Never edits policy here; all behavior lives in .secure-dev.yaml.
set -euo pipefail
: "${SDT_PROFILE:=pr}"
: "${SDT_CACHE_DIR:=$PWD/.cache/sdt}"
checkout --history="required-by-profile"

docker run --rm \
  --read-only \
  --volume "$PWD:/workspace:ro" \
  --volume "$PWD/reports:/reports" \
  --volume "$SDT_CACHE_DIR:/cache" \
  --workdir /workspace \
  secure-development-tools:<pinned-version> \
  scan --profile "$SDT_PROFILE" --output /reports --cache /cache

retain-artifacts reports/
