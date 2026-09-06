#!/usr/bin/env bash
# Generic CI wrapper: checkout, neutral context, pinned image, retain artifacts.
# Never edits policy here; all behavior lives in .secure-dev.yaml.
set -euo pipefail
: "${SDT_PROFILE:=pr}"
: "${SDT_CACHE_DIR:=$PWD/.cache/sdt}"
checkout --history="required-by-profile"

# Forward the full neutral SDT_* context into the container so a CI run
# reproduces a local run bit-for-bit. Output/cache dirs are remapped to the
# container mount points (/reports, /cache); every other neutral variable
# passes through verbatim when set on the host.
docker run --rm \
  --read-only \
  --volume "$PWD:/workspace:ro" \
  --volume "$PWD/reports:/reports" \
  --volume "$SDT_CACHE_DIR:/cache" \
  --workdir /workspace \
  -e "SDT_CONFIG=${SDT_CONFIG:-}" \
  -e "SDT_PROFILE=${SDT_PROFILE:-pr}" \
  -e "SDT_EVENT=${SDT_EVENT:-local}" \
  -e "SDT_BASE=${SDT_BASE:-}" \
  -e "SDT_HEAD=${SDT_HEAD:-HEAD}" \
  -e "SDT_IMAGE=${SDT_IMAGE:-}" \
  -e SDT_OUTPUT_DIR=/reports \
  -e SDT_CACHE_DIR=/cache \
  -e "SDT_OFFLINE=${SDT_OFFLINE:-}" \
  secure-development-tools:<pinned-version> \
  scan --profile "$SDT_PROFILE" --output /reports --cache /cache

retain-artifacts reports/
