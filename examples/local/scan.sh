#!/usr/bin/env bash
# Local scan with an explicit context (PRD §20). No provider needed.
set -euo pipefail
sdt doctor
sdt plan --profile pr --base origin/main --head HEAD
sdt scan --profile pr --base origin/main --head HEAD \
  --output reports --cache .cache/sdt
