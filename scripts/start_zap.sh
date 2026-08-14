#!/usr/bin/env bash
# Start OWASP ZAP (DAST) in Docker on 127.0.0.1:8080.
# Requires Docker Desktop (Windows/WSL) to be running first.
set -euo pipefail

ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
ZAP_API_KEY="${SCP_ZAP_API_KEY:-ccde052577282c3933fd9f3a12636084885cb2380a1caba5}"
ZAP_PORT="${ZAP_PORT:-8080}"
CONTAINER="secure-sdlc-zap"

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running. On Windows/WSL: start Docker Desktop first, then re-run this script." >&2
  exit 1
fi

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "Removing old $CONTAINER container..."
  docker rm -f "$CONTAINER" >/dev/null
fi

echo "Pulling $ZAP_IMAGE (first run downloads ~1GB)..."
docker pull "$ZAP_IMAGE"

echo "Starting ZAP on 127.0.0.1:$ZAP_PORT ..."
docker run -d \
  --name "$CONTAINER" \
  -p "${ZAP_PORT}:8080" \
  -v zap-data:/home/zap/data \
  -u zap \
  "$ZAP_IMAGE" \
  zap.sh -daemon \
    -host 0.0.0.0 -port 8080 \
    -config api.key="$ZAP_API_KEY"

echo "Waiting for ZAP API to become ready..."
for i in $(seq 1 60); do
  if curl -sf -m 3 "http://127.0.0.1:${ZAP_PORT}/JSON/core/view/version" >/dev/null 2>&1; then
    echo "ZAP is ready at http://127.0.0.1:${ZAP_PORT}"
    exit 0
  fi
  sleep 2
done
echo "ZAP container started but the API did not become ready within 2 minutes. Check: docker logs $CONTAINER" >&2
exit 1
