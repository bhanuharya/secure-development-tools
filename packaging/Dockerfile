# SDT OCI runtime image (PRD REL-001): sdt binary + default rule bundle only.
# Build: docker build -f packaging/Dockerfile -t secure-development-tools:<version> .
# Run (provider-neutral):
#   docker run --rm --read-only \
#     -v "$PWD:/workspace:ro" -v "$PWD/reports:/reports" -v "$SDT_CACHE_DIR:/cache" \
#     --workdir /workspace secure-development-tools:<version> \
#     scan --profile "$SDT_PROFILE" --output /reports --cache /cache
#
# EXTERNAL TOOL CONTRACT (explicit, not self-contained):
# This image does NOT bundle opengrep, gitleaks, or trivy. Those scanner
# binaries must be provided at runtime (separate pinned tool image, mounted
# binaries on PATH, or SDT_OPENGREP_BIN / SDT_GITLEAKS_BIN / SDT_TRIVY_BIN
# overrides). Verified reference: opengrep v1.29.0 per README; other tools
# per upstream install docs. `sdt doctor` reports availability and scans
# fail closed when a required scanner binary is absent. No checksums are
# claimed here for binaries this image does not contain.
ARG GO_VERSION=1.24.6
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/sdt ./cmd/sdt

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd -r sdt && useradd -r -g sdt -d /workspace sdt
COPY --from=build /out/sdt /usr/local/bin/sdt
COPY rules /opt/sdt/rules
# Deterministic in-image rule resolution: adapters honor SDT_RULES_PACK_DIR
# first, so scans inside the image use the bundled pack regardless of the
# mounted workspace content.
ENV SDT_RULES_PACK_DIR=/opt/sdt/rules/opengrep-rules \
    SDT_DEFAULT_RULES_DIR=/opt/sdt/rules/opengrep-rules
# Fail the image build when the runtime payload is incomplete rather than
# shipping a silently rule-less or binary-less image.
RUN test -x /usr/local/bin/sdt \
  && test -d /opt/sdt/rules/opengrep-rules \
  && test -f /opt/sdt/rules/manifest.yaml
USER sdt
WORKDIR /workspace
VOLUME ["/reports", "/cache"]
ENTRYPOINT ["sdt"]
