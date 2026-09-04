# SDT OCI toolchain image (PRD REL-001): non-root, pinned tools.
# Build: docker build -f packaging/Dockerfile -t secure-development-tools:<version> .
# Run (provider-neutral):
#   docker run --rm --read-only \
#     -v "$PWD:/workspace:ro" -v "$PWD/reports:/reports" -v "$SDT_CACHE_DIR:/cache" \
#     --workdir /workspace secure-development-tools:<version> \
#     scan --profile "$SDT_PROFILE" --output /reports --cache /cache
ARG GO_VERSION=1.24.6
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/sdt ./cmd/sdt

FROM debian:bookworm-slim
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.73.0
# NOTE: opengrep installed in lab images via release manifest; pinned at build time.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd -r sdt && useradd -r -g sdt -d /workspace sdt
COPY --from=build /out/sdt /usr/local/bin/sdt
COPY rules /opt/sdt/rules
USER sdt
WORKDIR /workspace
VOLUME ["/reports", "/cache"]
ENTRYPOINT ["sdt"]
