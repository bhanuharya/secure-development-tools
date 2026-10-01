# SDT scanner image: everything scan.sh and reports.sh call, at pinned versions, as a
# non-root user. Build it from the repository root, with the root as the `sdt` context:
#
#   docker buildx build -f integrations/jenkins/docker/Dockerfile \
#     --build-context sdt=. \
#     -t registry.example.com/appsec/sdt-scanner:2026.09 integrations/jenkins/docker/
#
# Flutter (~1.5 GB) is optional: pass --build-arg FLUTTER_VERSION= to leave it out for
# workspaces without Dart repositories.

ARG GO_VERSION=1.24.6

# ---------------------------------------------------------------- sdt binary
FROM golang:${GO_VERSION}-bookworm AS sdt-build
WORKDIR /src
COPY --from=sdt go.mod go.sum ./
RUN go mod download
COPY --from=sdt . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sdt ./cmd/sdt

# ------------------------------------------------------------------ scanner
FROM debian:bookworm-slim
ARG OPENGREP_VERSION=v1.29.0
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.73.0
ARG SONAR_SCANNER_VERSION=6.2.1.4610
ARG FLUTTER_VERSION=3.47.4

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git openssh-client unzip xz-utils python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fsSLo /usr/local/bin/opengrep \
      "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86"; \
    chmod +x /usr/local/bin/opengrep; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      | tar -xz -C /usr/local/bin trivy; \
    curl -fsSLo /tmp/scanner.zip \
      "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip"; \
    unzip -q /tmp/scanner.zip -d /opt; rm /tmp/scanner.zip; \
    ln -s "/opt/sonar-scanner-${SONAR_SCANNER_VERSION}-linux-x64/bin/sonar-scanner" /usr/local/bin/sonar-scanner

RUN if [ -n "${FLUTTER_VERSION}" ]; then \
      curl -fsSL "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_${FLUTTER_VERSION}-stable.tar.xz" \
        | tar -xJ -C /opt; \
    fi
ENV FLUTTER_HOME=/opt/flutter PATH="/opt/flutter/bin:${PATH}"

# SDT: binary, rule pack, tools, and the Python they need (in a venv, not system pip).
COPY --from=sdt-build /out/sdt /opt/sdt/sdt
COPY --from=sdt rules /opt/sdt/rules
COPY --from=sdt tools /opt/sdt/tools
COPY --from=sdt src /opt/sdt/src
COPY --from=sdt examples/fleet /opt/sdt/examples/fleet
COPY --from=sdt requirements.txt /opt/sdt/requirements.txt
RUN python3 -m venv /opt/sdt/venv && /opt/sdt/venv/bin/pip install --no-cache-dir -r /opt/sdt/requirements.txt
ENV PATH="/opt/sdt/venv/bin:${PATH}" SDT_HOME=/opt/sdt

# Private Bitbucket packages (git dependencies in pubspec.yaml) resolve over SSH with the
# credential Jenkins mounts; trust bitbucket.org's published host keys up front.
RUN useradd --create-home --uid 1000 scanner \
    && mkdir -p /home/scanner/.ssh && ssh-keyscan -t rsa,ecdsa,ed25519 bitbucket.org > /home/scanner/.ssh/known_hosts 2>/dev/null \
    && chown -R scanner:scanner /home/scanner /opt/flutter 2>/dev/null || true
USER scanner
RUN git config --global --add safe.directory '*' \
    && if [ -d /opt/flutter ]; then flutter config --no-analytics >/dev/null && flutter precache --no-android --no-ios >/dev/null; fi
WORKDIR /work
