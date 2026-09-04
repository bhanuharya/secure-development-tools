# ADR 0005: OCI-first distribution, no hosted service

Date: 2026-09-04
Status: accepted

## Context

PRD §24 / CORE-002: personal-lab MVP must run without provider credentials
or a hosted SDT service; OCI image is the portability baseline (NFR-002).

## Decision

- Primary artifact: versioned multi-arch OCI image with pinned `sdt` +
  scanner binaries + default rule bundle + tool manifest
  (versions, checksums, licenses, provenance).
- `latest` never used in examples; immutable version/digest references only.
- Update modes: `locked` (default for release), `database`, `rules`,
  `offline` (network prohibited, asset age recorded).
- No telemetry in MVP; metrics computed from local run manifests.

## Consequences

- `packaging/Dockerfile` builds a non-root image with read-only workspace
  mount and writable report/cache/tmp mounts.
- Local binary remains fully functional for laptop use.
