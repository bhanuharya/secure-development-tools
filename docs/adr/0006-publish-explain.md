# ADR 0006: Offline publish payloads and local-only explanations

Date: 2026-09-04
Status: accepted (PRD PUB-001, AI-001 — MVP scope)

## Context

PRD PUB-001 requires provider publication as a separate no-rescan command;
AI-001 requires opt-in, redacted, advisory explanation that cannot change
the policy decision. Both are P1 (company pilot), but thin MVP-safe versions
unblock lab use without network or credentials.

## Decision

- `sdt publish --provider github|bitbucket|gitlab` builds offline payload
  files from saved `findings.json` + `run-manifest.json` only
  (`internal/publish`): GitHub check annotations (capped at 50, blockers
  first) + step summary, Bitbucket Code Insights report, GitLab Code
  Quality report. No API calls, no rescan, checksummed inputs untouched.
- `sdt explain` renders a local template (`sdt-explain/v1`,
  `internal/app/explain.go`) over redacted canonical findings. No network,
  no model. Secret-category evidence is replaced with a placeholder.
  Disabled unless `ai.enabled=true`; the file header states provenance and
  non-authority.
- Gated by explicit config: `publish.enabled` and `ai.enabled` default to
  false. Enabling either never alters scan exit codes or artifacts.

## Consequences

- Delivery (API POSTs with provider tokens) stays out of core; a later
  publisher can consume the same payload files.
- A future model-backed explainer must reuse the redaction boundary and
  record provider/model/template identifiers.
