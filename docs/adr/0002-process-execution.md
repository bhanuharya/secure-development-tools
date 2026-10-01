# ADR 0002: Direct argv process execution, no shell

Date: 2026-09-04
Status: accepted

## Context

PRD SEC-001 / EXEC-002: repository-controlled values (paths, revisions,
image references) are untrusted and must never enter a shell command.

## Decision

- All subprocesses use `os/exec` with executable + argument slice
  (`internal/execute`). No `sh -c`, no string concatenation.
- Configuration has no command-string fields by construction (typed YAML
  structs in `internal/config`); unknown keys fail closed.
- Scanner stdout/stderr captured with byte caps (32 MiB / 4 MiB); stderr
  passes through `report.Redact` before persistence or display.
- Timeouts per task via `context.WithTimeout`; parent cancellation
  propagates to children via `CommandContext`.

## Consequences

- Adapters that need file-based machine output (gitleaks/trivy `--report-path`)
  use `os.CreateTemp` paths passed as argv; the orchestrator reads the file
  back and deletes it. `sdt plan` removes the empty placeholders it creates.
