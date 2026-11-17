# ADR 0004: Purpose-built typed YAML policy (no Rego)

Date: 2026-09-04
Status: accepted (PRD D-06)

## Context

PRD POL-001 requires ordered declarative rules over canonical findings with
pass/warn/fail actions and no network or arbitrary code.

## Decision

Typed YAML policy (`internal/config.Policy` + `internal/policy.Evaluate`):
ordered rules, first match wins per finding, explicit `defaultAction`.
Match dimensions: categories, severities, baselineStates, fixAvailable,
reachable, confidence.
No expression language, no Rego, no network.

## Confidence

Rules may match `confidence: [high, medium, low]` next to `severity`, so a
build can fail only on certain findings while the rest keep reporting. A
finding without confidence counts as `medium`; `[medium]` therefore includes
scanners that do not label certainty, and no rule silently skips them. The
built-in policy does not match confidence, so its behaviour is unchanged.
Example: `examples/policy-block-high-confidence.yaml` blocks new high and
critical SAST findings only at `high` confidence.

## Consequences

- Policy evaluation is trivially deterministic and auditable; traces map
  every blocker to its rule id (`policy.trace`).
- Revisit only when company-pilot use cases demonstrably exceed match
  dimensions; that change needs a PRD version bump.
