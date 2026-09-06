# ADR 0004: Purpose-built typed YAML policy (no Rego)

Date: 2026-09-04
Status: accepted (PRD D-06)

## Context

PRD POL-001 requires ordered declarative rules over canonical findings with
pass/warn/fail actions and no network or arbitrary code.

## Decision

Typed YAML policy (`internal/config.Policy` + `internal/policy.Evaluate`):
ordered rules, first match wins per finding, explicit `defaultAction`.
Match dimensions: categories, severities, baselineStates, fixAvailable.
No expression language, no Rego, no network.

## Consequences

- Policy evaluation is trivially deterministic and auditable; traces map
  every blocker to its rule id (`policy.trace`).
- Revisit only when company-pilot use cases demonstrably exceed match
  dimensions; that change needs a PRD version bump.
