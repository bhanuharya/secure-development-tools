# ADR 0003: sdt-v1 fingerprint algorithm

Date: 2026-09-04
Status: superseded on the algorithm (see note below); the decision to own fingerprinting in-tree (PRD D-04) still stands

> **Superseded algorithm:** the runtime now emits `sdt-v2` (`FingerprintVersion` in `internal/finding/finding.go`), which adds the start line as a last-resort disambiguator for true duplicates and an explicit empty trailing field. The `sdt-v1` formula below is kept for history. The drift is recorded in `docs/known-limits.md`; a correct ADR rewrite is still open. Baselines carrying a `sdt-v1` algorithm tag still fail closed.

## Context

PRD FIND-003: fingerprints must survive line movement while avoiding
accidental matches across unrelated rules or paths. Line number alone is
never the primary identity.

## Decision

`sdt-v1` = `sha256("sdt-v1" || category || adapter/rule || normalized
repo-relative path || normalized semantic context)`, NUL-separated,
context whitespace-collapsed and bounded to 512 bytes.

- Semantic context per adapter: SAST rule+message, secrets rule+path,
  vuln CVE+package@version+target, misconfig rule+target.
- Algorithm version stored in every finding and baseline
  (`fingerprint.algorithm`, `baseline.fingerprintVersion`); mismatches fail
  closed with an explicit migration error.
- Scanner-provided fingerprints are not trusted in MVP (semantics
  undocumented); may be namespaced in later.

## Consequences

- Same-file findings for one rule share identity across line moves
  (intended); distinct files/rules never collide.
- Baseline evolution fixtures must cover add/move/fix/reintroduce.
