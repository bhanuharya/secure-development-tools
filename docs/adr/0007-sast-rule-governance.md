# ADR 0007: SAST rule governance (curate, pin, prove)

Date: 2026-09-04
Status: accepted

## Context

The engine (OpenGrep 1.29.0) outruns our rule pack (19 hand-written rules).
Upstream options differ sharply in license and quality: the opengrep-rules
fork is archived/research-only (rejected); semgrep-rules is Semgrep Rules
License v1.0 — internal business use permitted, competing SaaS use
prohibited — which fits a company-internal scanner. `opengrep test` only
pairs tests correctly for single-rule invocations, and `.test.yaml`
fixtures passed as `--config` fail whole runs (exit 7).

## Decision

1. Vendor curated `lang/security` subsets (audit/ excluded) pinned by
   commit with bundle hashes in `rules/manifest.yaml`; Terraform provider
   rules excluded (Trivy owns IaC).
2. Enable `--taint-intrafile` on OpenGrep (test-proven 0→1 on a genuine
   cross-function flow); keep it out of the Semgrep fallback path.
3. `sdt rules verify` = YAML/manifest enforcement (counts, per-file and
   bundle hashes) + `opengrep validate` + per-rule `opengrep test`
   (annotation-indexed shared fixtures included). Test fixtures
   (`*.test.*`, `*.fixed.*`) are excluded from scan configs and targets.
4. Rule contents feed the plan digest (`RuleChecksums`), so identical
   inputs — including rule bytes — always produce identical plans.
5. Promotion ladder per `docs/rule-precision.md`: prove, then block.

## Consequences

- 19 → 147 rules, every file validated; all but 4 rule files carry
  annotated tests, and the 4 test-less ones stay visible, never silent.
- Re-vendoring and new custom rules follow the same harness; precision is
  measured per rule, not asserted.
