# SAST rule precision policy

How a rule earns the right to fail a build. (Normative for rule changes;
see also `rules/NOTICE` and ADR-0007.)

## Promotion ladder

1. **Proposed.** A rule ships in a wave with annotated true-positive tests
   (`sdt rules verify` green). It runs in scans immediately, but policy
   treats unproven severities as warnings: only `high`/`critical` from
   established sources block, and every new rule starts under observation
   regardless of its upstream severity.
2. **Shadow.** At least one full-profile run over real repositories. Triage
   every hit: true positive, false positive, or fixture-by-design.
   Record the verdict; fix the rule or its test on mismatch.
3. **Graduated.** Blocking builds only after shadow triage shows no
   systematic false positives. Demotion is one triage report away: a rule
   with repeated confirmed false positives is narrowed, moved to warn, or
   deleted — never left blocking.

Practical defaults today: ERROR→high blocks only for established rules;
WARNING→medium never blocks; secrets always block (separate adapter).

## Triage log (Wave 1+2, 2026-09-04, own repo)

| Finding | Verdict | Action |
|---|---|---|
| 24× html-in-template-string (dashboard JS) | FP here — all interpolations go through `esc()` | Kept (legit class); warn-level, baselined |
| use-defused-xml on pdf_report.py (`xml.sax.saxutils.escape` import) | FP here — escape helper, not parsing | Kept; baseline contains; candidate for a narrower custom rule |
| insecure-hash-algorithm-md5 on fixtures/vulnapp | TP by design (vuln fixture) | Kept |
| dangerous-system-call on testdata/taint-demo | TP by design (taint fixture) | Kept |
| 0 rules dropped across 147 vendored+custom | — | — |

## Wave policy

- Vendor `lang/security` minus `audit/`; Terraform provider rules stay out
  (Trivy misconfiguration owns IaC — no duplicate ownership).
- Pin by commit, hash bundles, record license + revision in
  `rules/manifest.yaml`. Re-vendoring is a deliberate act via
  `scripts/vendor_semgrep_rules.sh`, never a floating pull.
- C/Rust packs ship on passing per-rule tests; memory-safety taint rules
  depend on `--taint-intrafile` (adapter-enforced, test-proven).
- Path-filtered rules without upstream tests (gradle, shai-hulud signature)
  stay visible as "untested" in `sdt rules verify` until gap-fill tests land.

## Mined rules

`sdt rules propose --from reports/` ranks repeat-offender clusters and
drafts inert `.yaml.proposed` skeletons with annotated TP cases from
redacted evidence. Promotion path: fill `patterns:`, rename to `.yaml`
under the owning language dir, green `sdt rules verify`, one shadow run,
then the ladder above. Mined rules start at LOW confidence and warn-only
until triage graduates them — same as any new rule.
