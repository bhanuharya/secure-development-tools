# ADR 0010: Impact classes, upgrade actions and a first page of actions

Date: 2026-11-25
Status: accepted
Amends: [ADR 0009](0009-finding-priority.md)

## Context

ADR 0009 gives every finding a priority that starts from the scanner's severity and moves one step per known
fact. Developers act on P1 and mostly leave P2. On a typical Spring Boot 2.4 service that went wrong in three ways:

1. **Dependencies crowded out code.** Most P1 rows were vulnerable packages of one outdated framework stack, each
   its own row, although one framework upgrade fixes most of them.
2. **Scanner severity is not impact.** Account takeover (a signed-in user resets another user's password by
   putting that user's id in the URL) came from rules that report Medium, so it started at P3 and only the AI
   review lifted it, to P2. Routes beyond the review's per-rule cap stayed at P3.
3. **Duplicates.** Two rules flagged the same handlers, so each problem was counted and listed twice.

## Decision

1. **Impact classes for code.** Every code rule maps to an impact class and a label shown to developers
   (`tools/sdt_impact.py`):

   | Class | Labels |
   |---|---|
   | C1 Direct compromise | Account takeover, Authentication bypass, Credential exposure, Injection |
   | C2 Data or logic abuse | Data exposure, Logic abuse, Request forgery, Cross-site scripting, Weak credential storage |
   | C3 Defence in depth | Defence in depth |
   | C4 Hygiene | Hygiene |

   Sources, in order: a table of every rule of our own (a test fails when one is missing), a table of SonarQube
   rule keys and common vendored rules, a CWE table. A finding none of them covers keeps the ADR 0009
   severity start. Each entry also states its **precision** (high: a specific, verified pattern; medium: a
   construct to review) and whether it needs an attacker to reach the service.
2. **Priority from the class.** Each class has a ceiling: C1 P1, C2 P2, C3 P3, C4 P4. A high-precision rule
   starts at the ceiling, a medium-precision rule one step below. The review judging a finding real raises it one
   step, never past the ceiling. The ADR 0009 lowering facts and guardrails apply after, unchanged (at most two
   steps, an unknown fact never lowers, a review opinion never lowers, exposure never lowers credentials).
3. **Impact at the source.** The BOLA rule (`scp.endpoints.bola-unscoped-object-access`) is High for
   state-changing methods and Medium for reads, and carries `metadata.impact`: account takeover when the route or
   handler names a credential or contact field (whole words), logic abuse for other writes, data exposure for
   reads. Its location spans the handler body. `credential-change-by-request-id` is High. The AI review reads
   up to 30 findings of each endpoint rule instead of 6.
4. **One problem, one action.** Findings of rules in one family (object access; open route) that overlap in one
   handler or line count once and appear as one Fix First row naming both rules. Fix First groups the open
   findings of one rule, or merged set, in one file at one priority into one action, listing its routes.
5. **Dependency upgrade actions.** Vulnerable packages are grouped into upgrades: the packages a Spring Boot
   parent or BOM manages (including a JHipster BOM) become one action, a lock file or other manifest one action,
   other Maven packages and Java archives one action per package. Each action has an effort (Migration when a
   target's major version is above the installed one, else Drop-in). **A package without a known-exploited
   advisory is capped at P2**; with one (an optional local CISA KEV catalog, `--kev` or `SDT_KEV_FILE`) in an
   imported package it starts at P1, and the usual lowering facts still apply. An action takes its most urgent
   package's priority.
6. **First page.** Level meanings: P1 fix before the next deploy, P2 fix in this release, P3 plan the fix, P4 fix
   when the code is touched. The Executive Summary opens with a summary of actions and at most five Top risks
   lines from fixed templates (no AI text), one per impact label, always including the upgrade that fixes the
   most severe packages when one is at P1 or P2. Fix First shows Priority, Impact, Action and scope, Where and
   Why; severity stays in the rule sections. Dependency upgrades get their own Fix First table.
7. **Measures.** The report state lists the open Fix First actions and the decided findings, the pipeline keeps a
   dated copy per scan, and `tools/sdt_fix_rate.py` reports the share of P1 code actions closed within 14 and 30
   days and the P1 dismissal rate.

## Consequences

- **What moves up.** Account takeover, authentication bypass, hard-coded production credentials and injection
  from high-precision rules are P1 without depending on the AI review. On one service, scanned without the AI
  review: P1 in Fix First went from 17 rows, 16 of them packages, to 6 code and secret actions; Fix First went
  from 72 P1 and P2 rows (40 shown) to 19 actions plus 7 upgrades; 87 vulnerable packages became 14 upgrade
  actions, one of them covering 30 packages.
- **What moves down.** Dependencies leave P1 unless an advisory is known to be exploited, because one upgrade is
  a planned change, not a hotfix, and most advisories are never exploited. The cost: a Critical advisory that is
  exploited but not yet on the list waits for the release. The Top risks line and the upgrade table keep the
  upgrade on the first page, and a local KEV list restores P1 where it matters. Defence-in-depth and hygiene
  findings rank by class, so a High-severity hardening hotspot is P3 at most.
- **The AI review** can confirm a medium-precision finding up to its class ceiling. It cannot put a C2 finding
  at P1, cannot lower anything, and no P1 depends on it.
- **The pull request gate changes.** State-changing BOLA findings and `credential-change-by-request-id` are now
  High at the source, so the default policy rule `block-new-high-sast` fails a scan or pull request that adds
  one. In the Jenkins pipeline that result is reported, not blocking, unless the SonarQube quality gate is
  enforced.
- **SonarQube** shows the BOLA finding's impact as an `[impact: ...]` tag at the end of the issue message, which
  the report reads back and strips; SonarQube has no other field for it.
- **Open questions.** The class table needs upkeep as rules are added (a test enforces coverage of our own
  rules, not of SonarQube's). The Spring Boot managed group list is deliberately short; a package it misses
  stays its own action. Whether the targets hold (fix rate up, P1 dismissal rate under 15%) is for
  `sdt_fix_rate.py` to show; a high dismissal rate for a class means its rules rank too high.
