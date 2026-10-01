# ADR 0008: Fast path, supply chain evidence, safe fixes

Date: 2026-09-04
Status: accepted

## Context

Sonar parity is table stakes; the moat is workflow depth: catch issues
before commit, prove what is reachable, fix the boring ones automatically,
ship audit-grade supply-chain artifacts, and learn rules from history —
all without a server.

## Decision

1. **Staged mode** (`--staged`, `sdt init --hook`): pre-commit scans
   opengrep+gitleaks over staged files only; trivy defers to CI with a
   visible skip; required-scanner evaluation exempts only staged
   deferrals; findings unattributable to staged files are dropped and
   counted. Mode is digest input and manifest metadata. CI stays the
   authoritative gate; `SKIP_SDT=1` bypass is explicit and visible.
2. **Reachability** (`internal/reachability`, Go/Python/JS): package-level
   import analysis with a soundness contract — `unknown` on any doubt
   (dynamic imports, missing manifests, unsupported ecosystems) and
   `unknown` matches neither policy value. Policy gains the `reachable`
   match dimension.
3. **Safe autofix** (`sdt fix`, `internal/fix`): whitelisted versioned
   transforms, exact-line rewrites, per-file atomicity, syntax validation,
   quarantine file, secrets never touched, never commits.
4. **SBOM+VEX**: trivy-native CycloneDX merged across fs/image targets on
   request (`sbom` format); VEX derived from policy outcome with
   `not_affected` permanently unwired.
5. **Rule mining** (`sdt rules propose`): ranked clusters plus inert
   `.yaml.proposed` drafts with annotated TP cases from redacted evidence;
   humans finish patterns under the `docs/rule-precision.md` ladder.

## Consequences

- Five new surface areas, each independently shippable and tested; each
  degrades to diagnostics, never to silent assurance.
- Policy schema gains `reachable`; finding schema gains `reachability`;
  manifests gain `mode`. All additive and backward compatible.
