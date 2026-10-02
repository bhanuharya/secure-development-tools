# False positives

What `sdt` does to keep findings worth reading: the secret-scanning defaults,
dependency reachability, and how a developer checks or fixes a finding they
believe is wrong. For SAST rule governance see
[`rule-precision.md`](rule-precision.md).

## Which fix for which false positive

| Situation | Fix |
|---|---|
| The pattern is wrong wherever it appears (checksums, mock datasets, generated files) | Change the rule or add an allowlist, once. See the secrets sections below. |
| The rule is sound but one hit is harmless | A reviewer marks it false positive; the decision is carried into the next scan. See the next section. |
| The finding is real but will not be fixed now | The baseline: it stops blocking without being called false. |
| A rule is mostly wrong | `tools/sdt_rule_precision.py` shows it; narrow, demote or disable the rule. |

Secrets are never excepted one by one. A leaked credential is rotated; a pattern
that is not a credential is allowlisted at the rule.

## One finding: a reviewed false positive

1. A reviewer marks the finding *Safe* or *False positive* in SonarQube.
2. `tools/sdt_sonar_sync.py` copies the decision into the fleet store, with the
   reviewer and an audit record.
3. Before the next scan, export the decisions for that repository:

   ```bash
   python3 tools/sdt_fleet_exceptions.py --database "$SCP_DATABASE_URL" \
     --repository my-repo --out .secure-dev/exceptions.yaml
   ```

   Run it in the checkout that is about to be scanned, or write the file
   elsewhere and name it in the scan configuration (`exceptions.file`).
4. `sdt scan` applies the file. The finding stays in `findings.json` marked
   `suppression`, cannot block, and is left out of the SonarQube import, the
   fleet register (which states how many were left out) and the Word report.

Each exported exception names the reviewer, repeats their reason and expires
180 days after the review (`--expire-days`), after which the finding comes back
for a fresh look. The export skips secret findings and prints how many it left
out. A finding is matched by fingerprint: if the flagged code changes, it is a
new finding and needs a new decision.

Decisions are stored per branch, but a fingerprint is the same on every branch.
The export takes the decisions of all branches by default, so a false positive
reviewed on `release/v1.0` is not asked again on `release/v1.1`. `--branch`
limits it to the decisions made on one branch.

## Secrets: what sdt changes about Gitleaks

Every secret scan runs with the sdt defaults in
[`internal/scanner/gitleaks_default.toml`](../internal/scanner/gitleaks_default.toml),
layered on top of the Gitleaks built-in rules. The file is compiled into the
binary; its digest is recorded in the scan plan.

**Not reported**

| Pattern | Why it is not a secret |
|---|---|
| `generic-api-key` in dependency lock files (`Podfile.lock`, `pubspec.lock`, `Gemfile.lock`, `composer.lock`, `Cargo.lock`, `Package.resolved`, `packages.lock.json`, `flake.lock`, `gradle.lockfile`) | Package checksums next to a package name containing `auth`, `key` or `token`. |
| A Google API key (`AIza…`) in `google-services.json`, `GoogleService-Info.plist` or `firebase_options.dart` | Firebase client configuration. The key identifies the app and ships inside it; it cannot be kept out of the build. Restrict it in the Google Cloud console (application and API restrictions) instead. |

The Firebase exception is narrow on purpose: the same key in any other file is
still reported, and any other secret in those three files is still reported.

**Added**

| Rule | Reports |
|---|---|
| `sdt-url-embedded-credentials` | A password inside a connection URL, `scheme://user:password@host`, for database, cache, queue, FTP and HTTP schemes. |
| `sdt-jdbc-url-password` | A password passed as a JDBC URL parameter, `jdbc:…?password=…`. |

Both skip placeholders (`${VAR}`, `<password>`, `{{ var }}`, `%s`), a small set
of documentation values (`password`, `changeme`, `example`, …), and local or
documentation hosts (`localhost`, `127.0.0.1`, `example.com`).

## Secrets: check a finding on your machine

Run a full scan from the repository root:

```bash
sdt scan --profile full --output /tmp/sdt-reports --cache /tmp/sdt-cache
```

Each secret finding in `/tmp/sdt-reports/findings.json` has the rule id, the
file, the line and, for a finding from history, the commit. The value itself is
redacted. To iterate on one file without the rest of the pipeline, run Gitleaks
with the exact configuration the scan used:

```bash
gitleaks detect --source . --no-git --redact \
  --config /tmp/sdt-cache/native/gitleaks-config.toml
```

Then decide which case you are in:

1. **It is a real credential.** Rotate it first, then move it to the CI secret
   store or a vault. Deleting the line does not help: a full scan reads git
   history, so the finding stays until the credential is rotated and the finding
   is recorded as accepted in the baseline.
2. **It is not a credential, and the pattern is specific to your repository**
   (mock datasets, generated test vectors). Add a `.gitleaks.toml` at the
   repository root:

   ```toml
   [extend]
   useDefault = true

   [allowlist]
   description = "mock dataset, no real credentials"
   paths = ['''(?:^|/)src/mock/''']
   ```

   The sdt defaults keep running on top of it. Two things to know:
   - Start paths with `(?:^|/)`, not `^`. Paths are absolute in a current-tree
     scan and relative in a history scan.
   - Use the global `[allowlist]` shown above. An allowlist that uses
     `targetRules` in the repository file is dropped by Gitleaks 8.30 when
     another configuration extends it.
3. **It is not a credential, and any repository would hit it.** Propose a
   change to the sdt defaults (next section).

An inline `gitleaks:allow` comment only silences the commit that adds it. A
full-history scan still reports the earlier commits, so prefer a path allowlist.

To replace the sdt defaults entirely, set `scanners.gitleaks.config` in the
scan configuration or the `GITLEAKS_CONFIG` environment variable.

## Secrets: change the defaults

1. Edit `internal/scanner/gitleaks_default.toml`. Keep an allowlist as narrow as
   the evidence: name the rule (`targetRules`), the file, and where possible the
   value shape.
2. Add the case to `TestGitleaksDefaultsCutNoiseAndKeepLeaks` in
   `internal/scanner/gitleaks_config_test.go`: one file that must stop being
   reported, and next to it one that must still be reported. Build values with
   `fakeSecret`, never paste a credential-shaped literal.
3. Run the tests. They execute the real Gitleaks binary and are skipped when it
   is not installed, so check the output says `PASS`, not `SKIP`:

   ```bash
   go test ./internal/scanner -run Gitleaks -v
   ```

4. Rebuild (`go build -o sdt ./cmd/sdt`) and rescan a repository that showed the
   false positive. Compare the secret findings per rule before and after; the
   only differences should be the ones you intended.

## Dependencies: reachability

Every dependency finding carries a `reachability` state, with a reason:

| State | Meaning |
|---|---|
| `reachable` | First-party source imports the package, or imports a package that depends on it (the reason names which). |
| `unreachable` | Nothing imports it and, for a transitive dependency, nothing imports any package that pulls it in. |
| `unknown` | It cannot be decided, so it is treated as a risk. |

A transitive dependency is never imported by name, so a missing import proves
nothing about it. It is decided from the lock file's dependency graph:

- **npm**: `package-lock.json`, any `lockfileVersion` (version 1 also needs the
  `package.json` next to it). `yarn.lock` and `pnpm-lock.yaml` have no graph
  `sdt` reads; packages that are not imported are `unknown` there.
  A package also counts as used when a `package.json` script runs it (a
  framework or build tool) or when source or configuration names it as a
  string (a module, plugin or preset). Imports in `.vue`, `.svelte` and
  `.astro` files are read.
- **Go**: a direct requirement that nothing imports is `unreachable`. A module
  marked `// indirect` in `go.mod` is `unknown`.
- **Python**: a package that nothing imports is `unreachable` only when a
  manifest next to the lock file declares it as a direct dependency
  (`pyproject.toml`, `setup.cfg`, `setup.py`, `Pipfile`, `requirements.in`). A
  package that appears only in `requirements.txt` may be transitive, so it is
  `unknown`.
- Other ecosystems are `unknown`.

Expect most findings to stay `reachable`: an imported framework pulls in most
of the tree. `unreachable` mainly identifies build and test tooling that no
source file imports. Such a tool still runs on developer machines and in CI, so
an unreachable finding is lower priority, not a non-issue.

Reachability does not change the verdict unless the policy asks for it: the
built-in policy fails on every new critical dependency. To block only what is
not proven unreachable and warn on the rest, opt in with these two rules (rules
in a configuration file replace the built-in ones, so keep the secret, SAST and
IaC rules you rely on):

```yaml
policy:
  defaultAction: report
  rules:
    - id: block-new-critical-dependencies
      match:
        categories: [dependency-vulnerability, image-vulnerability]
        severities: [critical]
        baselineStates: [new, unknown]
        reachable: [reachable, unknown]
      action: fail
    - id: warn-unreachable-critical-dependencies
      match:
        categories: [dependency-vulnerability, image-vulnerability]
        severities: [critical]
        baselineStates: [new, unknown]
        reachable: [unreachable]
      action: warn
```

A rule that lists only `reachable` skips `unknown` findings, so list both. Try
the rules on your own repositories first and read what becomes a warning: a
package used in a way the analysis does not see would be demoted wrongly.

To check a finding, read its `reachability.reason` and `reachability.evidence`
(the importing file) in `findings.json`. If a package is reported `unreachable`
but is used, for example loaded by name from a configuration file, that is a
bug in the analysis: report it with the lock file entry rather than working
around it.
