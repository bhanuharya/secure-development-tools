# `sdt` — one security verdict for every pull request

[![ci](https://github.com/bhanuharya/secure-development-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/bhanuharya/secure-development-tools/actions/workflows/ci.yml)

**Code weaknesses, leaked secrets, vulnerable dependencies and unprotected HTTP
routes, judged by one policy file and returned as one exit code your CI can
trust.** `sdt` runs on a developer's laptop or a CI runner. It needs no server and
no account, and sends no telemetry.

## The problem it solves

Most teams already run a code scanner, a secret scanner and a dependency scanner.
That gives them three reports, three severity scales and hundreds of findings that
nobody owns. The pull-request gate ends up either so noisy that developers learn to
ignore it, or so lax that it never blocks anything.

`sdt` replaces that with **one decision per pull request**: what this change adds,
whether it may merge, and why. The reason is short enough to paste into the review.

## What it catches

Each example below is code from the rule pack's own tests, followed by the message
the developer gets. The messages say what an attacker can do and how to fix it,
not just a rule name.

**Account takeover in a Spring controller** (`scp.java.authz.credential-change-by-request-id`, CWE-639)

```java
@PutMapping("/user-data/reset-password/{userId}")
public String resetPassword(@PathVariable(value = "userId") String userId, @RequestBody Change body) {
    users.updatePassword(userId, body.getPassword());
    return "ok";
}
```

> This endpoint changes or resets a password, PIN, e-mail or phone number for the
> account named in the URL, and nothing in the method ties that account to the
> caller: no current user, no role check. Any caller who reaches it with any valid
> token can take over any account by changing its password or e-mail. Take the
> account from the verified token, or require an administrator role, and ask for
> the old password or a one-time code before the change.

**A security chain that leaves every new controller public** (`scp.java.authz.security-chain-without-default`, CWE-862)

```java
http.csrf().disable()
    .authorizeRequests()
    .antMatchers("/api/login").permitAll()
    .antMatchers("/api/**").authenticated()
    .antMatchers("/management/**").hasAuthority("ROLE_ADMIN");
```

> This HttpSecurity chain lists path rules but has no anyRequest() rule. With
> authorizeRequests(), a request that matches no rule is let through, so each new
> controller is public until someone adds a rule for it. End the chain with
> .anyRequest().authenticated() or .anyRequest().denyAll().

**Tokens and TLS in a Flutter app** (`scp.flutter.storage.shared-preferences-secret`, CWE-312; `scp.dart.tls.disable-certificate-validation`, CWE-295)

```dart
await prefs.setString("access_token", token);
client.badCertificateCallback = (cert, host, port) => true;
```

> A credential-like value is written to SharedPreferences, which is stored
> unencrypted on the device. Use flutter_secure_storage (Keychain / Keystore)
> instead.

> A badCertificateCallback that always returns true disables TLS certificate
> validation for every host, allowing trivial man-in-the-middle interception.

**Path traversal in a Go handler** (`scp.go.path-traversal.request-controlled-path`, CWE-22)

```go
name := r.URL.Query().Get("file")
data, _ := os.ReadFile(filepath.Join("/data/reports", name))
```

> The file path is built from the HTTP request. "../" in the value reaches files
> outside the intended folder, and filepath.Join does not prevent that. Use
> filepath.Base on the name, or check that the cleaned path still starts with the
> base folder.

**The secret your project generator shipped with** (`scp.yaml.spring.known-default-secret`, CWE-1392; `scp.javascript.secrets.env-fallback-literal`, CWE-798)

```yaml
jwt:
  base64-secret: bXktc2VjcmV0LWtleS13aGljaC1zaG91bGQtYmUtY2hhbmdlZC1pbi1wcm9kdWN0aW9uLWFuZC1iZS1iYXNlNjQtZW5jb2RlZAo=
```

```js
auth: { secret: env('ADMIN_JWT_SECRET', "tobemodified") },
```

> A secret still has the value the project generator or the framework ships with.
> That value is public: anyone can sign a token with a default JWT key or get a
> token for a client whose secret is the default, without stealing anything.
> Generate a long random value, read it from an environment variable or a secret
> manager, and rotate what was signed or issued with the default.

**Actuator endpoints that hand out memory and configuration** (`scp.yaml.spring.actuator-sensitive-endpoints`, CWE-200)

```yaml
management:
  endpoints:
    web:
      base-path: /management
      exposure:
        include: ["configprops", "env", "health", "info", "threaddump", "logfile"]
```

> Actuator endpoints that reveal configuration, secrets or memory are exposed over
> HTTP (env, configprops, logfile, heapdump, threaddump, ...). env and configprops
> show environment values and the URLs of internal services, logfile shows tokens
> and personal data, heapdump and threaddump show memory. Anyone who reaches
> /management with a valid or stolen session reads them. Expose only health, info
> and prometheus, on a management port that is not routed from the internet.

Next to these, the rule tests hold `ok:` cases: code that looks similar but is
safe. A rule change that starts flagging one fails CI. The same pack covers
command and SQL injection, request forgery, unsafe deserialisation, weak
cryptography, Android and iOS manifest settings, gateway routes that expose
internal paths, and open cloud firewalls. Gitleaks adds keys and tokens in code
and history. Trivy adds dependencies with known vulnerabilities.

## Why teams pick it

**Adopt it on a ten-year-old codebase today.** Every finding gets a stable,
content-derived fingerprint. Existing debt goes into a baseline, so only what a pull
request *adds* can block it. There is no cleanup sprint before you switch the gate
on, and nothing new slips in after.

**It cannot pass by accident.** A scanner that is missing, crashes or times out
gives exit `3`, never a green build. Every run writes a manifest with engine
versions, rule digests and native exit codes, so any verdict can be audited months
later.

**It finds the bug that lives between files.** A route is often left open by
something outside its own file: a middleware that only one router group got, a
security configuration nobody updated. Pattern rules look at one file at a time and
cannot see that. `sdt` builds an inventory of every HTTP route with its *effective*
protection. It covers Spring MVC and WebFlux, Go (gin, echo, fiber, chi,
net/http), Express, NestJS, Flask and FastAPI, and flags the route that breaks
its service's own convention:

```text
POST /api/funds/transfer is public while 9 of 10 state-changing routes in this
service require authentication (most often "main.go:9 middleware AuthMiddleware
on group /api"). Anyone can call it; add the same gate or move the route under
the protected group.
```

**Detection is measured, not promised.** The rule pack is scored against known
answers ([how](docs/detection.md); Benchmark figures from 2026-10-08):

| Yardstick | Result |
|---|---|
| Planted weaknesses (34 samples: injection, request forgery, path traversal, deserialisation, XXE, weak crypto, disabled TLS checks, hard-coded keys) | 33 found |
| OWASP Benchmark for Java v1.2: real weaknesses reported | 91% |
| OWASP Benchmark: weak cipher, insecure cookie, weak random numbers | 100% found, 0 false alarms |
| Safe look-alikes that must *not* be reported | checked in CI on every pull request |

**Less noise by design.** A tainted value that reaches five sinks is one finding,
not five. A key reported by both the code rules and the secret scanner is reported
once. A secret a framework ships with is reported once, as a default to replace,
not again as a leaked key. Rules are
curated and versioned, with per-rule tests and hash checks in CI. A
precision report shows which rules your reviewers keep accepting as safe, so you
can demote or remove them.

**Findings developers actually fix.** With the Jenkins integration:

- Each Bitbucket pull request gets one comment: passed or failed, the findings it adds, and
  links to the full report. Later scans update the same comment.
- The Word report puts code first. Each finding shows its excerpt, a fixed
  advisory and a link to the exact line in the scanned commit.
- Secret values are never printed.
- An optional AI review marks each code finding "likely real", "likely false
  positive" or "needs context", with a reason that cites the code. It is advisory
  only and never changes a verdict. It remembers its answers, so unchanged code is
  never asked about twice.

**It catches problems before the commit.** `sdt hook install` checks the lines being
committed with the same rules and policy as the pull-request scan, in 3 to 4
seconds:

```console
$ git commit -m "host check"
sdt: 2 problems in the lines being committed must be fixed first

  app/settings.py:2  high  secret (github-pat)
      Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.
      Take it out before you commit. It has to be replaced only if it was pushed or shared before.
  app/tool.py:9  high  injection.subprocess-shell  (+2 more rules on this line)
      Shell execution interprets metacharacters and can enable command injection. Pass an argument list with shell=False.

Fix and commit again. To commit as it is: SKIP_SDT=1 git commit ... (the pull request scan reports the same).
```

**Mobile is first-class.** Dart and Flutter rules ship next to Go, Java, Kotlin,
JavaScript/TypeScript, Python, PHP, YAML and Terraform. Most open-source SAST
setups leave that gap open.

**Your code stays yours.**

- `sdt` itself uploads nothing: there is no service, no account and no telemetry.
- Secrets are redacted from evidence and reports, and a test plants a key to
  prove it.
- The AI review is the only feature that sends code excerpts to an outside
  service, and never secrets. It runs only where you install and sign in to the
  Codex CLI, and `SDT_AI_TRIAGE=0` turns it off.

**It scales from one repository to the whole workspace.** Fleet mode scans every
repository in a Bitbucket workspace on a schedule. It keeps history in a local
store, imports findings into SonarQube and syncs review decisions back.

## Under the hood

`sdt` runs three proven open-source engines: [OpenGrep](https://github.com/opengrep/opengrep)
for code, [Gitleaks](https://github.com/gitleaks/gitleaks) for secrets and
[Trivy](https://github.com/aquasecurity/trivy) for dependencies. To them it adds:

- more than 100 first-party rules;
- about 460 vendored Semgrep rules, pinned to one upstream revision;
- the route inventory.

Every result goes through the same steps:

1. Each engine runs as a direct process, never through a shell.
2. Its report is normalized into one finding schema, and each finding is
   fingerprinted.
3. A typed YAML policy is evaluated against your baseline.
4. The run always writes the same evidence: `findings.json`, `findings.sarif`,
   `run-manifest.json` and `summary.txt`. The default `full` and `pr` profiles
   also write `endpoints.json`, the route inventory.

| Exit | Meaning |
|---|---|
| `0` | passed |
| `1` | policy failed: something new crosses the line |
| `2` | invalid input |
| `3` | a scanner failed (never a pass) |
| `4` | inconclusive |
| `5` | internal error |

## Try it

You need git on Linux or macOS, Go 1.24.6 to build, and OpenGrep 1.29.0, Gitleaks
8.30.1 and Trivy 0.73.0 on `PATH`. To use engines installed elsewhere, set
`SDT_OPENGREP_BIN`, `SDT_GITLEAKS_BIN` and `SDT_TRIVY_BIN`. `sdt doctor` checks
each prerequisite and says what is missing.

```bash
git clone https://github.com/bhanuharya/secure-development-tools.git
cd secure-development-tools
go build -o sdt ./cmd/sdt

./sdt doctor                                  # what is installed, what is missing, and why
./sdt init --dry-run                          # preview a starter config; nothing is written
./sdt scan --profile full --output reports    # scan the whole tree
./sdt scan --profile pr --base origin/main    # gate a pull request: only what it adds
```

A `pr` scan refuses to run without a merge base instead of silently scanning
everything.

To see it block something, scan the deliberately vulnerable fixture app this
repository ships:

```console
$ SDT_RULES_PACK_DIR=$PWD/rules/opengrep-rules \
    sdt scan --profile full --config examples/sample-run/demo.secure-dev.yaml \
      --cache /tmp/sdt-cache --output /tmp/sdt-reports
sdt: status=policy_failed findings=12 (critical=3 high=3 medium=6 low=0 info=0 unknown=0) blockers=4 warnings=0
  scanner opengrep     completed
  scanner trivy-fs     completed
  BLOCK opengrep:00003 sha256:7230d1c41a92 (block-new-high-sast)
  BLOCK trivy-fs:00005 sha256:7f12a60ae478 (block-new-critical-dependencies)
  BLOCK trivy-fs:00006 sha256:fb8c3b7400ab (block-new-critical-dependencies)
  BLOCK trivy-fs:00007 sha256:0e3e057cb85d (block-new-critical-dependencies)
$ echo $?
1
```

It reports twelve findings. Four of them are new and blocking, so the exit code is
`1`. The findings are the fixture working as designed, not a claim about this
repository. The two extra flags are needed only because the demo points at a
subdirectory ([known limits](docs/known-limits.md)).

## Works where you already work

| Where | What you get |
|---|---|
| Developer machine | `sdt hook install`: a pre-commit check of the staged lines in 3 to 4 seconds ([guide](docs/local-hook.md)) |
| Any CI | One command and one exit code. Templates for GitHub, GitLab, Bitbucket, Jenkins and generic runners ([examples](examples/README.md)) |
| GitHub / GitLab code scanning | `findings.sarif` |
| Jenkins + Bitbucket + SonarQube | A shared library and scanner image: per-PR comments, the Word report, optional AI review, nightly fleet scans ([setup](integrations/jenkins/README.md)) |
| SonarQube | Findings imported as issues, plus a companion plugin for native Dart issues ([fleet guide](docs/fleet-scanning.md)) |

## Is it for you?

**Yes**, if you want one gate across code, secrets, dependencies and routes, with
the policy in a file, a baseline for existing debt and evidence attached to every
review, and you don't want to run a service to get it.

**No**, if one engine behind your current gate already gives you that. `sdt` is not
a better OpenGrep and it does not replace SonarQube's review UI. Its value is what
it adds on top: one schema, one policy, the route inventory, and a verdict that
fails closed.

## Status and honest limits

**Pre-release:** `sdt 0.1.0-dev`, schema `secure-dev/v1alpha1`. It runs in a Jenkins
pipeline that scans a Bitbucket workspace of mobile and web services. CI on every
change builds it, verifies the rule bundle, and runs an end-to-end test that the gate
still blocks the vulnerable fixture. The full list, with steps to reproduce each
item, is in [`docs/known-limits.md`](docs/known-limits.md). The ones that matter
most:

- The schema is not frozen yet. Expect breaking changes before 1.0.
- You install the engines yourself. The local build does not bundle them. The
  container image runs as non-root but does not sandbox them.
- Redaction is pattern-based. It covers evidence and scanner output, not your own
  CI logs.
- In the injection categories, about half of the safe look-alikes are reported
  too. Treat those findings as review items, not hard blocks
  ([details](docs/detection.md)).
- `fix`, `reachability`, `publish`, `explain` and the SBOM/VEX formats are
  implemented and unit-tested, but have not been used outside tests.

## Developing

```bash
go build ./... && go test ./...
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest -q
```

Machine-specific paths and tokens come from flags or environment variables, never
from tracked files.

## Documentation

- [`docs/detection.md`](docs/detection.md): what the rules find and how it is measured
- [`docs/endpoints.md`](docs/endpoints.md): the route inventory, its three findings and their limits
- [`docs/false-positives.md`](docs/false-positives.md): secret defaults, dependency reachability, checking a finding locally
- [`docs/rule-precision.md`](docs/rule-precision.md): how rules are promoted, demoted and retired
- [`docs/local-hook.md`](docs/local-hook.md): the pre-commit check
- [`docs/sast-report.md`](docs/sast-report.md): the Word report developers receive
- [`docs/fleet-scanning.md`](docs/fleet-scanning.md): scheduled workspace scans, SonarQube import, review sync
- [`docs/performance.md`](docs/performance.md): what a scan costs in CPU and memory per scanner, and how to compare two builds
- [`docs/security-posture.md`](docs/security-posture.md): what each control does and does not cover
- [`docs/known-limits.md`](docs/known-limits.md): rough edges, each with steps to reproduce it
- [`docs/adr/`](docs/adr/): design decisions, including why the runtime was rebuilt in Go
- [`integrations/jenkins/`](integrations/jenkins/README.md): the Jenkins shared library, scanner image and SonarQube setup
- [`examples/`](examples/README.md): CI templates for GitHub, GitLab, Bitbucket, Jenkins and generic runners
- [`SECURITY.md`](SECURITY.md): reporting a vulnerability
- [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and [`rules/NOTICE`](rules/NOTICE): licenses, including the vendored Semgrep rules
- [`docs/legacy-control-plane.md`](docs/legacy-control-plane.md): the superseded Python platform, kept for reference
