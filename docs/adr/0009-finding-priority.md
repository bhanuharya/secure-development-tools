# ADR 0009: Priority from severity and what is known about the service

Date: 2026-11-03
Status: accepted

## Context

The SAST report ranked findings by scanner severity, plus import reachability for packages. Severity says how bad
a weakness is in general. It does not say how soon this repository has to act on it: a SQL injection in a batch
job on an internal network ranks the same as one in a public API, and a Critical advisory in a package only the
build uses ranks the same as one in the request path.

The opposite mistake is worse. A service someone believes is internal can be reachable from the internet, and a
secret does not need the service at all: everyone who can read the repository has it. A priority that hides
findings on a wrong assumption would cause the incidents it is meant to prevent.

## Decision

Every finding in the report gets a priority, **P1** (act now), **P2** (fix in the current release), **P3** (plan the
fix) or **P4** (fix when the code is touched), with the reasons that set it. `tools/sdt_priority.py` holds the rules.
`tools/sdt_to_docx.py` applies them, orders every section by them, and adds a Fix First list of the open P1 and P2
findings with a Why column.

1. **Start from severity.** Critical is P1, High P2, Medium P3, Low and Info P4. Secrets start from their kind
   instead: a credential recognisable by its format (private key, cloud or service token, password in a URL) is P1,
   a generic key or token P2, a client key that ships inside an app P3.
2. **Move one step per known fact**, and record each step with its reason:

   | | Raised | Lowered |
   |---|---|---|
   | Code | the review judged it real (not at low confidence) | test, example or documentation file; internal service, for rules an attacker exploits by reaching it (injection, cross-site scripting, server-side request forgery, path traversal, deserialisation, debug and development servers); low criticality |
   | Secrets | a generic secret named as a signing key or password (JWT secret, salt, `SECRET_KEY`, password); file served to browsers; public repository | test, example or documentation file |
   | Dependencies | | not imported by any scanned source file; manifest of a test or example; internal service; low criticality |
   | Configuration | | test, example or documentation file; low criticality |

3. **Guardrails.**
   - A fact that is not known never lowers a priority. A repository whose exposure is not recorded counts as
     reachable from the internet, and the report says so and asks for it.
   - Context lowers a finding by at most two steps. Nothing leaves the report, and the severity stays next to the
     priority.
   - A review's opinion raises, never lowers. "Likely false positive" stays at its level until a reviewer records
     the decision in SonarQube, which takes the finding out of the sections.
   - The service's exposure does not lower secrets, hard-coded credentials, cryptography, certificate checks or
     cross-site request forgery. None of them needs an attacker to reach the service directly. Cross-site request
     forgery rides on an internal user's browser.
   - High business criticality cancels the internal-service step. Low criticality never lowers a credential.
4. **Facts per repository come from an inventory**, a tab-separated file outside this repository (it names
   internal services): `repository`, `exposure` (`internet`, `internal`, `none`, `unknown`), `criticality` (`high`,
   `normal`, `low`), `visibility` (`private`, `public`), `note`. `--inventory` or `SDT_INVENTORY` points at it.
   `--exposure`, `--criticality` and `--visibility` override it for one report. A value outside its list is reported
   and ignored, so a typo counts as not recorded.
5. **The calculation runs when the report is built, not in the scan engine.** Most code findings in the report are
   SonarQube's own, which the engine never sees, and the review's verdict exists only after the scan.

## Consequences

- A report for an internal service is shorter at the top. One scan of a CMS has 35 P1 and 104 P2 findings with
  the service recorded as internet-facing, and 4 and 37 with it recorded as internal; every secret stays at the top
  either way.
- Secret values are never read for this: a generic secret's name comes from the scanner's redacted match.
- The inventory has to be kept up to date. A label that goes stale hides nothing (two steps at most), but it can
  rank an exposed service too low. Reading exposure from deployment manifests (Ingress, LoadBalancer) once the
  deployment repository is scanned would remove the hand-kept list.
- Not yet used: exploitation evidence for packages (CISA KEV, EPSS), the CVSS attack vector Trivy reports, and
  whether a package is a development dependency. Until they are, every Critical package in an exposed service is
  P1. Secrets in mobile app code, which ships to every user, are not recognised as public.
- The policy gate (ADR 0004) does not match on priority yet. The Go engine would need the same rules.
