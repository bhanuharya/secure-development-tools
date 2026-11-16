# Detection: what the code rules find, and how that is measured

A scanner that reports little can be precise or blind, and the finding count does not
say which. Two yardsticks with known answers do. Both are measured before and after
every change to the rule pack.

## The two yardsticks

**Planted weaknesses** (`testdata/detection`). 34 small files in Go, Java, Node, PHP
and Python, each with one well-known weakness: injection, request forgery, path
traversal, unsafe deserialisation, XML entities, weak cryptography, TLS checks switched
off, hard-coded keys. `expected.tsv` lists for each file the CWE numbers a correct
report may carry and who must find it. `go test ./internal/scanner -run
TestRulePackFindsThePlantedWeaknesses` fails when a sample the rule pack is responsible
for is not reported by a rule of the right weakness class. A sample flagged for some
other reason does not count.
CI runs it on every pull request, in the rule bundle job.

**Safe look-alikes** (`testdata/detection/java/lookalike`, `by` = `none`). Code that
resembles a weakness but is safe: a URI built only for a `Location` header, a file name
used only for a download header, PEM delimiters stripped from a key loaded at run time, a
batch helper whose values are bound. The same test fails when the rule pack reports one of
them under a listed CWE, so precision is measured next to recall: a rule change that
brings back a known false positive is caught before it ships.

**OWASP Benchmark for Java** (v1.2). 2,740 servlets, each with a weakness that is real
or a safe look-alike, and the list of which is which. The score per category is the
share of real weaknesses reported minus the share of safe ones reported:

```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava
mkdir bench && cp -r BenchmarkJava/src/main/java/org bench/ && cd bench
git init -q . && git add -A && git commit -qm benchmark
sdt scan --profile full --offline --output ../bench-out --cache ../bench-cache
scripts/owasp_benchmark_score.py ../BenchmarkJava/expectedresults-1.2.csv ../bench-out/findings.json
```

## Where it stands

| | Before wave 3 | With wave 3 (2026-10-08) | With request sources (2026-11-16) |
|---|---|---|---|
| Planted weaknesses found, of 34 | 11 | 33 | 33 |
| OWASP Benchmark: real weaknesses reported | 9% | 91% | 94% |
| OWASP Benchmark: safe look-alikes reported | 4% | 23% | 25% |
| OWASP Benchmark: score | 5% | 68% | 69% |

Before wave 3 a single rule fired on the whole Benchmark, and there were no PHP rules
at all. The 34th sample is a hard-coded password in Java: in the Jenkins pipeline
SonarQube's own analyser reports those, so no rule duplicates it.

Per category, 2026-11-16 (wave 3 alone in brackets where it differs):

| Category | Reported | False alarms | Score |
|---|---|---|---|
| Command injection | 100% | 54% | 46% |
| Weak cipher | 100% | 0% | 100% |
| Weak hash | 69% | 0% | 69% |
| LDAP injection | 100% | 44% | 56% |
| Path traversal | 98% (96%) | 46% (43%) | 53% |
| Insecure cookie | 100% | 0% | 100% |
| SQL injection | 97% | 52% | 45% |
| Trust boundary | 87% (54%) | 47% (33%) | 40% (22%) |
| Weak random numbers | 100% | 0% | 100% |
| XPath injection | 93% | 15% | 78% |
| Cross-site scripting | 89% | 14% | 75% |

The injection categories show the engine's limit. The rules see that request data
reaches a sink in the same file; they cannot tell the test cases where the data was
replaced by a constant on the way. Half of the safe look-alikes are reported there, so
these findings are for a person to review, not to block on.

## Request sources and the session (2026-11-16)

Every Benchmark miss and false alarm was sorted by its cause. What changed, because it
also holds for real code:

- **More of the request is a source.** The first-party Java taint rules (path, SQL,
  request forgery) knew `getParameter`, `getHeader` and the Spring annotations. They now
  also treat cookies (`getCookies()`, `Cookie.getValue()`, `@CookieValue`), parameter
  lists and names (`getParameterValues`, `getParameterMap`, `getParameterNames`), header
  lists and names, and `getQueryString()` as request data.
- **Request data stored in the session** (`scp.java.boundary.request-data-in-session`,
  CWE-501). The vendored rule only looks at the attribute value, and only when it is
  called on `request.getSession()` directly. The new rule reports a request value used
  as the attribute name (it can overwrite another attribute: the logged-in user, a role,
  a flag), and a request value stored through a session held in a variable, the usual
  form in real code.
- **`Paths.get` with one argument.** With `--taint-intrafile`, which every scan uses,
  OpenGrep 1.29 returns an untainted path from `Paths.get(x)` when it has one argument,
  as if it were a lookup by key. `Files.readAllBytes(Paths.get(name))` went unreported
  while the same call with two arguments was found. The path rule now carries the
  argument's taint across `Paths.get` itself. The rule tests do not run with that flag,
  so the planted sample `java/NioPathTraversal.java` covers it.
- **A constant command** given to `Runtime.getRuntime().exec("...")` is no longer
  reported as command injection.

Looked at and left as it is, because the change would not hold for real code:

- **Weak hash.** All 40 missed cases read the algorithm from `benchmark.properties`,
  and 33 safe cases do the same with a strong one. The Java code alone does not say
  which is which.
- **A helper class that reads the request** (`SeparateClassRequest.getTheParameter`)
  accounts for every missed cross-site scripting, SQL and XPath case. Data is followed
  inside one file only. Treating every object built from the request as a source would
  catch them, and also its twin method that returns a constant, used by 47 safe
  cross-site scripting cases.
- **The false alarms** come from constructs real code does not use for safety: a
  condition that is always false, a `switch` on a constant, a list or map read back at
  another index or key. Two vendored audit rules (`jdbc-sqli`,
  `command-injection-process-builder`) add 60 and 19 false alarms of their own, but they
  are the rules that find SQL or a command built from a method parameter in another
  class than the controller, the common layout of real services.

## What wave 3 added

The first two waves vendored `<language>/lang/security` without its `audit/` folders.
That is where upstream keeps the rules for SQL injection, request forgery,
deserialisation, XML entities and weak cryptography, so those classes were missing.
Wave 3 adds, from the same pinned upstream revision:

- Java: `lang/security/audit`, and the Spring rules.
- JavaScript: the Express, jsonwebtoken and node-crypto rules, and part of
  `lang/security/audit`.
- PHP (new): `lang/security` and the Laravel rules.
- Python: the Flask, Django, requests and SQLAlchemy rules.
- Go: `lang/security/audit` and the jwt-go rules.

Three first-party rules cover what no upstream rule reported on the samples: request
forgery in Java and in Node, and path traversal in Go.

## What it costs, and what was left out for that

Fifteen upstream rules are not vendored. Each was measured on real repositories; the
list with the reasons is in `scripts/vendor_semgrep_rules.sh`. Three of them decided
the cost:

- One JavaScript rule took 54% of all matching time and fired almost only inside
  committed third-party libraries.
- One rule that was already in the pack took 29% and had not produced a finding in
  any repository scanned.
- One Express rule took 90% of the time on repositories with large JavaScript
  libraries; another rule in the pack reports the same weakness.

With all candidate folders and nothing left out, the code scan of one repository went
from 96 s to 588 s, and another hit the ten-minute limit. With the selection:

| Repository (internal) | Code scan before | With wave 3 | Code findings before | With wave 3 |
|---|---|---|---|---|
| Java gateway | 6 s | 9 s | 0 | 7 |
| Django application with JavaScript libraries | 61 s | 32 s | 11 | 18 |
| Java back end with a JavaScript front end | 96 s | 123 s | 82 | 94 |
| PHP application | 104 s | 127 s | 78 | 262 |
| JavaScript application A | 102 s | 144 s | 96 | 101 |
| JavaScript application B | 124 s | 165 s | 4 | 4 |

The two JavaScript applications are averages of two alternating runs each; single runs of the same scan
differ by about 15% on the machine used. They pay about 40 s for rules that find little in them today.

The PHP application is the gap made visible: its new findings are request data echoed
into pages and SQL built from request data, in the application's own files.

## What is not done

- **No shadow triage.** `docs/rule-precision.md` asks for one full run over real
  repositories with every hit judged before a rule may block. That has not happened
  for wave 3.
- **One file at a time.** The engine follows data inside a file. A flow from a
  controller through a service to a repository class is not seen.
- **SonarQube.** The plugin reads rule folders when the server starts. Until SonarQube
  is restarted and the profiles are set up again (`install/sonar/setup-sonar.sh`),
  findings of new rules arrive as external issues.

## Adding a rule

1. Add a sample to `testdata/detection` and a line to `expected.tsv`, or change an
   existing line from `sonarqube` to `rules`. The test now fails.
2. Add the rule, with an annotated test file next to it (`ruleid:` for what it must
   report, `ok:` for what it must not).
3. `sdt rules verify`, the detection test, and the Benchmark score before and after.
4. Scan a few real repositories and read the new findings and the scan time before
   the rule ships.

A rule's `paths` filters are matched against the whole path the engine is given,
including folders above the scanned repository. An exclude such as `**/tests/**`
switches the rule off for every file when the checkout sits under a folder named
`tests`. Exclude by file name (`*.spec.*`, `test_*.py`) instead. The engine's test
mode ignores `paths`, so `sdt rules verify` does not catch this: check it with a real
scan.
