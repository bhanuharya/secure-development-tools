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

| | Before wave 3 | With wave 3 (2026-10-08) |
|---|---|---|
| Planted weaknesses found, of 34 | 11 | 33 |
| OWASP Benchmark: real weaknesses reported | 9% | 91% |
| OWASP Benchmark: safe look-alikes reported | 4% | 23% |
| OWASP Benchmark: score | 5% | 68% |

Before wave 3 a single rule fired on the whole Benchmark, and there were no PHP rules
at all. The 34th sample is a hard-coded password in Java: in the Jenkins pipeline
SonarQube's own analyser reports those, so no rule duplicates it.

Per category with wave 3:

| Category | Reported | False alarms | Score |
|---|---|---|---|
| Command injection | 100% | 54% | 46% |
| Weak cipher | 100% | 0% | 100% |
| Weak hash | 69% | 0% | 69% |
| LDAP injection | 100% | 44% | 56% |
| Path traversal | 96% | 43% | 53% |
| Insecure cookie | 100% | 0% | 100% |
| SQL injection | 97% | 52% | 45% |
| Trust boundary | 54% | 33% | 22% |
| Weak random numbers | 100% | 0% | 100% |
| XPath injection | 93% | 15% | 78% |
| Cross-site scripting | 89% | 14% | 75% |

The injection categories show the engine's limit. The rules see that request data
reaches a sink in the same file; they cannot tell the test cases where the data was
replaced by a constant on the way. Half of the safe look-alikes are reported there, so
these findings are for a person to review, not to block on.

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
