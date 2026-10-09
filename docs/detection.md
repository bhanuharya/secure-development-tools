# Detection: what the code rules find, and how that is measured

A scanner that reports little can be precise or blind, and the finding count does not
say which. Two yardsticks with known answers do. Both are measured before and after
every change to the rule pack.

## The two yardsticks

**Planted weaknesses** (`testdata/detection`). 38 small files in Go, Java, Node, PHP
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

| | Before wave 3 | With wave 3 (2026-10-08) | With the Java request rules (2026-10-09) |
|---|---|---|---|
| Planted weaknesses found | 11 of 34 | 33 of 34 | 37 of 38 |
| OWASP Benchmark: real weaknesses reported | 9% | 91% | 97% |
| OWASP Benchmark: safe look-alikes reported | 4% | 23% | 8% |
| OWASP Benchmark: score | 5% | 68% | 89% |

Before wave 3 a single rule fired on the whole Benchmark, and there were no PHP rules
at all. The sample that is not found is a hard-coded password in Java: in the Jenkins
pipeline SonarQube's own analyser reports those, so no rule duplicates it. The four
samples added on 2026-10-09 (LDAP, XPath, the session and the response, in Java) were
found by upstream rules before; they are in the table because first-party rules answer
for them now.

Per category:

| Category | Reported | False alarms | Score | Score with wave 3 |
|---|---|---|---|---|
| Command injection | 100% | 10% | 90% | 46% |
| Weak cipher | 100% | 0% | 100% | 100% |
| Weak hash | 69% | 0% | 69% | 69% |
| LDAP injection | 100% | 12% | 88% | 56% |
| Path traversal | 100% | 19% | 81% | 53% |
| Insecure cookie | 100% | 0% | 100% | 100% |
| SQL injection | 100% | 12% | 88% | 45% |
| Trust boundary | 100% | 19% | 81% | 22% |
| Weak random numbers | 100% | 0% | 100% | 100% |
| XPath injection | 100% | 15% | 85% | 78% |
| Cross-site scripting | 100% | 6% | 94% | 75% |

What is still wrong is two things the rules cannot see:

- **A `switch` on a character of a constant string.** Every false alarm that is left is
  one template: `"ABC".charAt(1)` picks the case that assigns a constant. The engine
  does not work out `charAt`, and the rule language can only describe the template by
  spelling out the Benchmark's own constants. That would add about 8 points and find
  nothing in real code, so it is not done.
- **A hash algorithm named in a properties file.** The 40 weak-hash cases that are
  missed read the algorithm's name from `benchmark.properties`. A rule sees one file.

Read the 89% with this in mind: 10 of its points come from one model that matters
little outside the Benchmark. A literal read back from a list after the list's first
element was removed is not request data, and the engine does not follow the shift
(`java/injection.yaml`, "A new list"). The model is right for any code of that shape,
but real code rarely has it. Without it the score is 79%.

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

## What the Java request rules changed

Wave 3's Java injection rules were upstream's. Five of them treat the whole request
object as untrusted, and two report on the shape of a call alone: any SQL text that is
not a literal, any `ProcessBuilder` argument that is not a literal. That is why half of
the Benchmark's safe look-alikes were reported.

`rules/opengrep-rules/java/injection.yaml` replaces nine of them with seven rules that
follow request data (into SQL, OS commands, file paths, LDAP, XPath, the session and
the response) and two that follow a method argument (into SQL and OS commands):

- Only what the client controls is a source: parameters, headers, cookies, the query
  string, the body and the path. A class of the application that wraps the request
  counts through its getters for those, by name.
- The engine's own flow analysis decides the rest. It already leaves out a value that
  was replaced by a constant, a branch that cannot run and a map entry that never held
  request data. The upstream rules hid that, by starting from the request object or by
  not following data at all.
- Two things are reported that upstream left out and the Benchmark counts as real:
  request data as the name of a session attribute, and as the environment of a new
  process.

Upstream's own test files for the nine rules hold 61 expectations. Every weakness
they mark is still reported, at the call that runs the query or command instead of
the line that puts its text together.

No longer reported: SQL text that is not a literal but is built from something other
than a method argument or request data, such as a field or another class's constant.
The upstream rule reported any SQL text that was not a literal.

The rules start from the servlet API. In a Spring controller, annotated parameters
reach SQL, commands, paths and HTML through the upstream Spring rules as before; for
LDAP, XPath and the session nothing follows them yet.

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

The Java request rules cost little where servlets are few. Java rules only, fastest of
three runs each, alternating:

| Repository (internal) | Java rules before | With the Java request rules | Findings |
|---|---|---|---|
| Java service A | 35.4 s | 35.9 s | the same 30 |
| Java service B | 29.0 s | 31.0 s | the same 49 |
| Java service C | 25.3 s | 26.0 s | the same 49 |

None of the three has a finding from the nine replaced rules or from the new ones:
they are Spring services, and their injection findings come from the Spring rules. On
OWASP VulnerableApp the argument rule reports both command injections of the ping
example, where the upstream rule reported one. On the Benchmark itself, where every
file is a servlet, the code scan took 70 s and 84 s in two runs, against 68 s before.

## What is not done

- **No shadow triage.** `docs/rule-precision.md` asks for one full run over real
  repositories with every hit judged before a rule may block. That has not happened
  for wave 3 or for the Java request rules.
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
