#!/usr/bin/env python3
"""Score an SDT scan of OWASP Benchmark for Java (v1.2).

The Benchmark is 2,740 small servlets, each with one weakness that is either real or a look-alike that is
safe, and a list saying which is which. Per category this prints the share of real weaknesses reported
(caught), the share of safe look-alikes reported anyway (false alarms), and their difference, which is the
Benchmark's own score: 100% is perfect, 0% is no better than guessing.

A test case counts as reported when a code finding in its file carries a CWE of the test's category.
Weak ciphers are tagged CWE-326 by the rules and CWE-327 by the Benchmark; both count for "crypto".

  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava
  mkdir bench && cp -r BenchmarkJava/src/main/java/org bench/ && cd bench
  git init -q . && git add -A && git commit -qm benchmark      # sdt wants a repository with history
  sdt scan --profile full --offline --output ../bench-out --cache ../bench-cache
  scripts/owasp_benchmark_score.py ../BenchmarkJava/expectedresults-1.2.csv ../bench-out/findings.json

Standard library only.
"""
import collections
import csv
import json
import re
import sys

CATEGORY_CWES = {"cmdi": {78, 77}, "crypto": {327, 326}, "hash": {328}, "ldapi": {90}, "pathtraver": {22, 23, 73},
                 "securecookie": {614}, "sqli": {89, 564}, "trustbound": {501}, "weakrand": {330, 338},
                 "xpathi": {643}, "xss": {79}}


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    expected = {}
    with open(sys.argv[1], newline="") as handle:
        for row in csv.reader(handle):
            if row and row[0].startswith("BenchmarkTest"):
                expected[row[0]] = (row[1], row[2].strip().lower() == "true")
    reported = collections.defaultdict(set)
    with open(sys.argv[2]) as handle:
        findings = json.load(handle)["findings"]
    for finding in findings:
        if (finding.get("scanner") or {}).get("adapter") != "opengrep":
            continue
        test = re.search(r"(BenchmarkTest\d+)\.java$", (finding.get("location") or {}).get("path", ""))
        if not test:
            continue
        for cwe in (finding.get("rule") or {}).get("cwe") or []:
            number = re.search(r"\d+", str(cwe))
            if number:
                reported[test.group(1)].add(int(number.group(0)))
    print(f"{len(expected)} test cases")
    print(f"  {'category':13} {'real':>5} {'safe':>5} {'caught':>7} {'false alarms':>13} {'score':>6}")
    rates = []
    for category in sorted(CATEGORY_CWES):
        counts = collections.Counter()
        for test, (test_category, real) in expected.items():
            if test_category == category:
                hit = bool(reported[test] & CATEGORY_CWES[category])
                counts["tp" if real and hit else "fn" if real else "fp" if hit else "tn"] += 1
        caught = counts["tp"] / max(counts["tp"] + counts["fn"], 1)
        alarms = counts["fp"] / max(counts["fp"] + counts["tn"], 1)
        rates.append((caught, alarms))
        print(f"  {category:13} {counts['tp'] + counts['fn']:5} {counts['fp'] + counts['tn']:5} {caught:7.0%} {alarms:13.0%} "
              f"{caught - alarms:6.0%}")
    caught = sum(r[0] for r in rates) / len(rates)
    alarms = sum(r[1] for r in rates) / len(rates)
    print(f"  {'average':13} {'':5} {'':5} {caught:7.0%} {alarms:13.0%} {caught - alarms:6.0%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
