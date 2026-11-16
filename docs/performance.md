# Scan cost: how it is measured and how to change it

A scan runs on shared agents, often two at a time on four cores, next to
SonarQube and other builds. What it costs the agent, CPU time and memory, matters
as much as how long it takes. This page says what every scan records, how to
compare two builds, and the rules a change made for speed follows.

## What every scan records

`run-manifest.json` has, for each scanner (`tasks[]`):

| Field | Meaning |
|---|---|
| `durationMs` | Wall time. |
| `cpuMs` | CPU time, user plus system, of the scanner and every process it waited for (a launcher's engine processes included). |
| `maxRssKb` | Peak resident memory of the scanner's largest process. |

The endpoint inventory runs inside `sdt`, beside the other scanners. Its entry is the
cost of the fact engine it starts. Its own Go work is part of `sdt`'s, in `resources`.

`resources` has the whole scan:

| Field | Meaning |
|---|---|
| `cpuMs` | CPU of `sdt` and every process it started. |
| `maxRssKb` | `sdt`'s own peak memory. |
| `scannerMaxRssKb` | The largest scanner process's peak memory. |

The Jenkins integration copies the per-scanner values into `out/timings.tsv` as
`cpu:<scanner>` (seconds) and `mem:<scanner>` (MiB), next to the wall times.

**Compare CPU time and memory between builds, not wall time.** On a shared machine the same scan
took from 3 s to 12 s of wall time in consecutive runs. Its CPU time stayed
within a few percent.

## Comparing two builds

```
go build -o sdt ./cmd/sdt                                   # in each checkout
python3 scripts/bench_scan.py --a ../sdt-main --b . \
    --config examples/fleet/scan-config.yaml --runs 3 <repository> ...
```

The script scans each repository with both builds, interleaved so a change in
machine load affects both alike. It prints the median CPU time, peak memory and wall time:

- per scanner;
- for the whole scan, in the `(scan)` row.

The summary is also written to `summary.tsv`. The script then compares the findings and exits 1 if they differ.

A shallow clone needs a configuration whose profile sets `missingHistory: warn`.
Results can name the scanned repositories; keep them out of the repository.

## Rules for a change made for speed

1. **Same findings.** The benchmark must report identical findings on the
   measured repositories, or the change is described as an accuracy change too
   and its new or lost findings are explained.
2. **Measured, not argued.** The pull request shows the before and after medians
   (CPU and memory per scanner and per scan) on repositories of the kinds it
   affects, and how many runs they are medians of.
3. **One change per measurement.** Measure the change itself: the baseline is
   the commit before it, built the same way.
4. **Bounded resources.** Every engine runs with the scan's core budget
   (`SDT_SCAN_THREADS`, default up to 4) and a time limit; output is capped. A
   new engine invocation follows the same rules.

## Where the cost is today

| Step | Cost on a large Java service | Notes |
|---|---|---|
| AI review (Jenkins) | 15 to 19 model calls of about 30 s on a first scan | Four rules at a time (`SDT_CODEX_PARALLEL`); remembered verdicts make a rescan cheap. |
| Clone (Jenkins) | 80 to 150 s with full history | `SDT_CLONE_CACHE` keeps a mirror per repository. |
| SonarQube analysis and import | about 140 s | SonarQube's own analyzers and server-side processing. |
| Code scan (opengrep) | about 60 s wall | Parsing every source file is most of it. Rules are loaded for the repository's languages only. |
| Endpoint inventory | 10 to 20 s, beside the code scan | A second opengrep run over the same files with the fact rules. It costs CPU, but no wall time unless cores are short. |
| Secrets, dependencies | a few seconds each | |
