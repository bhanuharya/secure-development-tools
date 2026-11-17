#!/usr/bin/env python3
"""Compare the cost of two SDT builds on the same repositories, and check they agree.

Wall time is a poor yardstick on a shared machine: another build or an editor
doubles it. This runs `sdt scan` with each build over each repository several
times and reports the median CPU time (user plus system) and peak memory, per
scanner (from run-manifest.json) and for the whole scan: CPU of sdt and every
process it started, and sdt's own peak memory (the "(scan)" row). It also compares the findings: a change made for speed must not
change what is found, so any difference is listed and the exit code is 1.

  python3 scripts/bench_scan.py --a ~/sdt-main --b ~/sdt-branch \\
      --config examples/fleet/scan-config.yaml --runs 3 repo1 repo2 ...

--a and --b are SDT homes: a checkout with the built `sdt` next to its rules.
Results go to --out (default: a temporary directory), one folder per build,
repository and run; the summary is printed and written as summary.tsv.
"""
from __future__ import annotations

import argparse
import json
import os
import resource
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run_scan(home: Path, repo: Path, config: Path, profile: str, out: Path, cache: Path) -> dict:
    """One scan; returns wall, CPU and peak memory of the scan and of each scanner."""
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, SDT_HOME=str(home))
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    proc = subprocess.run([str(home / "sdt"), "scan", "--config", str(config), "--profile", profile, "--offline",
                           "--output", str(out), "--cache", str(cache)],
                          cwd=repo, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    wall = time.monotonic() - started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    manifest = json.loads((out / "run-manifest.json").read_text()) if (out / "run-manifest.json").is_file() else {}
    # The manifest has sdt's own peak memory; ru_maxrss of this script's children would be the
    # largest child so far, not this scan's.
    resources = manifest.get("resources") or {}
    result = {
        "exit": proc.returncode,
        "wall": wall,
        "cpu": (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime),
        "mem": resources.get("maxRssKb", 0) / 1024,
        "scanners": {t["adapter"]: {"wall": t.get("durationMs", 0) / 1000, "cpu": t.get("cpuMs", 0) / 1000,
                                    "mem": t.get("maxRssKb", 0) / 1024}
                     for t in manifest.get("tasks") or []},
    }
    if proc.returncode not in (0, 1):
        result["error"] = proc.stderr.strip().splitlines()[-1:] if proc.stderr else []
    return result


def findings_of(out: Path) -> set[tuple]:
    path = out / "findings.json"
    if not path.is_file():
        return set()
    doc = json.loads(path.read_text())
    return {(f["rule"]["id"], (f.get("location") or {}).get("path", ""), (f.get("location") or {}).get("startLine"),
             f["fingerprint"]["value"]) for f in doc.get("findings") or []}


def median(values: list[float]) -> float:
    return statistics.median(values) if values else 0.0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--a", type=Path, required=True, help="SDT home of the baseline build")
    ap.add_argument("--b", type=Path, required=True, help="SDT home of the build to compare")
    ap.add_argument("--config", type=Path, required=True, help="scan configuration both builds use")
    ap.add_argument("--profile", default="full")
    ap.add_argument("--runs", type=int, default=3, help="scans per build and repository (median is reported)")
    ap.add_argument("--out", type=Path, help="where results go (default: a temporary directory)")
    ap.add_argument("repos", nargs="+", type=Path)
    args = ap.parse_args()
    out = args.out or Path(tempfile.mkdtemp(prefix="sdt-bench-"))
    builds = {"a": args.a.resolve(), "b": args.b.resolve()}
    for name, home in builds.items():
        if not (home / "sdt").is_file():
            ap.error(f"--{name}: no built sdt in {home} (go build -o sdt ./cmd/sdt there)")

    rows, differences = [], []
    for repo in args.repos:
        repo = repo.resolve()
        samples: dict[str, list[dict]] = {"a": [], "b": []}
        found: dict[str, set] = {}
        # Interleave the builds so a change in machine load hits both alike.
        for run in range(args.runs):
            for name, home in builds.items():
                target = out / name / repo.name / str(run)
                samples[name].append(run_scan(home, repo, args.config.resolve(), args.profile, target,
                                              out / name / ".cache"))
                found.setdefault(name, findings_of(target))
        if found["a"] != found["b"]:
            differences.append((repo.name, len(found["a"] - found["b"]), len(found["b"] - found["a"])))
        adapters = sorted({s for name in samples for run in samples[name] for s in run["scanners"]})
        for part in ["(scan)"] + adapters:
            row = {"repo": repo.name, "part": part}
            for name in builds:
                runs = samples[name]
                if part == "(scan)":
                    row[f"{name}_cpu"] = median([r["cpu"] for r in runs])
                    row[f"{name}_wall"] = median([r["wall"] for r in runs])
                    row[f"{name}_mem"] = median([r["mem"] for r in runs])
                else:
                    got = [r["scanners"].get(part, {}) for r in runs]
                    row[f"{name}_cpu"] = median([g.get("cpu", 0) for g in got])
                    row[f"{name}_wall"] = median([g.get("wall", 0) for g in got])
                    row[f"{name}_mem"] = median([g.get("mem", 0) for g in got])
            rows.append(row)
            print(f"{row['repo']:28} {part:10} cpu {row['a_cpu']:7.1f} -> {row['b_cpu']:7.1f} s   "
                  f"mem {row['a_mem']:7.0f} -> {row['b_mem']:7.0f} MiB   wall {row['a_wall']:6.1f} -> {row['b_wall']:6.1f} s",
                  flush=True)

    columns = ["repo", "part", "a_cpu", "b_cpu", "a_mem", "b_mem", "a_wall", "b_wall"]
    with open(out / "summary.tsv", "w") as fh:
        fh.write("\t".join(columns) + "\n")
        for row in rows:
            fh.write("\t".join(str(round(row[c], 2)) if isinstance(row[c], float) else row[c] for c in columns) + "\n")
    scans = [r for r in rows if r["part"] == "(scan)"]
    a_cpu, b_cpu = sum(r["a_cpu"] for r in scans), sum(r["b_cpu"] for r in scans)
    print(f"\nall repositories: CPU {a_cpu:.0f} s -> {b_cpu:.0f} s"
          f" ({(b_cpu - a_cpu) / a_cpu * 100:+.0f}%)" if a_cpu else "")
    print(f"results: {out}")
    if differences:
        print("\nFINDINGS DIFFER (a build made for speed must find the same):")
        for repo, only_a, only_b in differences:
            print(f"  {repo}: {only_a} only in a, {only_b} only in b")
        return 1
    print("findings: identical in every repository")
    return 0


if __name__ == "__main__":
    sys.exit(main())
