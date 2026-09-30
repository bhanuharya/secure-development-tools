#!/usr/bin/env python3
"""Per-rule precision from reviewed findings, and what to do about noisy rules.

A rule earns its place as a blocking Vulnerability by being right when a human
checks. This reads the fleet store's verdicts (true_positive / false_positive; the
rest is unreviewed or undecided) and, per rule, reports reviewed count, precision,
and a recommendation once there is enough evidence:

  precision >= 0.8                -> keep (or promote a hotspot to Vulnerability)
  0.4 <= precision < 0.8          -> demote to Security Hotspot (metadata sonar.type: hotspot)
  precision < 0.4                 -> disable, or rewrite with a safe fixture for each false positive

Precision is only reported for reviewed findings; it is never extrapolated to recall.

  python3 tools/sdt_rule_precision.py --database sqlite:///fleet.db [--min-reviewed 5] [--csv out.csv]
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEEP, DEMOTE = 0.8, 0.4


def recommend(true_positive: int, false_positive: int, min_reviewed: int) -> tuple[float | None, str]:
    """(precision, recommendation) for one rule's reviewed counts."""
    reviewed = true_positive + false_positive
    if reviewed == 0:
        return None, "no reviews yet"
    precision = true_positive / reviewed
    if reviewed < min_reviewed:
        return precision, f"collect more reviews ({reviewed}/{min_reviewed})"
    if precision >= KEEP:
        return precision, "keep"
    if precision >= DEMOTE:
        return precision, "demote to Security Hotspot"
    return precision, "disable or rewrite (add a safe fixture per false positive)"


def rows_from(pairs: list[tuple[str, str, str]], min_reviewed: int) -> list[dict]:
    """(tool, rule_id, verdict) triples -> one row per rule, noisiest first."""
    counts: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for tool, rule_id, verdict in pairs:
        counts[(tool, rule_id)][verdict] += 1
    rows = []
    for (tool, rule_id), c in counts.items():
        precision, advice = recommend(c["true_positive"], c["false_positive"], min_reviewed)
        rows.append({"tool": tool, "rule": rule_id, "findings": sum(c.values()),
                     "true_positive": c["true_positive"], "false_positive": c["false_positive"],
                     "unreviewed": c["unreviewed"], "precision": "" if precision is None else f"{precision:.2f}",
                     "recommendation": advice})
    rows.sort(key=lambda r: (r["precision"] == "", float(r["precision"] or 0), -r["findings"]))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Per-rule precision from fleet review verdicts.")
    ap.add_argument("--database", default=os.environ.get("SCP_DATABASE_URL", "") or "sqlite:///./sdt-fleet.db")
    ap.add_argument("--min-reviewed", type=int, default=5, help="reviews needed before recommending a change")
    ap.add_argument("--csv", type=Path, help="also write the table as CSV")
    args = ap.parse_args()
    os.environ["SCP_DATABASE_URL"] = args.database
    sys.path.insert(0, str(ROOT))
    from sqlmodel import select

    from src.api.database import Finding, Session, engine, init_db

    init_db()
    with Session(engine) as session:
        pairs = [(tool or "", rule or "", verdict or "unreviewed")
                 for tool, rule, verdict in session.exec(select(Finding.tool, Finding.rule_id, Finding.verdict)
                                                         .where(Finding.branch != "")).all()]
    rows = rows_from(pairs, args.min_reviewed)
    width = max([len(r["rule"]) for r in rows] + [4])
    print(f"{'rule'.ljust(width)}  findings  TP  FP  precision  recommendation")
    for r in rows:
        print(f"{r['rule'].ljust(width)}  {r['findings']:>8}  {r['true_positive']:>2}  {r['false_positive']:>2}  "
              f"{(r['precision'] or '-'):>9}  {r['recommendation']}")
    if args.csv:
        with args.csv.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else ["rule"])
            writer.writeheader()
            writer.writerows(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
