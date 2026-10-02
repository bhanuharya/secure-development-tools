#!/usr/bin/env python3
"""Carry reviewed false positives into the next scan, as sdt exceptions.

A finding a reviewer judged false_positive (in SonarQube, copied by sdt_sonar_sync.py,
or through the fleet API) is written as one exception: its fingerprint, the reviewer as
owner, the review's reason, and an expiry so the decision is looked at again. `sdt scan`
applies the file like any other exceptions file: the finding stays in the results,
marked as suppressed, and can no longer block.

A decision is kept per branch, but a fingerprint is the same on every branch. By
default the decisions of all branches are exported, so a false positive reviewed on
one release branch is not asked again on the next; --branch narrows it to one.

Left out, and counted in the summary:
  * secret findings: a leaked credential is rotated, and a pattern that is not a
    credential is allowlisted at the rule (docs/false-positives.md), never excepted here;
  * decisions older than --expire-days: they need a fresh review.

  python3 tools/sdt_fleet_exceptions.py --database sqlite:///fleet.db --repository app \\
      --out exceptions/app.exceptions.yaml
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPIRE_DAYS = 180


def exception_id(fingerprint: str) -> str:
    return "fp-" + fingerprint.rpartition(":")[2][:16]


def exceptions_from(reviews: list[dict], expire_days: int, today: date) -> tuple[list[dict], Counter]:
    """Reviewed false positives -> exception entries (oldest first) and what was left out.

    Each review is ``{"fingerprint", "source_type", "rule", "path", "reviewer", "reason",
    "reviewed_on"}``; the newest review of a fingerprint wins.
    """
    counts: Counter = Counter({"exported": 0, "secret": 0, "expired": 0})
    latest: dict[str, dict] = {}
    for review in reviews:
        if review["source_type"] == "secrets":
            counts["secret"] += 1
            continue
        kept = latest.get(review["fingerprint"])
        if kept is None or review["reviewed_on"] > kept["reviewed_on"]:
            latest[review["fingerprint"]] = review
    entries = []
    for review in sorted(latest.values(), key=lambda r: (r["reviewed_on"], r["fingerprint"])):
        expires = review["reviewed_on"] + timedelta(days=expire_days)
        if expires <= today:
            counts["expired"] += 1
            continue
        entries.append({"id": exception_id(review["fingerprint"]), "fingerprints": [review["fingerprint"]],
                        "reason": f"false positive: {review['reason']} ({review['rule']} at {review['path']})",
                        "owner": review["reviewer"], "createdAt": review["reviewed_on"].isoformat(),
                        "expiresAt": expires.isoformat()})
    counts["exported"] = len(entries)
    return entries, counts


def write_exceptions(path: Path, entries: list[dict]) -> None:
    """A bare list in JSON, which is YAML: stdlib-only here, and what `sdt scan` parses."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries, indent=2) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Export reviewed false positives as an sdt exceptions file.")
    ap.add_argument("--database", default=os.environ.get("SCP_DATABASE_URL", "") or "sqlite:///./sdt-fleet.db")
    ap.add_argument("--repository", required=True, help="repository slug as ingested into the fleet store")
    ap.add_argument("--branch", default="", help="only decisions made on this branch (default: every branch)")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--expire-days", type=int, default=EXPIRE_DAYS,
                    help=f"days a false-positive decision stays in force (default {EXPIRE_DAYS})")
    args = ap.parse_args()
    os.environ["SCP_DATABASE_URL"] = args.database
    sys.path.insert(0, str(ROOT))
    from sqlmodel import select

    from src.api.database import Finding, FindingAuditEvent, Project, Session, engine, init_db

    init_db()
    with Session(engine) as session:
        project = session.exec(select(Project).where(Project.repo_slug == args.repository)).first()
        if project is None:
            print(f"sdt_fleet_exceptions: no fleet project {args.repository!r}; ingest a run first", file=sys.stderr)
            return 2
        reviews = []
        query = select(Finding).where(Finding.project_id == project.id, Finding.verdict == "false_positive",
                                      Finding.branch != "")
        if args.branch:
            query = query.where(Finding.branch == args.branch)
        for finding in session.exec(query).all():
            event = session.exec(select(FindingAuditEvent).where(
                FindingAuditEvent.finding_id == finding.id, FindingAuditEvent.to_verdict == "false_positive")
                .order_by(FindingAuditEvent.created_at.desc())).first()
            if event is None or not event.reviewer:
                print(f"sdt_fleet_exceptions: finding {finding.id} has no recorded reviewer; left out", file=sys.stderr)
                continue
            reviews.append({"fingerprint": finding.fingerprint, "source_type": finding.source_type,
                            "rule": finding.rule_id, "path": finding.file_path, "reviewer": event.reviewer,
                            "reason": event.reason or finding.triage_reason or "no reason recorded",
                            "reviewed_on": event.created_at.date()})
    entries, counts = exceptions_from(reviews, args.expire_days, datetime.now(timezone.utc).date())
    write_exceptions(args.out, entries)
    print(f"sdt_fleet_exceptions: {counts['exported']} exceptions written to {args.out} "
          f"(left out: {counts['secret']} secret, {counts['expired']} expired)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
