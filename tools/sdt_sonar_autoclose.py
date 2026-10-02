#!/usr/bin/env python3
"""Mark the clearest false positives Safe in SonarQube, with the evidence as the comment.

Off unless asked for (SDT_AI_AUTOCLOSE=1 in the pipeline). It acts on the advisory review
(triage.json from sdt_triage_codex.py --confirm) and closes a security hotspot only when all
of these hold:

  * the review says false positive with high confidence and names the line that makes it so;
  * a second, sceptical review of the same code also says false positive;
  * SonarQube rates the hotspot's review priority Low or Medium (High is left for a person);
  * exactly one undecided hotspot matches the rule, file and line.

Vulnerabilities and other issues are never touched. Every hotspot it closes carries a comment
with the model, the evidence and what to confirm, and can be reopened in SonarQube; a person's
decision is never changed.

  SONAR_TOKEN=... python3 tools/sdt_sonar_autoclose.py --sonar-url http://localhost:9000 \\
      --project-key KEY --branch main --triage out/triage.json [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sdt_sonar_carry import Sonar, _path  # noqa: E402  (same SonarQube client)

AUTO_PRIORITIES = ("LOW", "MEDIUM")
NAMES_A_LINE = re.compile(r"\blines?\s+\d+", re.IGNORECASE)
MAX_COMMENT = 900


def closable(results: list[dict], hotspots: list[dict]) -> tuple[list[dict], Counter]:
    """Hotspots to mark Safe (with their review) and why the others were left for a person."""
    left: Counter = Counter()
    reviews: dict[tuple, list[dict]] = {}
    for r in results:
        reviews.setdefault((r.get("rule"), r.get("path"), r.get("line")), []).append(r)
    open_at: dict[tuple, list[dict]] = {}
    for h in hotspots:
        open_at.setdefault((h.get("ruleKey"), _path(h.get("component", "")), h.get("line")), []).append(h)
    closes = []
    for where, found in sorted(open_at.items(), key=lambda kv: (str(kv[0][1]), kv[0][2] or 0, str(kv[0][0]))):
        answers = reviews.get(where, [])
        if not answers:
            left["not reviewed"] += len(found)
        elif len(found) != 1 or len(answers) != 1:
            left["more than one finding on the line"] += len(found)
        elif answers[0].get("verdict") != "likely_false_positive" or answers[0].get("confidence") != "high":
            left["not a high-confidence false positive"] += 1
        elif answers[0].get("second_opinion") != "likely_false_positive":
            left["second review did not agree"] += 1
        elif not NAMES_A_LINE.search(str(answers[0].get("reason") or "")):
            left["no line named as evidence"] += 1
        elif str(found[0].get("vulnerabilityProbability") or "").upper() not in AUTO_PRIORITIES:
            left["high review priority"] += 1
        else:
            closes.append({"key": found[0]["key"], "rule": where[0], "path": where[1], "line": where[2],
                           "review": answers[0]})
    return closes, left


def comment(close: dict, model: str) -> str:
    review = close["review"]
    text = (f"Marked Safe by SDT automated review ({model}; a second, sceptical review agreed). "
            f"Evidence: {review.get('reason', '')} To confirm: {review.get('check', '')} "
            f"Reopen this hotspot if you disagree.")
    return " ".join(text.split())[:MAX_COMMENT]


def main() -> int:
    ap = argparse.ArgumentParser(description="Mark clear false positives Safe in SonarQube (opt-in).")
    ap.add_argument("--sonar-url", required=True)
    ap.add_argument("--project-key", required=True)
    ap.add_argument("--branch", default="")
    ap.add_argument("--pull-request", default="")
    ap.add_argument("--triage", required=True, type=Path, help="triage.json from sdt_triage_codex.py --confirm")
    ap.add_argument("--max", type=int, default=25, help="most hotspots to close in one run")
    ap.add_argument("--dry-run", action="store_true", help="list what would be marked Safe, change nothing")
    args = ap.parse_args()
    token = os.environ.get("SONAR_TOKEN", "")
    if not token:
        print("sdt_sonar_autoclose: SONAR_TOKEN is not set", file=sys.stderr)
        return 2
    try:
        triage = json.loads(args.triage.read_text())
    except (OSError, ValueError) as exc:
        print(f"sdt_sonar_autoclose: no usable review ({exc}); nothing closed", file=sys.stderr)
        return 0
    scope = {"pullRequest": args.pull_request} if args.pull_request else ({"branch": args.branch} if args.branch else {})
    sonar = Sonar(args.sonar_url, token, args.project_key)
    try:
        hotspots = sonar.paged("/api/hotspots/search", "hotspots", projectKey=args.project_key, status="TO_REVIEW", **scope)
        closes, left = closable(triage.get("results") or [], hotspots)
        closes = closes[:max(args.max, 0)]
        for close in closes:
            if not args.dry_run:
                sonar.post("/api/hotspots/change_status", hotspot=close["key"], status="REVIEWED", resolution="SAFE",
                           comment=comment(close, str(triage.get("model") or "model")))
            print(f"  {close['path']}:{close['line']} {close['rule']} -> Safe")
    except (OSError, urllib.error.HTTPError, KeyError, ValueError) as exc:
        print(f"sdt_sonar_autoclose: SonarQube request failed: {exc}", file=sys.stderr)
        return 2
    reasons = "; ".join(f"{n} {why}" for why, n in sorted(left.items())) or "none"
    print(f"sdt_sonar_autoclose: {len(closes)} of {len(hotspots)} undecided hotspots "
          f"{'would be ' if args.dry_run else ''}marked Safe; left for a person: {reasons}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
