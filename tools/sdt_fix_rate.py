#!/usr/bin/env python3
"""Fix-rate measures from the scan history the pipeline keeps (ADR 0010, PLAN D9).

For each repository and branch, and overall:

  * P1 code actions first reported in the window, and the share closed within 14 and within 30
    days. An action is closed at the first later scan that no longer lists it in Fix First (fixed,
    or decided in SonarQube). A share counts only the actions that could have reached that age by
    the last scan: an action first reported 5 days before the last scan is not yet a 14-day miss.
  * The P1 dismissal rate: of the P1 code findings seen in the window (open, or decided in
    SonarQube), the share whose last known decision is Safe, False positive or Accepted.
  * The median number of Fix First code and secret rows per scan.

Input: the history directory (SDT_HISTORY_DIR, kept by integrations/jenkins/resources/sdt/reports.sh):
<history>/<repository>/<branch>/states/<UTC time>.json, one report state per scan
(tools/sdt_to_docx.py --state-out). States written before this measure existed carry no "actions"
and are skipped. An action's identity is its key (sdt_to_docx.action_key): what it is about and
where, not its priority or line numbers.

Usage: sdt_fix_rate.py --history DIR [--since YYYY-MM-DD] [--out report.md]
       (--out also writes report.json next to it; without --out the Markdown goes to stdout)

Standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

WINDOWS = (14, 30)
DISMISSED = ("Safe", "False positive", "Accepted")
FIX_FIRST_KINDS = ("code", "secret")
TARGET_DISMISSAL = 0.15


@dataclass
class Scan:
    when: datetime
    actions: list[dict]
    decided: list[dict]

    @property
    def day(self) -> date:
        return self.when.date()


@dataclass
class Measures:
    repository: str
    branch: str
    scans: int = 0
    skipped: int = 0  # states without the fields this measure needs
    first_scan: str = ""
    last_scan: str = ""
    reported: int = 0
    closed: dict[int, int] = field(default_factory=lambda: {n: 0 for n in WINDOWS})
    eligible: dict[int, int] = field(default_factory=lambda: {n: 0 for n in WINDOWS})
    p1_findings: int = 0
    dismissed: int = 0
    rows: list[int] = field(default_factory=list)  # Fix First code and secret rows per scan

    def as_dict(self) -> dict:
        return {
            "repository": self.repository, "branch": self.branch, "scans": self.scans,
            "scansWithoutActions": self.skipped, "firstScan": self.first_scan, "lastScan": self.last_scan,
            "p1Actions": {"reported": self.reported,
                          **{f"closedWithin{n}": self.closed[n] for n in WINDOWS},
                          **{f"eligible{n}": self.eligible[n] for n in WINDOWS}},
            "p1Findings": {"total": self.p1_findings, "dismissed": self.dismissed},
            "fixFirstRows": {"median": _median(self.rows), "scans": len(self.rows)},
        }


def _median(values: list[int]) -> float | None:
    return float(statistics.median(values)) if values else None


def _when(state: dict, path: Path) -> datetime | None:
    raw = str(state.get("generatedAt") or "")
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        try:
            when = datetime.strptime(path.stem, "%Y%m%dT%H%M%SZ")
        except ValueError:
            return None
    return when if when.tzinfo is None else when.astimezone(timezone.utc).replace(tzinfo=None)  # compare in UTC


def load_series(directory: Path) -> tuple[list[Scan], int]:
    """The scans of one repository branch, oldest first, and how many states had no action data."""
    files = sorted((directory / "states").glob("*.json")) if (directory / "states").is_dir() else []
    latest = directory / "report-state.json"
    if latest.is_file():
        files.append(latest)
    scans: dict[datetime, Scan] = {}
    skipped = 0
    for path in files:
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            skipped += 1
            continue
        when = _when(state, path) if isinstance(state, dict) else None
        if when is None or when in scans:
            continue  # unreadable, or the latest state again (it is also the newest dated copy)
        if not isinstance(state.get("actions"), list):
            skipped += 1
            continue
        scans[when] = Scan(when, [a for a in state["actions"] if isinstance(a, dict)],
                           [d for d in state.get("decided") or [] if isinstance(d, dict)])
    return [scans[k] for k in sorted(scans)], skipped


def measure(repository: str, branch: str, scans: list[Scan], skipped: int, since: date | None) -> Measures:
    m = Measures(repository, branch, skipped=skipped)
    in_window = [s for s in scans if since is None or s.day >= since]
    m.scans = len(in_window)
    if not in_window:
        return m
    m.first_scan, m.last_scan = in_window[0].day.isoformat(), in_window[-1].day.isoformat()
    last_day = scans[-1].day

    # P1 code actions first reported in the window, and when each was first missing afterwards.
    first_p1: dict[str, int] = {}
    for i, scan in enumerate(scans):
        for a in scan.actions:
            if a.get("kind") == "code" and a.get("level") == "P1" and a.get("key"):
                first_p1.setdefault(a["key"], i)
    for key, i in first_p1.items():
        start = scans[i].day
        if since is not None and start < since:
            continue
        m.reported += 1
        closed_day = next((s.day for s in scans[i + 1:]
                           if key not in {a.get("key") for a in s.actions if a.get("kind") == "code"}), None)
        age = (closed_day - start).days if closed_day else None
        for n in WINDOWS:
            if age is not None and age <= n:
                m.closed[n] += 1
                m.eligible[n] += 1
            elif (last_day - start).days >= n:
                m.eligible[n] += 1

    # P1 code findings seen in the window and their last known state there.
    last_state: dict[str, str] = {}
    for scan in in_window:
        for a in scan.actions:
            if a.get("kind") == "code" and a.get("level") == "P1":
                for finding in a.get("findings") or []:
                    last_state[finding] = "Open"
        for d in scan.decided:
            if d.get("level") == "P1" and d.get("finding"):
                last_state[d["finding"]] = str(d.get("status") or "")
    m.p1_findings = len(last_state)
    m.dismissed = sum(1 for status in last_state.values() if status in DISMISSED)
    m.rows = [sum(1 for a in s.actions if a.get("kind") in FIX_FIRST_KINDS) for s in in_window]
    return m


def discover(history: Path) -> list[tuple[str, str, Path]]:
    """(repository, branch, directory) for every branch directory under the history root."""
    found = []
    for directory in sorted(p for p in history.rglob("*") if p.is_dir()):
        if directory.name == "states":
            continue
        if (directory / "report-state.json").is_file() or (directory / "states").is_dir():
            rel = directory.relative_to(history)
            repository = str(rel.parent).replace(os.sep, "/") if str(rel.parent) != "." else rel.name
            found.append((repository, directory.name, directory))
    return found


def overall(rows: list[Measures]) -> Measures:
    total = Measures("All repositories", "")
    for r in rows:
        total.scans += r.scans
        total.skipped += r.skipped
        total.reported += r.reported
        total.p1_findings += r.p1_findings
        total.dismissed += r.dismissed
        total.rows += r.rows
        for n in WINDOWS:
            total.closed[n] += r.closed[n]
            total.eligible[n] += r.eligible[n]
    days = sorted(d for r in rows for d in (r.first_scan, r.last_scan) if d)
    total.first_scan, total.last_scan = (days[0], days[-1]) if days else ("", "")
    return total


def _share(part: int, whole: int) -> str:
    return f"{part}/{whole} ({round(100 * part / whole)}%)" if whole else "-"


def markdown(rows: list[Measures], total: Measures, since: date | None) -> str:
    scope = f"since {since.isoformat()}" if since else "all kept scans"
    lines = [
        "# Fix rate",
        "",
        f"Scope: {scope}. P1 code actions are Fix First rows at P1 (fix before the next deploy); an action "
        "is closed at the first later scan that no longer lists it. A share counts only actions old enough "
        "to have reached that age by the last scan. Dismissal rate: P1 code findings whose last known "
        f"SonarQube decision is {', '.join(DISMISSED)}. Targets: fix rate up, dismissal rate under "
        f"{round(100 * TARGET_DISMISSAL)}%.",
        "",
        "| Repository | Branch | Scans | P1 actions reported | Closed within 14 days | Closed within 30 days "
        "| P1 dismissal rate | Median Fix First rows |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in [*rows, total]:
        median = _median(r.rows)
        lines.append(f"| {r.repository} | {r.branch or '-'} | {r.scans} | {r.reported} | "
                     f"{_share(r.closed[14], r.eligible[14])} | {_share(r.closed[30], r.eligible[30])} | "
                     f"{_share(r.dismissed, r.p1_findings)} | {'-' if median is None else f'{median:g}'} |")
    skipped = sum(r.skipped for r in rows)
    if skipped:
        lines += ["", f"{skipped} older report states carry no action data and were left out."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--history", type=Path, default=Path(os.environ["SDT_HISTORY_DIR"])
                    if os.environ.get("SDT_HISTORY_DIR") else None,
                    help="scan history directory (default: $SDT_HISTORY_DIR)")
    ap.add_argument("--since", type=date.fromisoformat, default=None,
                    help="first day of the window, YYYY-MM-DD (default: every kept scan)")
    ap.add_argument("--out", type=Path, default=None,
                    help="Markdown report path; the JSON goes next to it with a .json suffix (default: stdout)")
    args = ap.parse_args(argv)
    if args.history is None or not args.history.is_dir():
        print("sdt_fix_rate: --history (or $SDT_HISTORY_DIR) must be a directory", file=sys.stderr)
        return 2
    rows = []
    for repository, branch, directory in discover(args.history):
        scans, skipped = load_series(directory)
        rows.append(measure(repository, branch, scans, skipped, args.since))
    total = overall(rows)
    text = markdown(rows, total, args.since)
    doc = {"since": args.since.isoformat() if args.since else None,
           "series": [r.as_dict() for r in rows], "overall": total.as_dict()}
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        args.out.with_suffix(".json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
        print(f"sdt_fix_rate: wrote {args.out} and {args.out.with_suffix('.json')}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
