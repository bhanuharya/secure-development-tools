from __future__ import annotations

import re
from dataclasses import dataclass, field

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@.*$")


@dataclass
class DiffRange:
    start: int
    end: int

    def contains(self, line: int | None) -> bool:
        if line is None:
            return False
        return self.start <= line <= self.end


@dataclass
class ParsedDiff:
    files: dict[str, list[DiffRange]] = field(default_factory=dict)
    """map of new-file path -> list of added/context line ranges in the new file"""

    def is_line_changed(self, file_path: str, line: int | None) -> bool:
        if line is None:
            return False
        for rng in self.files.get(file_path, []):
            if rng.contains(line):
                return True
        return False


def parse_diff(diff_text: str) -> ParsedDiff:
    """Parse a unified diff into per-file new-side line ranges.

    Ranges cover both context and added lines (a finding on a changed file's
    context lines is still relevant to the PR's scope). Ranges are coalesced
    into contiguous spans.
    """
    result = ParsedDiff()
    current_file: str | None = None
    current_ranges: list[DiffRange] = []
    new_line: int | None = None
    hunk_open = False

    def flush() -> None:
        nonlocal current_ranges, new_line, hunk_open
        if current_file and current_ranges:
            result.files[current_file] = _coalesce(current_ranges)
        current_ranges = []
        new_line = None
        hunk_open = False

    for raw in diff_text.splitlines():
        line = raw
        if line.startswith("diff --git ") or line.startswith("diff --cc "):
            flush()
            current_file = None
            continue
        if line.startswith("--- a/") or line == "--- /dev/null":
            continue
        if line.startswith("+++ b/"):
            current_file = line[6:].split("\t")[0].strip()
            continue
        if line.startswith("+++ "):
            current_file = line[4:].split("\t")[0].strip()
            continue
        m = HUNK_RE.match(line)
        if m:
            hunk_open = True
            new_line = int(m.group(1))
            continue
        if not hunk_open or current_file is None:
            continue
        if line.startswith("\\"):
            continue
        if line.startswith("+"):
            if new_line is not None:
                current_ranges.append(DiffRange(new_line, new_line))
                new_line += 1
        elif line.startswith("-"):
            continue
        else:  # context line ' '
            if new_line is not None:
                current_ranges.append(DiffRange(new_line, new_line))
                new_line += 1
    flush()
    return result


def _coalesce(ranges: list[DiffRange]) -> list[DiffRange]:
    if not ranges:
        return []
    sorted_ranges = sorted(ranges, key=lambda r: r.start)
    merged: list[DiffRange] = [sorted_ranges[0]]
    for r in sorted_ranges[1:]:
        last = merged[-1]
        if r.start <= last.end + 1:
            last.end = max(last.end, r.end)
        else:
            merged.append(r)
    return merged
