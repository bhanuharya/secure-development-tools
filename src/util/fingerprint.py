from __future__ import annotations

import hashlib


def fingerprint(tool: str, rule_id: str, file_path: str, line: int | None, snippet: str = "") -> str:
    """SHA-256 dedup fingerprint over a normalized finding's identity."""
    line_s = str(line) if line is not None else "N/A"
    canonical = "|".join([tool, rule_id, file_path, line_s, (snippet or "").strip()[:200]])
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()