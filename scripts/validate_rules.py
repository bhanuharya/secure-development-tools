#!/usr/bin/env python3
"""Fail-closed provenance and structure validation for local SAST rules."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class ValidationResult:
    rule_count: int
    errors: list[str]


def _belongs(relative: str, prefixes: list[str]) -> bool:
    return any(relative == prefix or relative.startswith(prefix.rstrip("/") + "/") for prefix in prefixes)


def validate_manifest(manifest_path: Path, rules_root: Path) -> ValidationResult:
    errors: list[str] = []
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return ValidationResult(0, [f"manifest unreadable: {exc}"])

    sources = manifest.get("sources")
    if manifest.get("version") != 1 or not isinstance(sources, list) or not sources:
        return ValidationResult(0, ["manifest must have version: 1 and a non-empty sources list"])

    source_by_id = {}
    for source in sources:
        missing = [key for key in ("id", "repository", "license", "revision", "profile", "path_prefixes", "expected_rule_count") if not source.get(key) and source.get(key) != 0]
        if missing:
            errors.append(f"source missing required fields {missing}: {source!r}")
            continue
        source_id = str(source["id"])
        if source_id in source_by_id:
            errors.append(f"duplicate source id: {source_id}")
        source_by_id[source_id] = source

    seen_ids: dict[str, str] = {}
    counts: Counter[str] = Counter()
    total = 0
    for path in sorted(rules_root.rglob("*.y*ml")):
        relative = path.relative_to(rules_root).as_posix()
        owners = [sid for sid, source in source_by_id.items() if _belongs(relative, source["path_prefixes"])]
        if len(owners) != 1:
            errors.append(f"{relative}: expected exactly one manifest owner, got {owners}")
            continue
        owner = owners[0]
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{relative}: invalid YAML: {exc}")
            continue
        rules = document.get("rules")
        if not isinstance(rules, list):
            errors.append(f"{relative}: top-level rules must be a list")
            continue
        for rule in rules:
            rule_id = rule.get("id") if isinstance(rule, dict) else None
            if not rule_id:
                errors.append(f"{relative}: rule missing id")
                continue
            if rule_id in seen_ids:
                errors.append(f"duplicate rule id {rule_id}: {seen_ids[rule_id]} and {relative}")
            else:
                seen_ids[str(rule_id)] = relative
            total += 1
            counts[owner] += 1

    for source_id, source in source_by_id.items():
        expected = int(source["expected_rule_count"])
        if counts[source_id] != expected:
            errors.append(f"source {source_id}: expected {expected} rules, found {counts[source_id]}")
        for relative, expected_hash in (source.get("hashes") or {}).items():
            path = rules_root / relative
            try:
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                errors.append(f"{relative}: cannot verify hash: {exc}")
                continue
            if actual != expected_hash:
                errors.append(f"{relative}: SHA-256 mismatch")

    return ValidationResult(total, errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=Path("rules/manifest.yaml"))
    parser.add_argument("--rules", type=Path, default=Path("rules/opengrep-rules"))
    parser.add_argument("--skip-engine-validation", action="store_true")
    args = parser.parse_args()

    result = validate_manifest(args.manifest, args.rules)
    errors = list(result.errors)
    if not args.skip_engine_validation:
        semgrep = shutil.which("semgrep")
        if not semgrep:
            errors.append("semgrep executable not found for rule syntax validation")
        else:
            proc = subprocess.run(
                [semgrep, "--validate", "--config", str(args.rules)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                errors.append(f"semgrep validation failed: {(proc.stderr or proc.stdout)[-1000:]}")

    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        return 1
    print(f"OK: {result.rule_count} rules validated with governed provenance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
