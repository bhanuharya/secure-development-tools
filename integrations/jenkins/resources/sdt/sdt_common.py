"""What pr_comment.py and publish_report.py share: how a finding and the quality gate are read and worded.

Standard library only.
"""
import json
import os
import subprocess

LEVELS = ["critical", "high", "medium", "low", "info"]
CATEGORIES = {"sast": "Code", "secret": "Secret", "secrets": "Secret", "sca": "Dependency", "dependency": "Dependency",
              "dependency-vulnerability": "Dependency", "misconfiguration": "Configuration", "iac": "Configuration"}


def log(message):
    print(f"[sdt] {message}", flush=True)


def required(what, *names):
    """The named environment variables; None, after saying which one, when one is not set."""
    try:
        return [os.environ[name] for name in names]
    except KeyError as missing:
        log(f"{what}: {missing.args[0]} is not set")
        return None


def rank(level):
    return LEVELS.index(level) if level in LEVELS else len(LEVELS)


def severity(finding):
    return str((finding.get("severity") or {}).get("canonical", "")).lower()


def kind(finding, default):
    category = str(finding.get("category", "")).lower()
    return CATEGORIES.get(category) or category.capitalize() or default


def place_of(finding):
    where = finding.get("location") or {}
    return f"{where.get('path', '')}:{where['startLine']}" if where.get("startLine") else str(where.get("path", ""))


def cell(text):
    return str(text).replace("|", "\\|").replace("`", "'").replace("\n", " ").strip()


def reported(*path):
    """The findings of a findings file, without those an exception covers; None when it cannot be read."""
    try:
        return [f for f in json.load(open(os.path.join(*path)))["findings"] or [] if not f.get("suppression")]
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def gate(out):
    """PASSED / FAILED from the SonarQube quality gate, with the lines of the conditions that failed;
    NOT COMPLETED when the scan never got there."""
    try:
        lines = open(os.path.join(out, "quality-gate.txt")).read().splitlines()
    except OSError:
        return "NOT COMPLETED", []
    status = lines[0].strip() if lines else ""
    if status == "ERROR":
        return "FAILED", [line.strip() for line in lines[1:] if line.strip()]
    return ("PASSED" if status == "OK" else "NOT COMPLETED"), []


def scanned_commit(src):
    if not src:
        return ""
    try:
        return subprocess.run(["git", "-C", src, "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                              timeout=20, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""
