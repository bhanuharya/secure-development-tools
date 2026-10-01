from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from src.scanners.base import RawFinding

EVIDENCE_VERSION = 1

DEFAULT_CONTEXT_BEFORE = 4
DEFAULT_CONTEXT_AFTER = 4
MAX_CONTEXT_LINES = 25
MAX_CONTEXT_BYTES = 8 * 1024  # 8 KiB

_REDACT = "[REDACTED]"

# Likely credential values that must never survive persistence, even when a
# scanner fails to report the exact secret string. Specific vendor token
# formats first, then generic key/value assignments. Redaction errs on the
# side of over-matching: a false positive costs a snippet, a miss leaks a key.
_CREDENTIAL_PATTERNS = [
    # AWS access key ids (long-term AKIA and temporary ASIA/ABIA/ACCA prefixes)
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    # GitHub tokens (classic, fine-grained, server, refresh)
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
    # Slack tokens & webhook secrets
    re.compile(r"\bxox[bapose]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bhttps://hooks\.slack\.com/services/T[A-Za-z0-9_/+-]+"),
    # Stripe (live + test, all key classes)
    re.compile(r"\b[sprk]k_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    # OpenAI / Anthropic style
    re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"),
    # Google API key / OAuth refresh
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\b1//0[0-9A-Za-z_-]{30,}\b"),
    # GitLab PAT / trigger tokens
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    # JWTs (three base64url segments starting with the typical header)
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b"),
    # Private key blocks
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    # Bearer / Basic authorization header values
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}"),
    # Generic key/value assignment; the optional leading/trailing \w- run
    # catches composed names like aws_secret_access_key or CLIENT_TOKEN while
    # the \b anchors still stop mid-word accidents (e.g. "keyboard").
    re.compile(
        r"(?i)\b[\w-]*(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|"
        r"authorization|key)[\w-]*\s*[:=]\s*[\"']?"
        r"([A-Za-z0-9_\-./+=]{8,})"
    ),
]


def _resolve(workdir: Path, file_path: str) -> Path | None:
    if not file_path:
        return None
    p = Path(file_path)
    if not p.is_absolute():
        p = workdir / p
    try:
        resolved = p.resolve()
    except OSError:
        return None
    try:
        resolved.relative_to(workdir.resolve())
    except ValueError:
        return None  # escapes the scan workdir -> refuse to read
    return resolved


def collect_context(
    workdir: Path,
    file_path: str,
    start: int,
    end: int | None,
    before: int = DEFAULT_CONTEXT_BEFORE,
    after: int = DEFAULT_CONTEXT_AFTER,
) -> list[dict]:
    """Return bounded, numbered context lines around a finding.

    Containment-checks the resolved path inside ``workdir``, tolerates invalid
    encoding, and caps both the line count and the total byte size.
    """
    resolved = _resolve(workdir, file_path)
    if resolved is None or start is None:
        return []
    lo = max(1, start - before)
    hi = (end if end is not None else start) + after

    lines: list[dict] = []
    total_bytes = 0
    try:
        with resolved.open("rb") as fh:
            line_no = 0
            while line_no < hi:
                raw = fh.readline(MAX_CONTEXT_BYTES + 1)
                if not raw:
                    break
                line_no += 1
                truncated = len(raw) > MAX_CONTEXT_BYTES and not raw.endswith(b"\n")
                if truncated:
                    # Consume the rest of an attacker-controlled giant line in
                    # bounded chunks so it cannot be mistaken for later lines.
                    while raw and not raw.endswith(b"\n"):
                        raw = fh.readline(MAX_CONTEXT_BYTES + 1)
                    display = b"[line truncated]"
                else:
                    display = raw.rstrip(b"\r\n")
                if line_no < lo:
                    continue
                line_text = display.decode("utf-8", errors="replace")
                encoded_len = len(display) + 1
                if len(lines) >= MAX_CONTEXT_LINES or total_bytes + encoded_len > MAX_CONTEXT_BYTES:
                    break
                total_bytes += encoded_len
                lines.append(
                    {
                        "line": line_no,
                        "text": line_text,
                        "vulnerable": line_no >= start and line_no <= (end if end is not None else start),
                    }
                )
    except OSError:
        return []
    return lines


def redact_text(text: str, secrets: Iterable[str] | None = None) -> str:
    """Redact matched secret material and likely credential values."""
    out = text
    for secret in secrets or []:
        if secret and len(secret) >= 4 and secret in out:
            out = out.replace(secret, _REDACT)
    for pattern in _CREDENTIAL_PATTERNS:
        out = pattern.sub(_REDACT, out)
    return out


def _secrets_of(rf: RawFinding) -> list[str]:
    return [value for value in rf.redaction_tokens if value]


def _is_secret_finding(rf: RawFinding) -> bool:
    if rf.source_type == "secrets":
        return True
    return bool(rf.rule_id) and "secret" in rf.rule_id.lower()


def build_evidence(rf: RawFinding, workdir: Path | None) -> dict:
    """Build a version-1 evidence document for a raw finding."""
    evidence: dict = {"version": EVIDENCE_VERSION}
    if rf.file_path:
        evidence["file"] = redact_text(rf.file_path, _secrets_of(rf))

    if rf.line_start is not None:
        evidence["start"] = {"line": rf.line_start, "column": rf.col_start}
        evidence["end"] = {
            "line": rf.line_end if rf.line_end is not None else rf.line_start,
            "column": rf.col_end,
        }

    if workdir is not None and rf.file_path and rf.line_start is not None:
        context = collect_context(workdir, rf.file_path, rf.line_start, rf.line_end)
        # Every source excerpt can contain credentials near the vulnerable line,
        # even when the finding itself is not a secret finding. Always apply
        # generic credential redaction; secret scanners additionally provide the
        # exact matched token through a transient, non-persisted field.
        secrets = _secrets_of(rf) if _is_secret_finding(rf) else []
        context = [
            {**line, "text": redact_text(line["text"], secrets)} for line in context
        ]
        evidence["context"] = context

    meta: dict = {}
    if rf.cwe:
        meta["cwe"] = rf.cwe
    confidence = _extract_confidence(rf)
    if confidence:
        meta["confidence"] = confidence
    owasp = _extract_owasp(rf)
    if owasp:
        meta["owasp"] = owasp
    references = _extract_references(rf)
    if references:
        secrets = _secrets_of(rf)
        meta["references"] = [redact_text(r, secrets) for r in references]
    evidence["rule"] = {"id": rf.rule_id, "tool": rf.tool}
    evidence.update(meta)
    return evidence


def _extract_confidence(rf: RawFinding) -> str:
    raw = rf.raw or {}
    val = raw.get("issue_confidence") or raw.get("confidence")
    if val:
        return str(val).upper()
    meta = (raw.get("extra") or {}).get("metadata") or {}
    val = meta.get("confidence")
    return str(val).upper() if val else ""


def _extract_owasp(rf: RawFinding) -> str:
    raw = rf.raw or {}
    meta = (raw.get("extra") or {}).get("metadata") or {}
    val = meta.get("owasp")
    if isinstance(val, str):
        return val
    if isinstance(val, list) and val:
        return str(val[0])
    return ""


def _extract_references(rf: RawFinding) -> list[str]:
    refs: list[str] = []
    raw = rf.raw or {}
    meta = (raw.get("extra") or {}).get("metadata") or {}
    val = meta.get("references")
    if isinstance(val, list):
        refs.extend(str(r) for r in val)
    elif isinstance(val, str) and val:
        refs.append(val)
    more_info = raw.get("more_info")
    if isinstance(more_info, str) and more_info:
        refs.append(more_info)
    if rf.remediation and rf.remediation.startswith("http"):
        refs.append(rf.remediation)
    return refs
