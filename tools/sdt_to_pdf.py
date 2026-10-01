#!/usr/bin/env python3
"""Offline PDF report for Go `sdt` scans (Phase 1, pipeline-ready).

Reads the deterministic `sdt` artifacts — no server, DB, or network:
  reports/findings.json       (canonical secure-dev/report/v1alpha1)
  reports/run-manifest.json   (digests, tool versions, task health)
  reports/summary.txt         (optional, echoed on cover)

Writes:
  reports/security-report.pdf (A4, secrets stay redacted — inputs already are)

Usage (local or Jenkins sidecar, after `sdt scan`):
  python3 tools/sdt_to_pdf.py --from reports/findings.json \
    --manifest reports/run-manifest.json --out reports/security-report.pdf

Env/flags beat defaults so CI reproduces local runs bit-for-bit:
  --from / --manifest / --out / --project / --profile (all optional with sane defaults).
  Exit 0 on success, 2 on invalid input (mirrors sdt exit-code style).

Pipeline notes:
  - Run AFTER `sdt scan`, even on policy_failed (reports are finalized pre-exit).
  - Archive `reports/` always: findings.json + findings.sarif + run-manifest.json + security-report.pdf.
  - Needs only `reportlab>=4.0` (already in requirements.txt).
  - Guidance/snippet safety lives in tools/sdt_knowledge.py (stdlib-only).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        Preformatted,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
except ImportError:
    print("sdt_to_pdf: reportlab not installed (pip install 'reportlab>=4.0')", file=sys.stderr)
    sys.exit(2)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#B00020"),
    "high": colors.HexColor("#E65100"),
    "medium": colors.HexColor("#C77700"),
    "low": colors.HexColor("#3B6E9B"),
    "info": colors.HexColor("#555555"),
}
# Shared knowledge/helpers live in sdt_knowledge.py (single source of truth).
# Aliases keep the renderer's internal call sites unchanged.
from sdt_knowledge import (
    KNOWLEDGE_VERSION,
    SEV_ORDER,
    escape,
    knowledge_for,
    location_of,
    read_snippet,
    review_priority,
    sensitive_source,
    severity_of,
    short_rule,
)

_esc = escape
_short_rule = short_rule
_loc = location_of
_sev = severity_of
_priority = review_priority
_kb_for = knowledge_for
_snippet = read_snippet
_sensitive_source = sensitive_source


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=20, spaceAfter=6),
        "subtitle": ParagraphStyle("s", parent=base["Heading3"], textColor=colors.HexColor("#64748B")),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], spaceBefore=10, spaceAfter=6),
        "body": base["BodyText"],
        "mono": ParagraphStyle("m", parent=base["Code"], fontSize=8.5, textColor=colors.HexColor("#475569")),
        "small": ParagraphStyle("sm", parent=base["BodyText"], fontSize=8.5, textColor=colors.HexColor("#475569")),
        "sect": ParagraphStyle("sect", parent=base["Heading4"], fontSize=10, spaceBefore=6, spaceAfter=2),
        "code": ParagraphStyle("c", parent=base["Code"], fontSize=7.5, backColor=colors.HexColor("#F1F5F9")),
    }


def _meta_table(styles, rows) -> Table:
    t = Table(
        [[Paragraph(_esc(k), styles["mono"]), Paragraph(_esc(v), styles["body"])] for k, v in rows],
        colWidths=[3.8 * cm, 12.7 * cm],
    )
    t.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return t


def _count_table(styles, title_row, counts: Counter, order) -> Table:
    rows = [title_row]
    total = 0
    for key in order:
        n = int(counts.get(key, 0))
        total += n
        rows.append([str(key).capitalize(), str(n)])
    rows.append(["Total", str(total)])
    t = Table(rows, colWidths=[6 * cm, 3 * cm])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -2), 0.5, colors.HexColor("#D1D5DB")),
        ("BACKGROUND", (0, len(rows) - 1), (-1, len(rows) - 1), colors.HexColor("#F8FAFC")),
        ("FONTNAME", (0, len(rows) - 1), (-1, len(rows) - 1), "Helvetica-Bold"),
    ]
    t.setStyle(TableStyle(style))
    return t


def build_pdf(findings_doc: dict, manifest: dict, project: str, profile: str, out: Path, src_root: Path | None = None) -> None:
    styles = _styles()
    story: list = []
    findings = findings_doc.get("findings", [])
    policy = findings_doc.get("policy", {}) or {}
    blockers = {b.get("findingId") for b in policy.get("blockers", []) if isinstance(b, dict)}

    tools = ", ".join(
        f"{t.get('adapter')} {t.get('version', '')}".strip()
        for t in (manifest.get("tools", []) or [])
    ) or "-"
    status = findings_doc.get("status") or manifest.get("status") or "-"

    story.append(Paragraph("Security Scan Report (sdt)", styles["title"]))
    story.append(Paragraph("Local-first SAST + secrets + supply-chain — offline, deterministic", styles["subtitle"]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(
        _meta_table(
            styles,
            [
                ["Project", project],
                ["Profile", profile or manifest.get("profile", "-")],
                ["Status", status],
                ["Generated", findings_doc.get("generatedAt") or manifest.get("completedAt") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
                ["Run / Plan", f"{findings_doc.get('runId', manifest.get('runId', '-'))} / {str(findings_doc.get('planId', manifest.get('planId', '-')))[:19]}…"],
                ["Tools", tools],
            ],
        )
    )
    story.append(Spacer(1, 0.3 * cm))
    story.append(
        Paragraph(
            "Secrets are redacted in all evidence. AI was not used for verdicts. "
            "Blockers first; full list follows. Correlate with Sonar via fingerprints in findings.json.",
            styles["small"],
        )
    )

    sev_counts = Counter(_sev(f) for f in findings)
    cat_counts = Counter(str(f.get("category", "-")) for f in findings)
    story.append(Paragraph("Executive Summary", styles["h2"]))
    story.append(_count_table(styles, ["Severity", "Count"], sev_counts, SEV_ORDER))
    story.append(Spacer(1, 0.3 * cm))
    story.append(_count_table(styles, ["Category", "Count"], cat_counts, sorted(cat_counts)))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(f"Policy: {policy.get('status', status)} — blockers: {len(blockers)}, warnings: {policy.get('warnings', 0) if isinstance(policy.get('warnings'), int) else 0}", styles["body"]))

    def block(f: dict):
        sev = _sev(f)
        color = SEVERITY_COLORS.get(sev, colors.HexColor("#555555"))
        scanner = f.get("scanner", {}) or {}
        rule = f.get("rule", {}) or {}
        loc = f.get("location") or {}
        kb = _kb_for(f)
        rule_id = str(rule.get("id", "-"))
        header = f"{sev.upper()} | {scanner.get('adapter', '-')}/{scanner.get('tool', '')} | {_short_rule(rule_id)}"
        cwe = rule.get("cwe")
        if isinstance(cwe, list) and cwe:
            header += f" | {cwe[0]}"
        elif isinstance(cwe, str) and cwe:
            header += f" | {cwe}"
        mark = "BLOCKER " if f.get("id") in blockers else ""
        sev_style = ParagraphStyle(f"sev_{sev}_{mark}", parent=styles["body"], fontName="Helvetica-Bold", textColor=color, fontSize=10)
        catego = kb.get("label") or str(f.get("category", "-"))
        meta = f"Review priority: {_priority(sev)}  ·  Category: {catego}  ·  State: {f.get('baselineState', '-')}"
        conf = str(f.get("confidence") or "").strip()
        if conf:
            meta += f"  ·  Confidence: {conf}"
        cls = ((f.get("metadata") or {}).get("classification") or "")
        if cls and cls != "security":
            meta += f"  ·  Classification: {cls} (not a security weakness)"
        cells = [
            Paragraph(_esc(mark + header), sev_style),
            Paragraph(_esc(meta), styles["mono"]),
            Paragraph(_esc(f"Where: {_loc(f)}"), styles["mono"]),
            Paragraph(f"<b>What's the risk?</b> {_esc((f.get('message') or '-').strip()[:1200])}", styles["body"]),
        ]
        if kb.get("risk"):
            cells.append(Paragraph(f"<b>Why it matters:</b> {_esc(kb['risk'])}", styles["body"]))
        # Where — code. Key/secret findings never render source (values may be
        # live — note opengrep flags committed PEMs as SAST, not secret);
        # their redacted evidence + rotation guidance carry the section.
        if _sensitive_source(f):
            ev = (f.get("evidence") or {}).get("text") if isinstance(f.get("evidence"), dict) else None
            cells.append(
                Paragraph(
                    _esc(f"Evidence: {ev or '[redacted]'} — value withheld by design; rotate, do not inspect."),
                    styles["mono"],
                )
            )
        else:
            snip = _snippet(src_root or Path("."), str(loc.get("path") or ""), loc.get("startLine"), loc.get("endLine"))
            if snip:
                cells.append(Paragraph(_esc(f"Code (line {snip[0]}+, >> marks flagged lines):"), styles["mono"]))
                cells.append(Preformatted(_esc(snip[1]), styles["code"]))
        art = f.get("artifact") or {}
        if art.get("package"):
            cells.append(
                Paragraph(
                    _esc(f"Package: {art.get('package')} {art.get('installedVersion', '')} → fix: {art.get('fixedVersion') or '-'}"),
                    styles["mono"],
                )
            )
        if kb.get("assess"):
            cells.append(Paragraph("<b>Assess the risk — ask yourself whether:</b>", styles["sect"]))
            for q in kb["assess"]:
                cells.append(Paragraph(f"•  {_esc(q)}", styles["body"]))
        rem = (f.get("remediation") or {}).get("guidance") if isinstance(f.get("remediation"), dict) else None
        fix_text = rem or kb.get("fix") or ""
        if fix_text:
            cells.append(Paragraph(f"<b>How to fix:</b> {_esc(fix_text)}", styles["body"]))
        if kb.get("compliant"):
            cells.append(Preformatted(_esc(kb["compliant"]), styles["code"]))
        refs = list((rule.get("references") or []) if isinstance(rule.get("references"), list) else [])
        refs += [r for r in (kb.get("refs") or []) if r not in refs]
        if refs:
            cells.append(Paragraph(_esc("See: " + "  ·  ".join(str(r)[:110] for r in refs[:5])), styles["mono"]))
        fp = (f.get("fingerprint") or {}).get("value", "-")
        cells.append(Paragraph(_esc(f"Fingerprint: {fp}"), styles["mono"]))
        t = Table([[c] for c in cells], colWidths=[16.5 * cm])
        t.setStyle(
            TableStyle(
                [
                    ("LINEBEFORE", (0, 0), (0, -1), 4, color),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        return t

    ordered = sorted(findings, key=lambda f: (f.get("id") not in blockers, SEV_ORDER.index(_sev(f)) if _sev(f) in SEV_ORDER else 99, _loc(f)))
    story.append(Paragraph(f"Findings — blockers first ({len(ordered)})", styles["h2"]))
    if not ordered:
        story.append(Paragraph("No findings.", styles["body"]))
    for f in ordered:
        story.append(block(f))

    story.append(PageBreak())
    story.append(Paragraph("Appendix — reproducibility", styles["h2"]))
    story.append(
        _meta_table(
            styles,
            [
                ["runId", manifest.get("runId", findings_doc.get("runId", "-"))],
                ["planId", manifest.get("planId", findings_doc.get("planId", "-"))],
                ["planDigest", manifest.get("planDigest", "-")],
                ["contextDigest", manifest.get("contextDigest", "-")],
                ["configDigest", manifest.get("configDigest", "-")],
                ["policyDigest", manifest.get("policyDigest", "-")],
                ["Tasks", "; ".join(f"{t.get('adapter')}:{t.get('state')}" for t in (manifest.get("tasks", []) or [])) or "-"],
                ["Artifacts", "; ".join(f"{a.get('path')} {a.get('checksum', '')[:19]}…" for a in (manifest.get("artifacts", []) or [])) or "-"],
                ["Guidance", f"knowledge v{KNOWLEDGE_VERSION} (reviewed, offline — no AI)"],
                ["AI used", str((manifest.get("ai") or {}).get("used", False))],
            ],
        )
    )
    story.append(Spacer(1, 0.3 * cm))
    story.append(
        Paragraph(
            "Jenkins: archive the whole reports/ dir always (even on policy_failed). "
            "Reproduce locally by copying SDT_PROFILE/SDT_BASE/SDT_HEAD from the build log. "
            "Trivy offline: TRIVY_OFFLINE_SCAN=true + TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2 avoids Maven Central 429s.",
            styles["small"],
        )
    )

    out.parent.mkdir(parents=True, exist_ok=True)
    SimpleDocTemplate(
        str(out),
        pagesize=A4,
        title="Security Scan Report (sdt)",
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    ).build(story)


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline sdt findings.json -> PDF (no server, deterministic).")
    ap.add_argument("--from", dest="src", default="reports/findings.json", help="canonical findings.json path")
    ap.add_argument("--manifest", default="reports/run-manifest.json", help="run-manifest.json path (optional)")
    ap.add_argument("--out", default="reports/security-report.pdf", help="output PDF path")
    ap.add_argument("--project", default="", help="project label for cover (default: CWD name)")
    ap.add_argument("--profile", default="", help="profile label for cover (default: manifest profile)")
    ap.add_argument("--src-root", default=".", help="source tree for Where-code snippets (default: CWD; secrets never render source)")
    args = ap.parse_args()

    src = Path(args.src)
    if not src.is_file():
        print(f"sdt_to_pdf: findings not found: {src}", file=sys.stderr)
        return 2
    try:
        findings_doc = json.loads(src.read_text())
    except (OSError, ValueError) as exc:
        print(f"sdt_to_pdf: invalid findings.json: {exc}", file=sys.stderr)
        return 2
    manifest: dict = {}
    if args.manifest and Path(args.manifest).is_file():
        try:
            manifest = json.loads(Path(args.manifest).read_text())
        except ValueError as exc:
            print(f"sdt_to_pdf: invalid manifest (continuing without): {exc}", file=sys.stderr)
    project = args.project or Path.cwd().name
    profile = args.profile or str(manifest.get("profile", ""))
    try:
        build_pdf(findings_doc, manifest, project, profile, Path(args.out), Path(args.src_root))
    except Exception as exc:  # never emit a partial PDF silently
        print(f"sdt_to_pdf: build failed: {exc}", file=sys.stderr)
        return 2
    print(f"sdt_to_pdf: wrote {args.out} ({len(findings_doc.get('findings', []))} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
