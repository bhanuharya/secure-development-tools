from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

SEVERITY_COLORS = {
    "critical": colors.HexColor("#B00020"),
    "high": colors.HexColor("#E65100"),
    "medium": colors.HexColor("#C77700"),
    "low": colors.HexColor("#3B6E9B"),
    "info": colors.HexColor("#555555"),
}


def _esc(text: str) -> str:
    """Escape XML/HTML markup so project/scanner-controlled text renders
    literally inside a ReportLab ``Paragraph`` instead of being parsed as markup."""
    return _xml_escape(text if text is not None else "")


def _build_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=20, spaceAfter=6),
        "subtitle": ParagraphStyle("s", parent=base["Heading3"], textColor=colors.HexColor("#64748B")),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], spaceBefore=10, spaceAfter=6),
        "body": base["BodyText"],
        "mono_small": ParagraphStyle("m", parent=base["Code"], fontSize=8.5, textColor=colors.HexColor("#475569")),
        "code": ParagraphStyle("c", parent=base["Code"], fontSize=7.5, backColor=colors.HexColor("#F1F5F9")),
        "sev_critical": ParagraphStyle("sc", parent=base["Heading4"], textColor=SEVERITY_COLORS["critical"]),
        "sev_high": ParagraphStyle("sh", parent=base["Heading4"], textColor=SEVERITY_COLORS["high"]),
        "sev_medium": ParagraphStyle("sm", parent=base["Heading4"], textColor=SEVERITY_COLORS["medium"]),
        "sev_low": ParagraphStyle("sl", parent=base["Heading4"], textColor=SEVERITY_COLORS["low"]),
        "sev_info": ParagraphStyle("si", parent=base["Heading4"], textColor=SEVERITY_COLORS["info"]),
    }


def _sev_style(styles, severity):
    return styles.get(f"sev_{severity}", styles["body"])


class PdfReportBuilder:
    """Developer-facing PDF report. Protective tone, findings first for PRs."""

    def __init__(self, output_path: str) -> None:
        self.output_path = output_path
        self.styles = _build_styles()
        self.story: list = []

    def _doc(self) -> SimpleDocTemplate:
        return SimpleDocTemplate(
            self.output_path,
            pagesize=A4,
            title="Security Scan Report",
            rightMargin=1.5 * cm, leftMargin=1.5 * cm, topMargin=1.5 * cm, bottomMargin=1.5 * cm,
        )

    # ---------------------------------------------------------------- build
    def build_scan(self, scan, project, findings) -> None:
        self._header("Security Scan Report")
        meta = [
            ["Project", project.name],
            ["Repository", f"{project.workspace}/{project.repo_slug}"],
            ["Scan type", scan.scan_type.upper()],
            ["Scope", f"{scan.ref_type}: {scan.ref_name}"],
            ["Commit", scan.commit_sha or "-"],
            ["Engines", scan.engines or "auto"],
            ["Run date", self._fmt(scan.created_at)],
            ["Status", scan.status],
        ]
        self._meta(meta)
        self._summary(findings)
        self._findings(findings)

    def build_project(self, project, findings, pr_only: bool = False) -> None:
        self._header("Aggregate Security Report")
        self._meta([
            ["Project", project.name],
            ["Repository", f"{project.workspace}/{project.repo_slug}"],
            ["Scope", "Findings in PR-changed code only" if pr_only else "All findings"],
            ["Generated", self._fmt(datetime.now(timezone.utc))],
        ])
        self._summary(findings)
        self._findings(findings, pr_only=pr_only)

    def save(self) -> str:
        self._doc().build(self.story)
        return self.output_path

    # ---------------------------------------------------------------- parts
    def _header(self, title: str) -> None:
        self.story.append(Paragraph(title, self.styles["title"]))
        self.story.append(Paragraph("Mirae Secure SDLC - Unified SAST/DAST Control Plane", self.styles["subtitle"]))
        self.story.append(Spacer(1, 0.4 * cm))

    def _meta(self, rows: list) -> None:
        table = Table([[Paragraph(_esc(k), self.styles["mono_small"]), Paragraph(_esc(str(v)), self.styles["body"])] for k, v in rows],
                      colWidths=[3.5 * cm, 13 * cm])
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        self.story.append(table)
        self.story.append(Spacer(1, 0.5 * cm))

    def _summary(self, findings) -> None:
        counts: Counter = Counter()
        for f in findings:
            counts[f.severity] += 1
        self.story.append(Paragraph("Executive Summary", self.styles["h2"]))
        rows = [["Severity", "Count"]]
        for sev in ("critical", "high", "medium", "low", "info"):
            rows.append([sev.capitalize(), counts.get(sev, 0)])
        rows.append(["Total", sum(counts.values())])
        table = Table(rows, colWidths=[6 * cm, 3 * cm])
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -2), 0.5, colors.HexColor("#D1D5DB")),
            ("BACKGROUND", (0, 7), (-1, 7), colors.HexColor("#F8FAFC")),
            ("FONTNAME", (0, 7), (-1, 7), "Helvetica-Bold"),
        ]
        for i, sev in enumerate(("critical", "high", "medium", "low", "info"), start=1):
            style.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS[sev]))
        table.setStyle(TableStyle(style))
        self.story.append(table)
        self.story.append(Spacer(1, 0.4 * cm))

    def _findings(self, findings, pr_only: bool = False) -> None:
        pr = [f for f in findings if f.in_pr_diff]
        pre = [f for f in findings if not f.in_pr_diff]

        def emit(title: str, items: list) -> None:
            self.story.append(Paragraph(title, self.styles["h2"]))
            if not items:
                self.story.append(Paragraph("No findings in this set.", self.styles["body"]))
            for f in items:
                self.story.append(self._finding_block(f))
            self.story.append(Spacer(1, 0.5 * cm))

        if pr_only:
            emit("Findings in Pull Request Changed Code", pr)
        elif pr:
            emit("Findings in Your Changed Code (this PR)", pr)
            emit("Pre-existing Findings in This Repository", pre)
        else:
            emit("Findings", findings)

    def _finding_block(self, f):
        color = SEVERITY_COLORS.get(f.severity, colors.HexColor("#555555"))
        loc = f.file_path or "-"
        if f.line_start:
            loc = f"{loc}:{f.line_start}"
        header = f"{f.severity.upper()} | {f.tool} | {f.rule_id}"
        if f.cwe:
            header += f" | {f.cwe}"
        cells = [
            Paragraph(_esc(header), _sev_style(self.styles, f.severity)),
            Paragraph(_esc(f"Location: {loc}"), self.styles["mono_small"]),
            Paragraph(_esc((f.description or "-").strip()), self.styles["body"]),
        ]
        if f.snippet:
            cells.append(Preformatted(f.snippet[:1200], self.styles["code"]))
        if f.remediation:
            cells.append(Paragraph(f"<b>Remediation:</b> {_esc(f.remediation.strip())}", self.styles["body"]))
        table = Table([[c] for c in cells], colWidths=[16 * cm])
        table.setStyle(TableStyle([
            ("LINEBEFORE", (0, 0), (0, -1), 4, color),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        return table

    @staticmethod
    def _fmt(dt) -> str:
        if not dt:
            return "-"
        return dt.strftime("%Y-%m-%d %H:%M UTC")
