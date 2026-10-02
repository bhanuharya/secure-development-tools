#!/usr/bin/env python3
"""Offline XLSX and PDF summary from immutable SDT fleet artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import zipfile
from collections import Counter
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from sdt_to_sonar import extract_vuln_fields

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
DEP_CATEGORY = "dependency-vulnerability"
FINDING_COLUMNS = ("Repository", "Commit", "Status", "Category", "Severity", "Rule", "CWE", "Location", "Message", "Remediation", "Fingerprint", "Confidence", "Baseline", "Verdict", "Reviewer", "Review reason", "Reviewed at", "Sonar project")
COVERAGE_COLUMNS = ("Repository", "Branch", "Commit", "Scan status", "SDT exit", "Findings", "OpenGrep", "Gitleaks", "Trivy", "Sonar", "PDF", "Error")
VERDICTS = {"true_positive", "false_positive", "needs_context", "accepted_risk"}


def _cell(value: object) -> str:
    value = str(value if value is not None else "")
    value = "".join(char if ord(char) in (9, 10, 13) or 32 <= ord(char) <= 0xD7FF
                    or 0xE000 <= ord(char) <= 0xFFFD or 0x10000 <= ord(char) <= 0x10FFFF
                    else "�" for char in value)
    return escape(value, {'"': '&quot;', "'": '&apos;'})


def _column(index: int) -> str:
    label = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        label = chr(65 + remainder) + label
    return label


def sheet_xml(rows: list[tuple]) -> bytes:
    lines = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>']
    for row_number, row in enumerate(rows, 1):
        lines.append(f'<row r="{row_number}">')
        for col_number, value in enumerate(row, 1):
            ref = f"{_column(col_number)}{row_number}"
            lines.append(f'<c r="{ref}" t="inlineStr"><is><t>{_cell(value)}</t></is></c>')
        lines.append('</row>')
    lines.append('</sheetData></worksheet>')
    return "".join(lines).encode()


def write_xlsx(path: Path, sheets: list[tuple[str, list[tuple]]]) -> None:
    """Write a portable, formula-free workbook using only the Python stdlib."""
    content_types = ['<?xml version="1.0" encoding="UTF-8"?>',
                     '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
                     '<Default Extension="xml" ContentType="application/xml"/>',
                     '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>']
    workbook_sheets = []
    relations = []
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        for index, (name, rows) in enumerate(sheets, 1):
            archive.writestr(f"xl/worksheets/sheet{index}.xml", sheet_xml(rows))
            content_types.append(f'<Override PartName="/xl/worksheets/sheet{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
            workbook_sheets.append(f'<sheet name="{_cell(name)}" sheetId="{index}" r:id="rId{index}"/>')
            relations.append(f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>')
        archive.writestr("[Content_Types].xml", "".join(content_types) + "</Types>")
        archive.writestr("xl/workbook.xml", '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' + "".join(workbook_sheets) + '</sheets></workbook>')
        archive.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + "".join(relations) + '</Relationships>')


def _location(finding: dict) -> str:
    loc = finding.get("location") or {}
    path = loc.get("path") or (finding.get("artifact") or {}).get("target") or ""
    line = loc.get("startLine")
    return f"{path}:{line}" if line else str(path)


def load_triage(path: Path | None) -> dict[tuple[str, str], dict]:
    if path is None:
        return {}
    verdicts: dict[tuple[str, str], dict] = {}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"repository", "fingerprint", "verdict", "reviewer", "reason", "reviewed_at"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("triage CSV missing required columns")
        for row in reader:
            if row["verdict"] not in VERDICTS or not row["reviewer"] or not row["reason"]:
                raise ValueError("triage row requires valid verdict, reviewer, and reason")
            key = (row["repository"], row["fingerprint"])
            if key in verdicts:
                raise ValueError("duplicate triage key")
            verdicts[key] = row
    return verdicts


def unfixed_advisory(finding: dict) -> bool:
    """True only for a dependency advisory that positively shows no fix version.

    An unfixed vulnerability stays in the default register; this predicate is the
    report-time filter a reader opts into, never a scan-time suppression.
    Structured scanner fields are authoritative: an identified package with an
    installed version but no fix version anywhere in the record is unfixed,
    whatever the advisory prose looks like.
    """
    if str(finding.get("category") or "") != DEP_CATEGORY:
        return False
    if (finding.get("artifact") or {}).get("fixedVersion"):
        return False
    if (finding.get("remediation") or {}).get("fixedVersion"):
        return False
    artifact = finding.get("artifact") or {}
    if artifact.get("package") and artifact.get("installedVersion"):
        return True
    extracted = extract_vuln_fields(str(finding.get("message") or ""))
    if extracted["fix"]:
        return False
    # Flattened records: prose this reader cannot place on a package is not
    # evidence of no fix.
    return bool(extracted["package"] or extracted["cve"] or extracted["version"])


def build_rows(manifest: dict, root: Path, triage: dict[tuple[str, str], dict] | None = None,
               hide_unfixed: bool = False) -> tuple[list[tuple], list[tuple], Counter]:
    triage = triage or {}
    findings_rows = [FINDING_COLUMNS]
    coverage_rows = [COVERAGE_COLUMNS]
    totals: Counter = Counter()
    if hide_unfixed:
        totals["hidden_unfixed"] += 0  # disclose the applied filter even when it hides nothing
    for record in manifest.get("repositories", []):
        repo = record["repository"]
        report_dir = root / "repositories" / repo
        tasks = {}
        manifest_path = report_dir / "run-manifest.json"
        if manifest_path.is_file():
            native = json.loads(manifest_path.read_text())
            tasks = {task.get("adapter"): task.get("state") for task in native.get("tasks", [])}
        coverage_rows.append((repo, record.get("branch", ""), record.get("commit", ""),
                              record.get("status", ""), record.get("sdtExitCode", ""),
                              record.get("findings", 0), tasks.get("opengrep", "not_run"),
                              tasks.get("gitleaks", "not_run"), tasks.get("trivy-fs", "not_run"),
                              record.get("sonar", ""), record.get("pdf", ""), record.get("error", "")))
        report_path = report_dir / "findings.json"
        if not report_path.is_file():
            totals["repositories_without_report"] += 1
            continue
        report = json.loads(report_path.read_text())
        for finding in report.get("findings", []):
            if finding.get("suppression"):
                # Covered by an approved exception (e.g. a reviewed false positive): counted, not listed.
                totals["suppressed"] += 1
                continue
            if hide_unfixed and unfixed_advisory(finding):
                totals["hidden_unfixed"] += 1
                continue
            severity = str((finding.get("severity") or {}).get("canonical") or "unknown")
            totals[severity] += 1
            rule = finding.get("rule") or {}
            rem = finding.get("remediation") or {}
            fingerprint = (finding.get("fingerprint") or {}).get("value", "")
            review = triage.get((repo, fingerprint), {})
            totals[f"verdict_{review.get('verdict') or 'unreviewed'}"] += 1
            cwe = rule.get("cwe") or []
            cwe_text = ", ".join(cwe) if isinstance(cwe, list) else str(cwe)
            findings_rows.append((repo, record.get("commit", ""), record.get("status", ""),
                                  finding.get("category", ""), severity, rule.get("id", ""),
                                  cwe_text, _location(finding),
                                  finding.get("message", ""), rem.get("guidance", ""),
                                  fingerprint, finding.get("confidence", ""), finding.get("baselineState", ""),
                                  review.get("verdict", "unreviewed"), review.get("reviewer", ""),
                                  review.get("reason", ""), review.get("reviewed_at", ""),
                                  record.get("sonarProjectKey", "")))
    return findings_rows, coverage_rows, totals


def rule_quality_rows(findings: list[tuple]) -> list[tuple]:
    counts: dict[str, Counter] = {}
    for row in findings[1:]:
        if row[3] != "sast":
            continue
        counts.setdefault(str(row[5]), Counter())[str(row[13])] += 1
    rows = [("Rule", "True positives", "False positives", "Needs context", "Unreviewed", "Reviewed precision")]
    for rule in sorted(counts):
        c = counts[rule]
        reviewed = c["true_positive"] + c["false_positive"]
        precision = f"{c['true_positive'] / reviewed:.1%}" if reviewed else "unmeasured"
        rows.append((rule, c["true_positive"], c["false_positive"], c["needs_context"], c["unreviewed"], precision))
    return rows


def write_pdf(path: Path, manifest: dict, coverage: list[tuple], totals: Counter) -> None:
    styles = getSampleStyleSheet()
    story = [Paragraph("SDT Fleet Security Scan", styles["Title"]),
             Paragraph(escape(f"Workspace: {manifest.get('workspace', '')} | Run: {manifest.get('runId', '')}"), styles["Normal"]),
             Spacer(1, 16), Paragraph("Coverage", styles["Heading2"])]
    rows = [["Repository", "Status", "Findings", "Sonar"]]
    for item in coverage[1:]:
        rows.append([str(item[0])[:32], str(item[3]), str(item[5]), str(item[9])])
    for offset in range(0, len(rows), 35):
        segment = rows[:1] + rows[max(1, offset):offset + 35] if offset else rows[:35]
        if len(segment) < 2:
            continue
        table = Table(segment, colWidths=[160, 110, 70, 80], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
                                   ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                   ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                                   ("FONTSIZE", (0, 0), (-1, -1), 8)]))
        story.append(table)
        story.append(Spacer(1, 8))
    story.extend([Spacer(1, 12), Paragraph("Finding totals", styles["Heading2"])])
    totals_line = ", ".join(f"{severity}: {totals[severity]}" for severity in SEVERITIES)
    if "hidden_unfixed" in totals:
        totals_line += f", Hidden unfixed: {totals['hidden_unfixed']}"
    if totals["suppressed"]:
        totals_line += f", Suppressed by an exception: {totals['suppressed']}"
    story.append(Paragraph(escape(totals_line), styles["Normal"]))
    story.append(Paragraph(escape("Triage: " + ", ".join(f"{status}: {totals['verdict_' + status]}" for status in ("true_positive", "false_positive", "needs_context", "accepted_risk", "unreviewed"))), styles["Normal"]))
    story.append(Paragraph("Full finding details and scanner coverage are in fleet-findings.xlsx. Repository PDFs and canonical SDT reports are stored under repositories/.", styles["Normal"]))
    SimpleDocTemplate(str(path), pagesize=A4).build(story)


def main() -> int:
    parser = argparse.ArgumentParser(description="Export SDT fleet Excel and PDF reports")
    parser.add_argument("--from", dest="source", required=True, type=Path)
    parser.add_argument("--triage", type=Path, help="CSV verdict ledger with repository,fingerprint,verdict,reviewer,reason,reviewed_at")
    parser.add_argument("--hide-unfixed", action="store_true",
                        help="report filter: drop dependency advisories that show no fix version from the Findings "
                             "sheet and state how many were hidden; findings this filter cannot read stay visible")
    args = parser.parse_args()
    try:
        manifest = json.loads(args.source.read_text())
        root = args.source.resolve().parent
        findings, coverage, totals = build_rows(manifest, root, load_triage(args.triage), args.hide_unfixed)
        write_xlsx(root / "fleet-findings.xlsx", [("Findings", findings), ("Coverage", coverage),
                                                    ("Rule quality", rule_quality_rows(findings))])
        write_pdf(root / "fleet-summary.pdf", manifest, coverage, totals)
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(f"fleet report failed: {exc}", file=sys.stderr)
        return 2
    print(f"fleet report: {len(findings) - 1} findings, {len(coverage) - 1} repositories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
