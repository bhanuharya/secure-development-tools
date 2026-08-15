import types

from reportlab.platypus import Paragraph, Table

from src.reporting.pdf_report import PdfReportBuilder, _esc


def _scan():
    return types.SimpleNamespace(
        scan_type="sast",
        ref_type="branch",
        ref_name="main",
        commit_sha="abc123",
        engines="bandit",
        created_at=None,
        status="succeeded",
    )


def _project():
    return types.SimpleNamespace(
        name="<a href='javascript:alert(1)'>evil</a>",
        workspace="miraworkspace",
        repo_slug="repo<script>",
    )


def _finding():
    return types.SimpleNamespace(
        severity="high",
        tool="bandit",
        rule_id="B324",
        cwe="CWE-326",
        file_path="app.py<b>",
        line_start=1,
        snippet="hash()",
        description="<unclosed bold",
        remediation="<img src=x onerror=alert(1)>",
        in_pr_diff=False,
    )


def _para_texts(obj):
    out = []
    if isinstance(obj, Paragraph):
        out.append(obj.text)
    elif isinstance(obj, Table):
        for row in obj._cellvalues:
            for cell in row:
                if isinstance(cell, (list, tuple)):
                    for item in cell:
                        out.extend(_para_texts(item))
                else:
                    out.extend(_para_texts(cell))
    return out


def _all_paragraph_texts(flowables):
    texts = []
    for f in flowables:
        texts.extend(_para_texts(f))
    return texts


def test_esc_escapes_markup():
    assert _esc("<a href='x'>y</a> & more") == "&lt;a href='x'&gt;y&lt;/a&gt; &amp; more"
    assert _esc("plain text") == "plain text"


def test_report_generation_escapes_markup_and_does_not_crash(tmp_path):
    builder = PdfReportBuilder(str(tmp_path / "report.pdf"))
    builder.build_scan(_scan(), _project(), [_finding()])

    combined = "\n".join(_all_paragraph_texts(builder.story))
    # attacker markup is never emitted as active tags
    assert "<a href" not in combined
    assert "<img" not in combined
    assert "<unclosed" not in combined
    # it is present as escaped, literal text
    assert "&lt;a href" in combined
    assert "&lt;img" in combined
    assert "&lt;unclosed" in combined
    # normal text remains present
    assert "evil" in combined
    assert "bold" in combined
    # the intentional trusted label is retained as real markup
    assert "<b>Remediation:</b>" in combined

    out = builder.save()
    assert out == str(tmp_path / "report.pdf")
