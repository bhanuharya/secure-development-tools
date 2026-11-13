"""T34: review3 credential shapes stay out of artifacts and a fake model's echoed advice."""
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "testdata/endpoints/redaction"
sys.path.insert(0, str(ROOT / "tools"))

import sdt_advisory as advisory  # noqa: E402
import sdt_to_docx as docx  # noqa: E402
import sdt_triage_codex as triage  # noqa: E402

CASES = json.loads((FIXTURES / "cases.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_whole_block_redaction(case):
    withheld = set()
    safe = (advisory.redact_evidence if case["evidence"] else advisory.redact)(case["text"], withheld=withheld)
    lines = advisory.redact_lines(dict(enumerate(case["text"].splitlines())), withheld=withheld)
    assert safe.count("\n") == case["text"].count("\n")
    if case["evidence"]:
        assert safe == json.loads((FIXTURES / "expected-evidence.json").read_text())[case["name"]]
    for secret in case["secrets"]:
        assert secret not in safe
        if not case["evidence"]:
            assert secret not in "\n".join(lines.values())
        assert secret in withheld


@pytest.fixture(scope="module")
def sdt_binary(tmp_path_factory):
    binary = tmp_path_factory.mktemp("t34-bin") / "sdt"
    subprocess.run(["go", "build", "-o", str(binary), "./cmd/sdt"], cwd=ROOT, check=True, timeout=120)
    return binary


def test_fake_model_pipeline_withholds_review_credentials(tmp_path, sdt_binary):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("main.go", "Security.java"):
        shutil.copyfile(FIXTURES / name, source / name)
    artifacts = _inventory(sdt_binary, source, tmp_path)
    secrets = ["synthetic_Fiber7Demo!", "synthetic_Only7Demo!", "synthetic_Other8Demo!",
               "synthetic_Third9Demo!", "synthetic_Four0Demo!", "synthetic_Fifth1Demo!",
               "synthetic signing secret 7!"]
    # Include an out-of-date finding whose evidence still carries raw middleware arguments.
    finding = {"scanner": {"adapter": "endpoints"}, "category": "sast",
               "rule": {"id": "scp.endpoints.sensitive-route-without-role"},
               "location": {"path": "main.go", "startLine": 18}, "message": "missing authorization",
               "metadata": {"evidence": ["main.go:4 basicauth.New(...)", "main.go:11 gin.BasicAuth(...)",
                                          "Security.java:3 configure()"]}}
    groups = docx.from_findings({"findings": [finding]})["code"]
    prompts, memory = [], {"old": {"reason": "SIGNING_KEY = \"" + secrets[-1] + "\"",
                                  "extra": {"echo": secrets[0]}}}

    def fake(*args):
        prompts.append(args[2])
        echo = " ".join(secrets)
        return {"results": [{"id": "o1", "verdict": "likely_true_positive", "confidence": "high",
                             "reason": echo, "check": echo, "suggested_fix": echo, "impact": echo,
                             "fix_steps": [echo], "fix_example": (source / "main.go").read_text(),
                             "verify_fix": echo}]}

    answer = triage.triage(groups, source, "fake", "test", per_call_timeout=20, budget=100,
                           max_rules=2, max_per_rule=6, max_failures=2, call=fake,
                           findings={"findings": [finding]}, memory=memory)
    assert answer["calls"] == 1 and answer["results"] and prompts
    triage.save_memory(tmp_path / "memory.json", memory)
    docx.apply_triage(groups, answer)
    report = docx.Report("example", "example/orders", "main", "", "abc", "SDT", groups,
                         [], [], [], docx.date.today())
    docx.write_docx(report, source, tmp_path / "report.docx", logo=None)
    with zipfile.ZipFile(tmp_path / "report.docx") as archive:
        artifacts += [archive.read(name).decode() for name in archive.namelist()
                      if name.endswith((".xml", ".rels"))]
    artifacts += prompts + [json.dumps(answer), json.dumps(memory), (tmp_path / "memory.json").read_text()]
    for artifact in artifacts:
        for secret in secrets:
            assert secret not in artifact


def _inventory(binary, source, out):
    inventory, findings = out / "endpoints.json", out / "findings.json"
    subprocess.run([str(binary), "endpoints", str(source), "-o", str(inventory),
                    "--findings", str(findings)], cwd=ROOT, check=True, timeout=120)
    data = json.loads(inventory.read_text())
    assert data["routes"], "the CLI must actually extract routes"
    assert json.loads(findings.read_text()), "the CLI must actually produce convention findings"
    evidence = " ".join(e for route in data["routes"] for e in route["evidence"])
    assert "basicauth.New(...)" in evidence and "gin.BasicAuth(...)" in evidence
    return [inventory.read_text(), findings.read_text()]


def test_final_structured_pass_scrubs_unknown_fields_and_decoded_literals():
    raw = r'SIGNING_KEY = "synthetic \"quoted\" secret 7!"'
    secret = 'synthetic "quoted" secret 7!'
    safe = advisory.redact_tree({"new": {"source": raw}, "earlier_echo": secret})
    assert secret not in json.dumps(safe)
    assert safe["earlier_echo"] == "[REDACTED]"


def test_memory_redacts_values_before_normalising_individual_entries(tmp_path):
    secret = "synthetic memory secret 7!"
    path = tmp_path / "memory.json"
    triage.save_memory(path, {"first": {"reason": secret},
                              "second": {"reason": f'SIGNING_KEY = "{secret}"'}})
    safe = json.loads(path.read_text())
    assert safe["entries"]["first"]["reason"] == "[REDACTED]"
    assert secret not in path.read_text()
