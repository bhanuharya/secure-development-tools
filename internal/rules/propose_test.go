package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func pclFinding(id, adapter, rule, cat, sev, path, evidence string) *finding.Finding {
	f := &finding.Finding{
		ID: id, Category: cat, Rule: finding.Rule{ID: rule},
		Severity:    finding.Severity{Canonical: sev},
		Scanner:     finding.ScannerID{Adapter: adapter, Tool: adapter},
		Fingerprint: finding.Fingerprint{Algorithm: "sdt-v1", Value: "sha256:" + id},
	}
	if path != "" {
		f.Location = &finding.Location{Path: path}
	}
	if evidence != "" {
		f.Evidence = &finding.Evidence{Text: evidence}
	}
	return f
}

func TestClusterFindingsRanksAndDedupes(t *testing.T) {
	a := []*finding.Finding{
		pclFinding("1", "opengrep", "r1", "sast", "high", "a.py", "x"),
		pclFinding("2", "opengrep", "r1", "sast", "high", "b.py", "x"), // dup evidence
		pclFinding("3", "opengrep", "r1", "sast", "high", "c.py", "y"),
		pclFinding("4", "gitleaks", "s", "secret", "high", "k", ""),
	}
	cl := ClusterFindings(a)
	if len(cl) != 2 || cl[0].RuleID != "r1" || cl[0].Count != 3 {
		t.Fatalf("bad clusters: %+v", cl)
	}
	if len(cl[0].Evidence) != 2 {
		t.Fatalf("evidence must dedupe, got %v", cl[0].Evidence)
	}
	if len(cl[1].Evidence) != 0 {
		t.Fatal("secret cluster must carry no evidence")
	}
}

func TestSkeletonIsInertButComplete(t *testing.T) {
	cl := ClusterFindings([]*finding.Finding{
		pclFinding("1", "opengrep", "my.rule/x", "sast", "high", "a.py", "eval(v)"),
	})[0]
	ruleFile, ruleYAML, testFile, testBody := Skeleton(cl)
	if !strings.HasSuffix(ruleFile, ".yaml.proposed") {
		t.Fatalf("draft must be inert by naming: %s", ruleFile)
	}
	if !strings.Contains(ruleYAML, "scp.mined") || !strings.Contains(ruleYAML, "TODO_FILL_PATTERN") {
		t.Fatalf("bad skeleton:\n%s", ruleYAML)
	}
	if testFile != "my-rule-x.test.py" {
		t.Fatalf("bad test name: %s", testFile)
	}
	if !strings.Contains(testBody, "# ruleid: scp.mined.my-rule-x") || !strings.Contains(testBody, "eval(v)") {
		t.Fatalf("bad test body:\n%s", testBody)
	}
}

func TestLoadReportFindingsFileAndDir(t *testing.T) {
	dir := t.TempDir()
	body := `{"findings": [{"id": "a", "rule": {"id": "r"}}]}`
	if err := os.WriteFile(filepath.Join(dir, "findings.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	one, err := LoadReportFindings(filepath.Join(dir, "findings.json"))
	if err != nil || len(one) != 1 || len(one[0]) != 1 {
		t.Fatalf("file load: %v %+v", err, one)
	}
	all, err := LoadReportFindings(dir)
	if err != nil || len(all) != 1 {
		t.Fatalf("dir load: %v %+v", err, all)
	}
	if _, err := LoadReportFindings(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected error on missing file")
	}
}
