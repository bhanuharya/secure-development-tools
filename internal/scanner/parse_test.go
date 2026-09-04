package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// Golden: native gitleaks JSON -> canonical findings, redacted.
func TestGitleaksParseGolden(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/native-results/gitleaks-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	a := &GitleaksAdapter{}
	pr := a.Parse("8.30.1", "/repo", raw, "", 0)
	if pr.Health != HealthCompleted {
		t.Fatalf("health=%s diag=%v", pr.Health, pr.Diagnostics)
	}
	if len(pr.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(pr.Findings))
	}
	f := pr.Findings[0]
	if f.Category != "secret" || f.Severity.Canonical != "high" {
		t.Fatalf("bad normalization: %+v", f)
	}
	if f.BaselineState != "unknown" {
		t.Fatalf("baseline must default to unknown, got %q", f.BaselineState)
	}
	for _, s := range []string{"sk-live-12345678901234567890"} {
		if containsStr(f.Message, s) {
			t.Fatalf("raw secret leaked in message: %q", f.Message)
		}
		if f.Evidence != nil && containsStr(f.Evidence.Text, s) {
			t.Fatalf("raw secret leaked in evidence")
		}
	}
	_ = filepath.Separator
}

// Golden: native trivy fs JSON -> canonical CVE mapping.
func TestTrivyFSParseGolden(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/native-results/trivy-fs-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	a := &TrivyFSAdapter{}
	pr := a.Parse("0.73.0", "/repo", raw, "", 0)
	if pr.Health != HealthCompleted {
		t.Fatalf("health=%s", pr.Health)
	}
	if len(pr.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(pr.Findings))
	}
	if pr.Findings[0].Category != "dependency-vulnerability" || pr.Findings[0].Severity.Canonical != "critical" {
		t.Fatalf("bad vuln mapping: %+v", pr.Findings[0])
	}
	if pr.Findings[1].Category != "misconfiguration" {
		t.Fatalf("bad misconfig mapping: %+v", pr.Findings[1])
	}
}

func TestOpengrepPathsRelativeToRoot(t *testing.T) {
	payload := []byte(`{"results": [{"check_id": "scp.python.exec.eval", "path": "/repo/app.py", "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 9}, "extra": {"message": "eval use", "severity": "ERROR"}}]}`)
	a := &OpengrepAdapter{}
	pr := a.Parse("1.29.0", "/repo", payload, "", 1)
	if len(pr.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(pr.Findings))
	}
	if got := pr.Findings[0].Location.Path; got != "app.py" {
		t.Fatalf("path not relativized: %q", got)
	}
	// Same logical finding from a different checkout root must fingerprint identically.
	payloadOther := []byte(`{"results": [{"check_id": "scp.python.exec.eval", "path": "/other/app.py", "start": {"line": 9, "col": 1}, "end": {"line": 9, "col": 9}, "extra": {"message": "eval use", "severity": "ERROR"}}]}`)
	pr3 := a.Parse("1.29.0", "/other", payloadOther, "", 1)
	if pr.Findings[0].Fingerprint.Value != pr3.Findings[0].Fingerprint.Value {
		t.Fatal("fingerprints diverge across checkouts")
	}
}

func TestTrivyImageResolvedDigest(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/native-results/trivy-image-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	a := &TrivyImageAdapter{}
	pr := a.Parse("0.73.0", "/repo", raw, "", 0)
	if len(pr.Findings) != 1 {
		t.Fatalf("want 1, got %d", len(pr.Findings))
	}
	if got := pr.Findings[0].Artifact.Image; got != "juice@sha256:deadbeef" {
		t.Fatalf("resolved digest not recorded: %q", got)
	}
}

func TestOpengrepMalformed(t *testing.T) {
	a := &OpengrepAdapter{}
	pr := a.Parse("1.0", "/repo", []byte("{nope"), "", 1)
	if pr.Health != HealthMalformed {
		t.Fatalf("want malformed, got %s", pr.Health)
	}
}

func containsStr(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
