package scanner

import (
	"fmt"
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
	// Machine independence: same finding, same position, from a different
	// checkout root must fingerprint identically.
	payloadOther := []byte(`{"results": [{"check_id": "scp.python.exec.eval", "path": "/other/app.py", "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 9}, "extra": {"message": "eval use", "severity": "ERROR"}}]}`)
	pr3 := a.Parse("1.29.0", "/other", payloadOther, "", 1)
	if pr.Findings[0].Fingerprint.Value != pr3.Findings[0].Fingerprint.Value {
		t.Fatal("fingerprints diverge across checkouts")
	}
	// Occurrence identity: the same rule+message at a different line in the
	// same file is a distinct occurrence, never a fingerprint collision.
	payloadMoved := []byte(`{"results": [{"check_id": "scp.python.exec.eval", "path": "/repo/app.py", "start": {"line": 9, "col": 1}, "end": {"line": 9, "col": 9}, "extra": {"message": "eval use", "severity": "ERROR"}}]}`)
	pr2 := a.Parse("1.29.0", "/repo", payloadMoved, "", 1)
	if pr.Findings[0].Fingerprint.Value == pr2.Findings[0].Fingerprint.Value {
		t.Fatal("distinct occurrences in one file must not share a fingerprint")
	}
}

// Regression (pilot): four identical `hardcoded-conditional` messages in one
// file collapsed to one fingerprint. Flagged-code content must dominate.
func TestOpengrepContentSeparatesSameFileFindings(t *testing.T) {
	a := &OpengrepAdapter{}
	mk := func(line int, lines string) []byte {
		return []byte(`{"results": [{"check_id": "vendor.semgrep.java.lang.correctness.hardcoded-conditional", "path": "/repo/R.java", "start": {"line": ` +
			itoa(line) + `, "col": 1}, "end": {"line": ` + itoa(line) + `}, "extra": {"message": "This if statement will always have the same behavior.", "severity": "ERROR", "lines": "` + lines + `"}}]}`)
	}
	p1 := a.Parse("1.29.0", "/repo", mk(84, `if (a.equals(b)) {`), "", 1)
	p2 := a.Parse("1.29.0", "/repo", mk(243, `if (c.isEnabled()) {`), "", 1)
	if len(p1.Findings) != 1 || len(p2.Findings) != 1 {
		t.Fatalf("want 1 finding each")
	}
	if p1.Findings[0].Fingerprint.Value == p2.Findings[0].Fingerprint.Value {
		t.Fatal("different code content in one file must not share a fingerprint")
	}
}

// B2: correctness-family rules are logic bugs — capped at medium, tagged, and
// the scanner's original severity is preserved. Security rules keep high.
func TestOpengrepCorrectnessClassification(t *testing.T) {
	a := &OpengrepAdapter{}
	correctness := []byte(`{"results": [{"check_id": "vendor.semgrep.java.lang.correctness.eqeq", "path": "/repo/S.java", "start": {"line": 119, "col": 1}, "end": {"line": 119}, "extra": {"message": "always true", "severity": "ERROR", "metadata": {"confidence": "HIGH"}}}]}`)
	security := []byte(`{"results": [{"check_id": "vendor.semgrep.java.lang.security.servletresponse-writer-xss", "path": "/repo/W.java", "start": {"line": 5, "col": 1}, "end": {"line": 5}, "extra": {"message": "xss", "severity": "ERROR", "metadata": {"confidence": "HIGH"}}}]}`)

	pc := a.Parse("1.29.0", "/repo", correctness, "", 1)
	ps := a.Parse("1.29.0", "/repo", security, "", 1)
	cf, sf := pc.Findings[0], ps.Findings[0]

	if cf.Severity.Canonical != "medium" || cf.Severity.Original != "ERROR" {
		t.Fatalf("correctness must cap at medium with original kept: %+v", cf.Severity)
	}
	if got := cf.Metadata["classification"]; got != "correctness" {
		t.Fatalf("classification not tagged: %v", cf.Metadata)
	}
	if sf.Severity.Canonical != "high" {
		t.Fatalf("security rule must keep high: %+v", sf.Severity)
	}
	if got := sf.Metadata["classification"]; got != "security" {
		t.Fatalf("security classification missing: %v", sf.Metadata)
	}
	if cf.Confidence != "high" || sf.Confidence != "high" {
		t.Fatalf("scanner confidence not carried: %q / %q", cf.Confidence, sf.Confidence)
	}
}

// B1: gitleaks --redact uniformizes match text, so distinct leaks at distinct
// lines of one file must not collapse into one fingerprint.
func TestGitleaksDistinctLinesDistinctFingerprints(t *testing.T) {
	payload := []byte(`[
		{"RuleID": "generic-api-key", "File": "/repo/cfg.yml", "StartLine": 117, "EndLine": 117, "Match": "password: REDACTED", "Secret": "REDACTED", "Description": "key", "Commit": "aaaaaaaaaaaaaaaa"},
		{"RuleID": "generic-api-key", "File": "/repo/cfg.yml", "StartLine": 209, "EndLine": 209, "Match": "password: REDACTED", "Secret": "REDACTED", "Description": "key", "Commit": "aaaaaaaaaaaaaaaa"}
	]`)
	a := &GitleaksAdapter{}
	pr := a.Parse("8.30.1", "/repo", payload, "", 0)
	if len(pr.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(pr.Findings))
	}
	if pr.Findings[0].Fingerprint.Value == pr.Findings[1].Fingerprint.Value {
		t.Fatal("distinct secret occurrences must not share a fingerprint")
	}
	if pr.Findings[0].Confidence != "high" {
		t.Fatalf("secret confidence must be high, got %q", pr.Findings[0].Confidence)
	}
}

// B1: the same misconfig check at several lines of one target is distinct.
func TestTrivyMisconfigDistinctLinesDistinctFingerprints(t *testing.T) {
	payload := []byte(`{"SchemaVersion": 2, "Results": [{"Target": "Dockerfile", "Misconfigurations": [
		{"ID": "DS-0002", "Title": "t", "Severity": "HIGH", "CauseMetadata": {"StartLine": 3, "EndLine": 3}},
		{"ID": "DS-0002", "Title": "t", "Severity": "HIGH", "CauseMetadata": {"StartLine": 9, "EndLine": 9}}
	]}]}`)
	a := &TrivyFSAdapter{}
	pr := a.Parse("0.73.0", "/repo", payload, "", 0)
	if len(pr.Findings) != 2 {
		t.Fatalf("want 2, got %d", len(pr.Findings))
	}
	if pr.Findings[0].Fingerprint.Value == pr.Findings[1].Fingerprint.Value {
		t.Fatal("distinct misconfig occurrences must not share a fingerprint")
	}
	if pr.Findings[0].Confidence != "medium" {
		t.Fatalf("misconfig confidence must be medium, got %q", pr.Findings[0].Confidence)
	}
}

// B1: vendored rule ids must not leak the operator's install path.
func TestCleanRuleIDStripsInstallPath(t *testing.T) {
	cases := map[string]string{
		"home.wishnu.secure-development-tools.rules.opengrep-rules.vendor.semgrep.java.lang.security.x":
			"vendor.semgrep.java.lang.security.x",
		"scp.common.secrets.private-key": "scp.common.secrets.private-key",
		"CVE-2022-0839":                  "CVE-2022-0839",
	}
	for in, want := range cases {
		if got := cleanRuleID(in); got != want {
			t.Fatalf("cleanRuleID(%q)=%q, want %q", in, got, want)
		}
	}
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
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
