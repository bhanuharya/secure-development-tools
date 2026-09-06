package publish

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func mk(id, sev, path string, line int) *finding.Finding {
	return &finding.Finding{
		ID: id, Message: "msg " + id,
		Fingerprint: finding.Fingerprint{Algorithm: "sdt-v1", Value: "sha256:" + strings.Repeat("a", 64)},
		Category:    "sast",
		Rule:        finding.Rule{ID: "rule-1"},
		Severity:    finding.Severity{Canonical: sev},
		Location:    &finding.Location{Path: path, StartLine: &line},
		Redaction:   finding.Redaction{Applied: true},
	}
}

func TestGitHubCapsAndOrders(t *testing.T) {
	var fs []*finding.Finding
	for i := 0; i < 60; i++ {
		fs = append(fs, mk("f1", "low", "a.go", 1))
	}
	fs = append(fs, mk("crit", "critical", "b.go", 2))
	anns, summary := GitHub(fs, Blockers([]string{"crit"}), "policy_failed")
	var decoded []map[string]any
	if err := json.Unmarshal(anns, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != maxAnnotations {
		t.Fatalf("want cap %d, got %d", maxAnnotations, len(decoded))
	}
	if decoded[0]["title"] != "[critical] rule-1" {
		t.Fatalf("blockers must come first: %+v", decoded[0])
	}
	if !strings.Contains(summary, "policy_failed") {
		t.Fatal("summary must carry recorded status")
	}
}

func TestBitbucketResultMirrorsStatus(t *testing.T) {
	raw := Bitbucket([]*finding.Finding{mk("a", "high", "x.py", 1)}, Blockers([]string{"a"}), "policy_failed")
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["result"] != "FAIL" {
		t.Fatalf("blocking findings must FAIL: %v", doc["result"])
	}
	raw = Bitbucket(nil, Blockers(nil), "passed")
	doc = map[string]any{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["result"] != "PASS" {
		t.Fatalf("clean must PASS: %v", doc["result"])
	}
}

func TestGitLabShape(t *testing.T) {
	raw := GitLab([]*finding.Finding{mk("a", "medium", "x.py", 3)}, Blockers(nil))
	var issues []map[string]any
	if err := json.Unmarshal(raw, &issues); err != nil {
		t.Fatal(err)
	}
	if len(issues) != 1 || issues[0]["severity"] != "major" {
		t.Fatalf("bad codequality mapping: %v", issues)
	}
}
