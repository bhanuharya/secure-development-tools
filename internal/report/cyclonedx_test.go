package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
)

func vexFinding(id, rule, pkg, ver, target, sev string) *finding.Finding {
	return &finding.Finding{
		ID: id, Category: finding.CatDepVuln,
		Rule:     finding.Rule{ID: rule},
		Severity: finding.Severity{Canonical: sev},
		Artifact: &finding.Artifact{Package: pkg, InstalledVersion: ver, Target: target},
	}
}

func TestToVEXSkipsNonVulnCategories(t *testing.T) {
	fs := []*finding.Finding{
		vexFinding("a", "CVE-2024-1", "lodash", "4.17.20", "package-lock.json", "high"),
		{ID: "b", Category: finding.CatSAST, Rule: finding.Rule{ID: "r"},
			Severity: finding.Severity{Canonical: "high"},
			Artifact: &finding.Artifact{Package: "x"}},
		{ID: "c", Category: finding.CatSecret, Rule: finding.Rule{ID: "s"},
			Severity: finding.Severity{Canonical: "high"}},
	}
	raw := ToVEX("policy_failed", fs, policy.Outcome{
		Status:   "policy_failed",
		Blockers: []policy.Match{{FindingID: "a", RuleID: "block"}},
	})
	var doc struct {
		BomFormat       string `json:"bomFormat"`
		SpecVersion     string `json:"specVersion"`
		Vulnerabilities []struct {
			ID       string `json:"id"`
			BomRef   string `json:"bomRef"`
			Analysis struct {
				State  string `json:"state"`
				Detail string `json:"detail,omitempty"`
			} `json:"analysis"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("VEX not JSON: %v", err)
	}
	if doc.BomFormat != "CycloneDX" || doc.SpecVersion != "1.5" {
		t.Fatalf("bad envelope: %+v", doc)
	}
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("want only the dep vuln, got %d", len(doc.Vulnerabilities))
	}
	v := doc.Vulnerabilities[0]
	if v.Analysis.State != "exploitable" {
		t.Fatalf("blocker must be exploitable, got %q", v.Analysis.State)
	}
	if v.Affects[0].Ref != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("bad purl ref: %q", v.Affects[0].Ref)
	}
}

func TestToVEXNeverNotAffected(t *testing.T) {
	fs := []*finding.Finding{
		vexFinding("a", "CVE-2024-1", "p", "1.0", "requirements.txt", "critical"),
	}
	fs[0].Suppression = &finding.Suppression{ExceptionID: "EX-1", Reason: "accepted risk"}
	raw := ToVEX("passed", fs, policy.Outcome{Status: "passed"})
	if strings.Contains(string(raw), "not_affected") {
		t.Fatal("suppressed findings must never render not_affected")
	}
	if !strings.Contains(string(raw), "EX-1") {
		t.Fatal("suppression provenance must be recorded")
	}
	var doc struct {
		Vulnerabilities []struct {
			Analysis struct {
				State string `json:"state"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	_ = json.Unmarshal(raw, &doc)
	if doc.Vulnerabilities[0].Analysis.State != "in_triage" {
		t.Fatalf("suppressed must be in_triage, got %q", doc.Vulnerabilities[0].Analysis.State)
	}
}

func TestComponentRefEcosystems(t *testing.T) {
	cases := map[string]string{
		"package-lock.json": "pkg:npm/a@1",
		"requirements.txt":  "pkg:pypi/a@1",
		"go.mod":            "pkg:golang/a@1",
		"pom.xml":           "pkg:maven/a@1",
		"Cargo.lock":        "pkg:cargo/a@1",
		"mystery.file":      "pkg:generic/a@1",
	}
	for target, want := range cases {
		f := vexFinding("x", "CVE-1", "a", "1", target, "low")
		if got := componentRef(f); got != want {
			t.Fatalf("%s: got %q want %q", target, got, want)
		}
	}
}

func TestMergeCycloneDXDedupes(t *testing.T) {
	mkdoc := func(refs ...string) []byte {
		comps := []any{}
		for _, r := range refs {
			comps = append(comps, map[string]any{"bom-ref": r, "name": "x"})
		}
		raw, _ := json.Marshal(map[string]any{
			"bomFormat": "CycloneDX", "specVersion": "1.5",
			"serialNumber": "urn:uuid:1",
			"components":   comps,
		})
		return raw
	}
	merged, err := MergeCycloneDX(mkdoc("a", "b"), mkdoc("b", "c"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []struct {
			BomRef string `json:"bom-ref"`
		} `json:"components"`
		Metadata struct {
			Comment string `json:"comment"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(merged, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 3 {
		t.Fatalf("want 3 deduped components, got %d", len(doc.Components))
	}
	if !strings.Contains(doc.Metadata.Comment, "merged by sdt") {
		t.Fatal("merge provenance missing")
	}
	var doc2 map[string]any
	_ = json.Unmarshal(merged, &doc2)
	if _, ok := doc2["serialNumber"]; ok {
		t.Fatal("stale serialNumber must be dropped on merge")
	}
}

func TestMergeCycloneDXRejectsGarbage(t *testing.T) {
	if _, err := MergeCycloneDX([]byte("{nope")); err == nil {
		t.Fatal("expected merge error on invalid JSON")
	}
	if _, err := MergeCycloneDX(); err == nil {
		t.Fatal("expected merge error on empty input")
	}
}
