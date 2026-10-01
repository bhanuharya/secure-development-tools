package app

import (
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func mkFinding(path string) *finding.Finding {
	f := &finding.Finding{ID: "x", Category: finding.CatSAST}
	if path != "" {
		f.Location = &finding.Location{Path: path}
	}
	return f
}

func TestFilterStagedKeepsOnlyStagedPaths(t *testing.T) {
	in := []*finding.Finding{
		mkFinding("a.go"),
		mkFinding("sub/b.go"),
		mkFinding("unstaged.go"),
		mkFinding(""),
		{ID: "nolocation", Category: finding.CatSecret},
	}
	kept, dropped := filterStaged(in, []string{"a.go", "sub/b.go"})
	if len(kept) != 2 || dropped != 3 {
		t.Fatalf("kept=%d dropped=%d, want 2/3", len(kept), dropped)
	}
	for _, f := range kept {
		if f.Location.Path != "a.go" && f.Location.Path != "sub/b.go" {
			t.Fatalf("leaked unstaged finding: %v", f.Location)
		}
	}
}

func TestFilterStagedEmptySetDropsAll(t *testing.T) {
	kept, dropped := filterStaged([]*finding.Finding{mkFinding("a.go")}, nil)
	if len(kept) != 0 || dropped != 1 {
		t.Fatalf("kept=%d dropped=%d, want 0/1", len(kept), dropped)
	}
}

func TestStagedCapable(t *testing.T) {
	for _, id := range []string{"opengrep", "gitleaks"} {
		if !stagedCapable(id) {
			t.Fatalf("%s must be staged-capable", id)
		}
	}
	for _, id := range []string{"trivy-fs", "trivy-image", "bogus"} {
		if stagedCapable(id) {
			t.Fatalf("%s must defer to CI in staged mode", id)
		}
	}
}
