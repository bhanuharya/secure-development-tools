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
