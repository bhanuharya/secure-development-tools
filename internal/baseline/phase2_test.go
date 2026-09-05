package baseline

import (
	"testing"
	"time"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func fpFinding(id, fp, rule, loc string) *finding.Finding {
	f := &finding.Finding{ID: id, Fingerprint: finding.Fingerprint{Algorithm: "sdt-v1", Value: fp}, Rule: finding.Rule{ID: rule}}
	if loc != "" {
		f.Location = &finding.Location{Path: loc}
	}
	return f
}

func TestValidateExceptionRequiresScope(t *testing.T) {
	e := Exception{ID: "EX-1", Reason: "r", Owner: "o", ExpiresAt: "2999-01-01"}
	if _, err := ValidateException(e, time.Now()); err == nil {
		t.Fatal("scope-less exception must fail validation")
	}
}

func TestMatchesRuleAndPath(t *testing.T) {
	now := time.Now()
	ruleEx := Exception{ID: "R", Reason: "r", Owner: "o", ExpiresAt: "2999-01-01", Rules: []string{"SEC001"}}
	if _, err := ValidateException(ruleEx, now); err != nil {
		t.Fatal(err)
	}
	f := fpFinding("a", "sha256:x", "SEC001", "other.go")
	if !ruleEx.Matches(f) {
		t.Fatal("rule scope must match")
	}
	pathEx := Exception{ID: "P", Reason: "r", Owner: "o", ExpiresAt: "2999-01-01", Paths: []string{"legacy/*"}}
	fl := fpFinding("b", "sha256:y", "OTHER", "legacy/old.go")
	if !pathEx.Matches(fl) {
		t.Fatal("path scope must match")
	}
	if pathEx.Matches(fpFinding("c", "sha256:z", "OTHER", "src/new.go")) {
		t.Fatal("path scope must not match unrelated path")
	}
}
