package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func mk(id, fp string) *finding.Finding {
	return &finding.Finding{ID: id, Fingerprint: finding.Fingerprint{Algorithm: "sdt-v1", Value: fp}, BaselineState: "new"}
}

func TestApplyNewExistingResolved(t *testing.T) {
	bl := &Baseline{Entries: map[string]Entry{"sha256:old": {}}}
	fs := []*finding.Finding{mk("a", "sha256:old"), mk("b", "sha256:new")}
	resolved := bl.Apply(fs)
	if fs[0].BaselineState != "existing" || fs[1].BaselineState != "new" {
		t.Fatalf("bad states: %v %v", fs[0].BaselineState, fs[1].BaselineState)
	}
	if len(resolved) != 0 {
		t.Fatalf("unexpected resolved: %v", resolved)
	}
	resolved = (&Baseline{Entries: map[string]Entry{"sha256:gone": {}}}).Apply(fs)
	if len(resolved) != 1 || resolved[0] != "sha256:gone" {
		t.Fatalf("resolved not reported: %v", resolved)
	}
}

func TestCreateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "baseline.json")
	fs := []*finding.Finding{mk("a", "sha256:abc")}
	if err := Create(p, fs, "sha256:cfg", "HEAD"); err != nil {
		t.Fatal(err)
	}
	bl, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bl.Entries["sha256:abc"]; !ok {
		t.Fatal("entry missing after round trip")
	}
	_ = os.Remove(p)
}

func TestExceptionRequiresExpiry(t *testing.T) {
	e := Exception{ID: "EX-1", Reason: "r", Owner: "o", ExpiresAt: "2000-01-01"}
	expired, err := ValidateException(e, time.Now())
	if err != nil || !expired {
		t.Fatalf("past expiry must report expired: %v %v", expired, err)
	}
	bad := Exception{ID: "EX-2", Reason: "r"}
	if _, err := ValidateException(bad, time.Now()); err == nil {
		t.Fatal("expected owner/expiry validation error")
	}
}

func mkc(id, fp, content string) *finding.Finding {
	f := mk(id, fp)
	f.Fingerprint.Content = content
	return f
}

// Lines added above a finding change its line-bound fingerprint, not its code:
// it stays existing, and its baseline entry is not reported as resolved.
func TestApplyMovedFindingIsExisting(t *testing.T) {
	bl := &Baseline{Entries: map[string]Entry{"sha256:at35": {Content: "sha256:code"}}}
	fs := []*finding.Finding{mkc("a", "sha256:at43", "sha256:code")}
	if resolved := bl.Apply(fs); len(resolved) != 0 {
		t.Fatalf("the moved finding's entry must not be resolved: %v", resolved)
	}
	if fs[0].BaselineState != finding.StateExisting {
		t.Fatalf("moved finding: %s, want existing", fs[0].BaselineState)
	}
}

// Each baseline entry accounts for one finding: a pull request that copies
// existing code adds one new finding, wherever the copies land.
func TestApplySecondCopyOfExistingCodeIsNew(t *testing.T) {
	bl := &Baseline{Entries: map[string]Entry{"sha256:at10": {Content: "sha256:code"}}}
	fs := []*finding.Finding{mkc("a", "sha256:at12", "sha256:code"), mkc("b", "sha256:at30", "sha256:code")}
	bl.Apply(fs)
	if fs[0].BaselineState != finding.StateExisting || fs[1].BaselineState != finding.StateNew {
		t.Fatalf("states %s %s, want existing new", fs[0].BaselineState, fs[1].BaselineState)
	}
	// An exact match takes its own entry before a moved copy can.
	bl = &Baseline{Entries: map[string]Entry{"sha256:at10": {Content: "sha256:code"}}}
	fs = []*finding.Finding{mkc("a", "sha256:at40", "sha256:code"), mkc("b", "sha256:at10", "sha256:code")}
	bl.Apply(fs)
	if fs[0].BaselineState != finding.StateNew || fs[1].BaselineState != finding.StateExisting {
		t.Fatalf("states %s %s, want new existing", fs[0].BaselineState, fs[1].BaselineState)
	}
}

// The full scan of the target branch kept the secret scanner's finding and
// collapsed the code rule's copy into it; a pull request scan, whose secret
// scanner reads only the new commits, reports the code rule's copy alone.
func TestApplyCollapsedIdentityIsExisting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "baseline.json")
	secret := mk("g", "sha256:gitleaks")
	secret.Fingerprint.Collapsed = []finding.Fingerprint{{Value: "sha256:opengrep", Content: "sha256:opengrep-content"}}
	if err := Create(p, []*finding.Finding{secret}, "", ""); err != nil {
		t.Fatal(err)
	}
	bl, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	fs := []*finding.Finding{mkc("o", "sha256:opengrep", "sha256:opengrep-content")}
	if resolved := bl.Apply(fs); len(resolved) != 0 {
		t.Fatalf("one finding stands for both entries; resolved: %v", resolved)
	}
	if fs[0].BaselineState != finding.StateExisting {
		t.Fatalf("code rule's copy: %s, want existing", fs[0].BaselineState)
	}
	// The other way round: the baseline has only the code rule's finding, the
	// scan has the secret scanner's finding with that copy collapsed into it.
	bl = &Baseline{Entries: map[string]Entry{"sha256:opengrep": {}}}
	fs = []*finding.Finding{secret}
	if resolved := bl.Apply(fs); len(resolved) != 0 || fs[0].BaselineState != finding.StateExisting {
		t.Fatalf("state %s resolved %v, want existing and none", fs[0].BaselineState, resolved)
	}
}
