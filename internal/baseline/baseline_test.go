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
