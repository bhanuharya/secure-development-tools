package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bhanuharya/secure-development-tools/internal/baseline"
	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func phase1Cfg(t *testing.T, exceptionsContent string) *config.ScanConfiguration {
	t.Helper()
	cfg := config.Defaults()
	if exceptionsContent == "" {
		cfg.Exceptions.File = filepath.Join(t.TempDir(), "no-exceptions.yaml")
		return cfg
	}
	p := filepath.Join(t.TempDir(), "exceptions.yaml")
	if err := os.WriteFile(p, []byte(exceptionsContent), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.Exceptions.File = p
	return cfg
}

func phase1Finding(fp string) *finding.Finding {
	return &finding.Finding{
		ID: "f1", Category: finding.CatSAST, Rule: finding.Rule{ID: "r"},
		Fingerprint: finding.Fingerprint{Algorithm: finding.FingerprintVersion, Value: fp},
	}
}

// Malformed exception files fail closed instead of scanning as if no
// exceptions were requested.
func TestApplyExceptionsMalformedFails(t *testing.T) {
	cfg := phase1Cfg(t, "exceptions: [this is not\n  valid: : :\n")
	if err := applyExceptions(cfg, nil, time.Now()); err == nil {
		t.Fatal("malformed exceptions file must fail closed")
	}
}

// Invalid entries (missing owner/reason/expiry) fail closed.
func TestApplyExceptionsInvalidEntryFails(t *testing.T) {
	cfg := phase1Cfg(t, "exceptions:\n  - id: EX-1\n    fingerprints: [sha256:x]\n    reason: r\n    owner: \"\"\n    expiresAt: 2099-01-01\n")
	if err := applyExceptions(cfg, nil, time.Now()); err == nil {
		t.Fatal("invalid exception entry must fail closed")
	}
}

// A valid fingerprint exception suppresses before policy, and unsuppressed
// filtering removes exactly the suppressed items.
func TestApplyExceptionsSuppressesBeforePolicy(t *testing.T) {
	cfg := phase1Cfg(t, "exceptions:\n  - id: EX-1\n    fingerprints: [sha256:abc]\n    reason: fp\n    owner: o\n    createdAt: 2026-01-01\n    expiresAt: 2099-01-01\n")
	fs := []*finding.Finding{phase1Finding("sha256:abc"), phase1Finding("sha256:other")}
	if err := applyExceptions(cfg, fs, time.Now()); err != nil {
		t.Fatal(err)
	}
	if fs[0].Suppression == nil || fs[0].Suppression.ExceptionID != "EX-1" {
		t.Fatal("valid exception did not suppress")
	}
	if fs[1].Suppression != nil {
		t.Fatal("unrelated finding must not be suppressed")
	}
	active := unsuppressed(fs)
	if len(active) != 1 || active[0].Fingerprint.Value != "sha256:other" {
		t.Fatalf("unsuppressed wrong: %+v", active)
	}
}

// Expired exceptions never suppress but are not errors.
func TestApplyExceptionsExpiredSkips(t *testing.T) {
	cfg := phase1Cfg(t, "exceptions:\n  - id: EX-1\n    fingerprints: [sha256:abc]\n    reason: fp\n    owner: o\n    createdAt: 2020-01-01\n    expiresAt: 2020-02-01\n")
	if _, err := baseline.ValidateException(baseline.Exception{}, time.Now()); err == nil {
		t.Fatal("sanity: empty exception must be invalid")
	}
	fs := []*finding.Finding{phase1Finding("sha256:abc")}
	if err := applyExceptions(cfg, fs, time.Now()); err != nil {
		t.Fatal(err)
	}
	if fs[0].Suppression != nil {
		t.Fatal("expired exception must not suppress")
	}
}

// Missing exceptions file means no exceptions (not an error).
func TestApplyExceptionsMissingFileOK(t *testing.T) {
	cfg := phase1Cfg(t, "")
	if err := applyExceptions(cfg, nil, time.Now()); err != nil {
		t.Fatalf("missing file must be OK: %v", err)
	}
}

func TestProfileTimeoutParses(t *testing.T) {
	if _, ok := profileTimeout("15m"); !ok {
		t.Fatal("15m must parse")
	}
	if _, ok := profileTimeout(""); ok {
		t.Fatal("empty must mean no enforcement")
	}
	if d, ok := profileTimeout("soon"); !ok || d <= 0 {
		t.Fatal("invalid timeout must receive enforced fallback")
	}
	if d, ok := profileTimeout("-5m"); !ok || d <= 0 {
		t.Fatal("negative timeout must receive enforced fallback")
	}
}
