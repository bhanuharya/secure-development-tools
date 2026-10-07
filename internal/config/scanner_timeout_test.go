package config

import "testing"

// A scanner's time limit is the one scanner-level setting the engine acts on: it is accepted,
// checked, and survives the merge onto the defaults. Every other scanner setting is still refused.
func TestScannerTimeoutIsAcceptedAndMerged(t *testing.T) {
	cfg := mustParse(t, "scanners:\n  gitleaks:\n    timeout: 30m\n")
	if got := cfg.Scanners.Gitleaks.Timeout; got != "30m" {
		t.Fatalf("scanners.gitleaks.timeout = %q, want 30m", got)
	}
	merged := Merge(Defaults(), cfg)
	if got := merged.Scanners.Gitleaks.Timeout; got != "30m" {
		t.Fatalf("after merge scanners.gitleaks.timeout = %q, want 30m", got)
	}
	if got := merged.Scanners.Opengrep.Timeout; got != "" {
		t.Fatalf("a timeout appeared for a scanner that set none: %q", got)
	}
}

func TestInvalidScannerTimeoutFails(t *testing.T) {
	for _, value := range []string{"soon", "-5m", "0s"} {
		raw := []byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nmetadata:\n  name: t\nprofiles:\n  pr:\n    mode: changed\n    scanners: [gitleaks]\n    requiredScanners: [gitleaks]\nscanners:\n  gitleaks:\n    timeout: " + value + "\n")
		if _, _, err := Parse(raw, "test"); err == nil {
			t.Fatalf("scanner timeout %q must fail closed", value)
		}
	}
}

func TestOtherScannerSettingsAreStillRefused(t *testing.T) {
	raw := []byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nmetadata:\n  name: t\nprofiles:\n  pr:\n    mode: changed\n    scanners: [gitleaks]\n    requiredScanners: [gitleaks]\nscanners:\n  opengrep:\n    exclude: [\"vendor/**\"]\n")
	if _, _, err := Parse(raw, "test"); err == nil {
		t.Fatal("an unimplemented scanner setting must still fail closed")
	}
}
