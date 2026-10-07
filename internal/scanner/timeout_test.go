package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
)

func TestTaskTimeoutUsesTheConfiguredDurationElseTheDefault(t *testing.T) {
	for _, c := range []struct {
		configured string
		want       int
	}{{"", 600}, {"30m", 1800}, {"90s", 90}, {"soon", 600}, {"-5m", 600}, {"0s", 600}} {
		if got := taskTimeout(c.configured, 600); got != c.want {
			t.Errorf("taskTimeout(%q, 600) = %d, want %d", c.configured, got, c.want)
		}
	}
}

// A full-history secret scan of a large repository needs more than the default ten minutes:
// the limit set in the scan configuration is the one the task runs with.
func TestScannerPlansRunWithTheConfiguredTimeout(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"gitleaks", "trivy"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SDT_GITLEAKS_BIN", filepath.Join(dir, "gitleaks"))
	t.Setenv("SDT_TRIVY_BIN", filepath.Join(dir, "trivy"))
	ctx := testCtx()
	ctx.CacheRoot = t.TempDir()

	cfg := config.Defaults()
	secrets, err := (&GitleaksAdapter{}).PlanForProfile(ctx, cfg, "/repo", "full")
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	dependencies, err := (&TrivyFSAdapter{}).Plan(ctx, cfg, "/repo")
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if secrets.TimeoutSeconds != 600 || dependencies.TimeoutSeconds != 1200 {
		t.Fatalf("defaults changed: gitleaks %d, trivy-fs %d", secrets.TimeoutSeconds, dependencies.TimeoutSeconds)
	}

	cfg.Scanners.Gitleaks.Timeout = "30m"
	cfg.Scanners.TrivyFS.Timeout = "5m"
	secrets, _ = (&GitleaksAdapter{}).PlanForProfile(ctx, cfg, "/repo", "full")
	dependencies, _ = (&TrivyFSAdapter{}).Plan(ctx, cfg, "/repo")
	if secrets.TimeoutSeconds != 1800 || dependencies.TimeoutSeconds != 300 {
		t.Fatalf("configured timeouts not used: gitleaks %d, trivy-fs %d", secrets.TimeoutSeconds, dependencies.TimeoutSeconds)
	}
}
