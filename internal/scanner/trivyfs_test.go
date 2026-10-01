package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
)

// Dependency findings must reach the canonical report in full: development
// dependencies and unfixed advisories are visible at scan time and are only
// ever hidden by an explicit report filter, so the plan states both values.
func TestTrivyFSPlanKeepsDevAndUnfixedDepsVisible(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "trivy")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SDT_TRIVY_BIN", bin)
	task, err := (&TrivyFSAdapter{}).Plan(testCtx(), config.Defaults(), "/repo")
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	joined := strings.Join(task.Args, " ")
	for _, flag := range []string{"--include-dev-deps=true", "--ignore-unfixed=false"} {
		if !strings.Contains(joined, flag) {
			t.Fatalf("%s missing from trivy-fs plan: %v", flag, task.Args)
		}
	}
	for _, arg := range task.Args {
		if arg == "--ignore-unfixed" || arg == "--include-dev-deps=false" {
			t.Fatalf("trivy-fs plan must not hide findings at scan time, found %q: %v", arg, task.Args)
		}
	}
}

func TestTrivyFSPlanHonorsIgnoreFile(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "trivy")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SDT_TRIVY_BIN", bin)
	t.Setenv("SDT_TRIVY_IGNOREFILE", "/srv/trivy-ignore")
	task, err := (&TrivyFSAdapter{}).Plan(testCtx(), config.Defaults(), "/repo")
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	joined := strings.Join(task.Args, " ")
	if !strings.Contains(joined, "--ignorefile /srv/trivy-ignore") {
		t.Fatalf("--ignorefile missing from trivy-fs plan: %v", task.Args)
	}
	if !strings.HasSuffix(joined, "/repo") {
		t.Fatalf("scan root must stay last, got: %v", task.Args)
	}
}
