package scanner

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func withRulePack(t *testing.T) {
	t.Helper()
	t.Setenv("SDT_RULES_PACK_DIR", filepath.Join(repoRoot(t), "rules", "opengrep-rules"))
}

func TestOpengrepPlanEnablesIntrafileTaint(t *testing.T) {
	withRulePack(t)
	a := &OpengrepAdapter{}
	task, err := a.Plan(testCtx(), config.Defaults(), t.TempDir())
	if err != nil {
		if strings.Contains(err.Error(), "executable not found") {
			t.Skip("opengrep not installed")
		}
		t.Fatal(err)
	}
	joined := strings.Join(task.Args, " ")
	if !strings.Contains(joined, "--taint-intrafile") {
		t.Fatalf("opengrep plan must enable intra-file taint, got: %s", joined)
	}
}

func TestOpengrepSemgrepFallbackOmitsIntrafileTaint(t *testing.T) {
	withRulePack(t)
	// Fake executable named semgrep: Plan must not pass the OpenGrep-only flag.
	fake := filepath.Join(t.TempDir(), "semgrep")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SDT_OPENGREP_BIN", fake)
	a := &OpengrepAdapter{}
	task, err := a.Plan(testCtx(), config.Defaults(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(task.Args, " "), "--taint-intrafile") {
		t.Fatalf("semgrep fallback must not receive --taint-intrafile: %v", task.Args)
	}
}

// TestTaintIntrafileFindsCrossFunctionFlow proves the flag's depth value
// end to end: a taint-mode rule whose source and sink live in different
// functions of one file fires only with the flag enabled.
func TestTaintIntrafileFindsCrossFunctionFlow(t *testing.T) {
	bin := whichBin(envOr("SDT_OPENGREP_BIN", "opengrep"))
	if bin == "" || strings.Contains(filepath.Base(bin), "semgrep") {
		t.Skip("opengrep binary not installed")
	}
	dir := filepath.Join(repoRoot(t), "testdata", "taint-demo")
	rule := filepath.Join(dir, "taint-rule.yaml")
	target := filepath.Join(dir, "app.py")
	run := func(extra ...string) int {
		t.Helper()
		cmdArgs := []string{"scan", "--json", "-q", "--timeout", "60"}
		cmdArgs = append(cmdArgs, extra...)
		cmdArgs = append(cmdArgs, "--config", rule, target)
		cmd := exec.Command(bin, cmdArgs...)
		out, err := cmd.Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok && len(out) == 0 {
				t.Fatalf("opengrep failed: %s", string(ee.Stderr))
			}
		}
		var data struct {
			Results []any `json:"results"`
		}
		if err := json.Unmarshal(out, &data); err != nil {
			t.Fatalf("invalid opengrep JSON: %v", err)
		}
		return len(data.Results)
	}
	if n := run(); n != 0 {
		t.Fatalf("single-function analysis should miss the cross-function flow, got %d findings", n)
	}
	if n := run("--taint-intrafile"); n != 1 {
		t.Fatalf("--taint-intrafile should find the cross-function flow, got %d findings", n)
	}
}
