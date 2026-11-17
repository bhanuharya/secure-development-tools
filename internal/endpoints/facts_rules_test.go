package endpoints_test

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/scanner"
)

// TestFactRules proves the fact rules load and their annotated examples pass.
// Fact rules never join the scan pack, so this is their only regression gate.
func TestFactRules(t *testing.T) {
	bin := scanner.OpengrepBinary()
	if bin == "" {
		t.Skip("opengrep not installed")
	}
	root := filepath.Join("..", "..")
	cmd := exec.Command(bin, "scan", "--test", "--config", "rules/endpoint-facts", "rules/endpoint-facts")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fact rule tests failed: %v\n%s", err, out)
	}
}
