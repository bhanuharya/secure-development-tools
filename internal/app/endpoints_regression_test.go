package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/baseline"
	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
	"github.com/bhanuharya/secure-development-tools/internal/scanner"
)

func TestEndpointProtectionRegressionBlocksDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	blPath := filepath.Join(dir, "baseline.json")

	prev := map[string]baseline.EndpointSnapshot{
		endpoints.SnapshotKey(".", "DELETE", "/api/admin/users/{id}"): {
			Service:    ".",
			Method:     "DELETE",
			Path:       "/api/admin/users/{id}",
			Protection: string(endpoints.ProtRole),
			Roles:      []string{"ADMIN"},
			File:       "main.go",
			Line:       15,
		},
	}
	if err := baseline.CreateWithEndpoints(blPath, nil, prev, "sha256:cfg", "abc123"); err != nil {
		t.Fatalf("CreateWithEndpoints: %v", err)
	}

	bl, err := baseline.Load(blPath)
	if err != nil {
		t.Fatalf("baseline.Load: %v", err)
	}
	if len(bl.Endpoints) != 1 {
		t.Fatalf("expected 1 baseline endpoint snapshot, got %d", len(bl.Endpoints))
	}

	currentInv := endpoints.Inventory{
		Schema: endpoints.Schema,
		Root:   ".",
		Routes: []endpoints.Route{
			{
				Service:    ".",
				Framework:  "gin",
				Method:     "DELETE",
				Path:       "/api/admin/users/{id}",
				Handler:    "deleteUser",
				File:       "main.go",
				Line:       15,
				Protection: endpoints.ProtPublic,
				Confidence: "high",
			},
		},
	}
	invRaw, err := json.Marshal(currentInv)
	if err != nil {
		t.Fatal(err)
	}

	regs, diag := endpointRegressions(bl, []extraArtifact{{name: "endpoints.json", data: invRaw}})
	if len(regs) != 1 {
		t.Fatalf("want 1 regression finding, got %d (diag=%q)", len(regs), diag)
	}
	if regs[0].Rule.ID != endpoints.RuleProtectionDowngraded {
		t.Fatalf("unexpected rule id: %s", regs[0].Rule.ID)
	}

	out := policy.Evaluate(config.Defaults(), regs)
	if out.Status != "policy_failed" || len(out.Blockers) != 1 {
		t.Fatalf("expected weakened endpoint to block default policy, got status=%s blockers=%d", out.Status, len(out.Blockers))
	}
}

func TestEndpointsCompareWithoutFindingsReportsAndFails(t *testing.T) {
	if scanner.OpengrepBinary() == "" {
		t.Skip("opengrep not installed")
	}
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SDT_HOME", repoRoot)

	svcDir := t.TempDir()
	src := `package main
import "github.com/gin-gonic/gin"
func main() {
	r := gin.Default()
	r.DELETE("/api/admin/users/:id", deleteUser)
}
func deleteUser(c *gin.Context) {}
`
	if err := os.WriteFile(filepath.Join(svcDir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	// Build a previous inventory where DELETE /api/admin/users/{id} required role ADMIN.
	prevInv := endpoints.Inventory{
		Schema: endpoints.Schema,
		Root:   ".",
		Routes: []endpoints.Route{
			{
				Service:    ".",
				Framework:  "gin",
				Method:     "DELETE",
				Path:       "/api/admin/users/{id}",
				Handler:    "deleteUser",
				File:       "main.go",
				Line:       5,
				Protection: endpoints.ProtRole,
				Roles:      []string{"ADMIN"},
				Confidence: "high",
			},
		},
	}
	prevRaw, err := json.Marshal(prevInv)
	if err != nil {
		t.Fatal(err)
	}
	prevPath := filepath.Join(t.TempDir(), "prev-endpoints.json")
	if err := os.WriteFile(prevPath, prevRaw, 0o644); err != nil {
		t.Fatal(err)
	}

	// Run `sdt endpoints --compare prev.json svcDir` WITHOUT --findings.
	var stdout, stderr bytes.Buffer
	cmd := newEndpointsCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--compare", prevPath, svcDir})
	runErr := cmd.Execute()
	var exitErr *ExitError
	if !errors.As(runErr, &exitErr) || exitErr.Code != ExitPolicyFailed {
		t.Fatalf("expected ExitPolicyFailed (%d) on downgrade without --findings, got %v (stderr=%q)", ExitPolicyFailed, runErr, stderr.String())
	}
	if !strings.Contains(stderr.String(), "protection regression(s)") || !strings.Contains(stderr.String(), "/api/admin/users/{id}") {
		t.Fatalf("expected regression details on stderr, got:\n%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "/api/admin/users/{id}") {
		t.Fatalf("expected inventory table on stdout, got:\n%s", stdout.String())
	}

	// Comparing against an inventory with equal protection must succeed (exit 0).
	prevInv.Routes[0].Protection = endpoints.ProtPublic
	prevInv.Routes[0].Roles = nil
	cleanRaw, err := json.Marshal(prevInv)
	if err != nil {
		t.Fatal(err)
	}
	cleanPath := filepath.Join(t.TempDir(), "clean-endpoints.json")
	if err := os.WriteFile(cleanPath, cleanRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	cmd2 := newEndpointsCmd()
	cmd2.SetOut(&stdout)
	cmd2.SetErr(&stderr)
	cmd2.SetArgs([]string{"--compare", cleanPath, svcDir})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("expected clean compare to succeed, got %v (stderr=%q)", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "no protection regressions") {
		t.Fatalf("expected no-regression summary on stderr, got:\n%s", stderr.String())
	}
}
