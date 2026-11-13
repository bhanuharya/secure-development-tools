package scanner

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
)

// The adapter runs the inventory in process during Plan and hands the native
// report to Parse: no executable is spawned, the finding is the §6 rule, and
// the inventory becomes the endpoints.json artifact.
func TestEndpointsAdapterPlansInProcess(t *testing.T) {
	if OpengrepBinary() == "" {
		t.Skip("opengrep not installed")
	}
	t.Setenv("SDT_HOME", repoRoot(t))
	root := filepath.Join(repoRoot(t), "testdata", "detection", "endpoints", "transfer")
	adapter := &EndpointsAdapter{}
	task, err := adapter.Plan(testCtx(), config.Defaults(), root)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if task.Executable != "" || task.Stdout == nil {
		t.Fatalf("expected an in-process report, got executable %q", task.Executable)
	}
	parsed := adapter.Parse("test", root, task.Stdout, "", 0)
	if parsed.Health != HealthCompleted {
		t.Fatalf("Parse health = %s: %v", parsed.Health, parsed.Diagnostics)
	}
	if len(parsed.Findings) != 1 || parsed.Findings[0].Rule.ID != endpoints.RuleSensitiveRoutePublic {
		t.Fatalf("findings = %+v", parsed.Findings)
	}
	if len(parsed.Artifacts) != 1 || parsed.Artifacts[0].Name != "endpoints.json" {
		t.Fatalf("artifacts = %+v", parsed.Artifacts)
	}
	var inventory endpoints.Inventory
	if err := json.Unmarshal(parsed.Artifacts[0].Data, &inventory); err != nil {
		t.Fatalf("endpoints.json: %v", err)
	}
	if inventory.Schema != endpoints.Schema || len(inventory.Routes) != 7 {
		t.Fatalf("inventory = %s with %d routes", inventory.Schema, len(inventory.Routes))
	}
}

func TestEndpointsAdapterRejectsMissingReport(t *testing.T) {
	parsed := (&EndpointsAdapter{}).Parse("test", ".", []byte("not json"), "", 0)
	if parsed.Health != HealthMalformed {
		t.Fatalf("health = %s, want malformed", parsed.Health)
	}
}
