package app

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/baseline"
	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
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
