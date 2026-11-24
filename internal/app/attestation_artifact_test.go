package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/plan"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
	"github.com/bhanuharya/secure-development-tools/internal/report"
)

func TestWriteArtifactsEmitsInTotoAttestationWhenEnabled(t *testing.T) {
	outDir := t.TempDir()
	cfg := config.Defaults()
	cfg.Outputs.Directory = outDir
	cfg.Runtime.CacheDirectory = t.TempDir()
	cfg.Outputs.Formats = append(cfg.Outputs.Formats, "attestation")

	p := &plan.Plan{
		PlanID:        "plan-att-1",
		Profile:       "pr",
		Mode:          "changed",
		ContextDigest: "sha256:ctx",
		ConfigDigest:  "sha256:cfg",
		PlanDigest:    "sha256:pln",
	}
	err := writeArtifacts(
		nil, cfg, p, "run-att-1", time.Now().UTC(),
		nil, nil, nil,
		map[string]string{"endpoints": "completed"},
		map[string]string{"endpoints": "builtin"},
		policy.Outcome{Status: "passed"},
		"passed", 0, nil,
	)
	if err != nil {
		t.Fatalf("writeArtifacts: %v", err)
	}

	attPath := filepath.Join(outDir, "run-attestation.intoto.jsonl")
	raw, err := os.ReadFile(attPath)
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	var stmt report.InTotoStatement
	if err := json.Unmarshal(raw, &stmt); err != nil {
		t.Fatalf("unmarshal attestation: %v", err)
	}
	if stmt.Type != report.InTotoStatementType || stmt.PredicateType != report.ScanPredicateType {
		t.Fatalf("unexpected statement types: %q / %q", stmt.Type, stmt.PredicateType)
	}
	foundManifest := false
	for _, s := range stmt.Subject {
		if s.Name == "run-manifest.json" && len(s.Digest["sha256"]) == 64 {
			foundManifest = true
		}
	}
	if !foundManifest {
		t.Fatalf("expected run-manifest.json sha256 subject in attestation: %+v", stmt.Subject)
	}
}
