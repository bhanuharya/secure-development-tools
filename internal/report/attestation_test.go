package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/plan"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
)

func TestToAttestationBuildsValidInTotoV1Statement(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "fake-opengrep")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\necho opengrep\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	manifest := Manifest{
		SchemaVersion: "secure-dev/manifest/v1alpha1",
		RunID:         "run-123",
		PlanID:        "plan-456",
		Profile:       "pr",
		Mode:          "changed",
		Status:        "passed",
		ExitCode:      0,
		StartedAt:     "2026-01-01T00:00:00Z",
		CompletedAt:   "2026-01-01T00:00:05Z",
		ContextDigest: "sha256:ctx",
		ConfigDigest:  "sha256:cfg",
		PolicyDigest:  "sha256:pol",
		PlanDigest:    "sha256:pln",
		Tools: []ToolIdentity{
			{Adapter: "opengrep", Tool: "opengrep", Version: "1.29.0"},
		},
		Artifacts: []ArtifactRec{
			{Path: "findings.json", Checksum: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Status: "generated"},
			{Path: "failed.sarif", Checksum: "sha256:bbbb", Status: "failed: disk full"},
		},
		Findings: FindingCounts{Total: 1},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	p := &plan.Plan{
		Tasks: []plan.Task{
			{Adapter: "opengrep", Executable: binPath},
		},
	}
	out := policy.Outcome{
		Blockers: []policy.Match{{FindingID: "f1", RuleID: "block-new-high-sast", Action: "fail"}},
	}

	raw, err := ToAttestation(manifest, manifestBytes, p, out)
	if err != nil {
		t.Fatalf("ToAttestation: %v", err)
	}
	// JSONL: single line terminated with '\n'.
	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatalf("expected trailing newline for JSONL")
	}
	if bytes.Count(bytes.TrimRight(raw, "\n"), []byte("\n")) != 0 {
		t.Fatalf("expected single-line JSONL statement")
	}

	var stmt InTotoStatement
	if err := json.Unmarshal(raw, &stmt); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}
	if stmt.Type != InTotoStatementType {
		t.Fatalf("unexpected _type: %q", stmt.Type)
	}
	if stmt.PredicateType != ScanPredicateType {
		t.Fatalf("unexpected predicateType: %q", stmt.PredicateType)
	}
	// Expect run-manifest.json + generated findings.json (failed artifact excluded).
	if len(stmt.Subject) != 2 {
		t.Fatalf("expected 2 subjects, got %d: %+v", len(stmt.Subject), stmt.Subject)
	}
	if stmt.Subject[0].Name != "run-manifest.json" || len(stmt.Subject[0].Digest["sha256"]) != 64 {
		t.Fatalf("unexpected first subject: %+v", stmt.Subject[0])
	}
	if stmt.Subject[1].Name != "findings.json" || stmt.Subject[1].Digest["sha256"] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("unexpected second subject: %+v", stmt.Subject[1])
	}
	if len(stmt.Predicate.Tools) != 1 || len(stmt.Predicate.Tools[0].BinarySHA256) != 64 {
		t.Fatalf("expected attested binary SHA-256 for opengrep, got %+v", stmt.Predicate.Tools)
	}
	if stmt.Predicate.Blockers != 1 || stmt.Predicate.PolicyDigest != "sha256:pol" {
		t.Fatalf("unexpected predicate verdict/digests: %+v", stmt.Predicate)
	}
}
