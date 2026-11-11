package endpoints_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
	"github.com/bhanuharya/secure-development-tools/internal/scanner"
)

// goldenFinding is the compact projection of a convention finding that
// expected-findings.json stores (rule id, file, line, endpoint only).
type goldenFinding struct {
	Rule     string `json:"rule"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Endpoint string `json:"endpoint"`
}

// TestGoldenInventories runs the inventory for every testdata/endpoints/<case>
// that ships an expected.json and compares the whole document. Golden fixtures
// are the contract: fix the resolver, not the expectation, when they drift.
func TestGoldenInventories(t *testing.T) {
	if scanner.OpengrepBinary() == "" {
		t.Skip("opengrep not installed")
	}
	root := filepath.Join("..", "..", "testdata", "endpoints")
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	// The test binary has no checkout beside it; point the fact-rule lookup at
	// the repository under test (same knob operators use in packaged installs).
	t.Setenv("SDT_HOME", repoRoot)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		expectedPath := filepath.Join(dir, "expected.json")
		raw, err := os.ReadFile(expectedPath)
		if err != nil {
			continue // not a golden case
		}
		t.Run(e.Name(), func(t *testing.T) {
			var want endpoints.Inventory
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatalf("expected.json: %v", err)
			}
			got, err := endpoints.BuildInventory(dir)
			if err != nil {
				t.Fatalf("BuildInventory: %v", err)
			}
			if !reflect.DeepEqual(got.Routes, want.Routes) ||
				!reflect.DeepEqual(got.Summary, want.Summary) ||
				!reflect.DeepEqual(got.Unresolved, want.Unresolved) ||
				got.Schema != want.Schema || got.Root != want.Root {
				g, _ := json.MarshalIndent(got, "", "  ")
				w, _ := json.MarshalIndent(want, "", "  ")
				t.Fatalf("inventory mismatch\n--- got ---\n%s\n--- want ---\n%s", g, w)
			}
			compareFindings(t, dir, got)
		})
	}
}

func compareFindings(t *testing.T, dir string, inv *endpoints.Inventory) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "expected-findings.json"))
	if err != nil {
		return // the case does not pin convention findings
	}
	var want []goldenFinding
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("expected-findings.json: %v", err)
	}
	findings, err := endpoints.Analyze(inv, config.Defaults().Endpoints)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	got := make([]goldenFinding, 0, len(findings))
	for _, f := range findings {
		line := 0
		file := ""
		if f.Location != nil {
			file = f.Location.Path
			if f.Location.StartLine != nil {
				line = *f.Location.StartLine
			}
		}
		endpoint, _ := f.Metadata["endpoint"].(string)
		got = append(got, goldenFinding{Rule: f.Rule.ID, File: file, Line: line, Endpoint: endpoint})
	}
	if !reflect.DeepEqual(got, want) {
		g, _ := json.MarshalIndent(got, "", "  ")
		w, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("findings mismatch\n--- got ---\n%s\n--- want ---\n%s", g, w)
	}
}
