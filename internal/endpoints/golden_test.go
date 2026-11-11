package endpoints_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
	"github.com/bhanuharya/secure-development-tools/internal/scanner"
)

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
		})
	}
}
