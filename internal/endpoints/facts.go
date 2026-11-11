package endpoints

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Fact is one engine result: what kind of fact, where, and its metavariables.
type Fact struct {
	Kind     string
	File     string // slash path relative to the scanned root
	Line     int
	Metavars map[string]string
}

// factRulesDir resolves rules/endpoint-facts: $SDT_HOME, then the checkout
// around the executable (like rulePackOfExecutable), then the working tree.
// Kept local on purpose: internal/endpoints must not import internal/scanner,
// or the T09 adapter registration would create an import cycle.
func factRulesDir() (string, error) {
	isDir := func(p string) bool {
		info, err := os.Stat(p)
		return err == nil && info.IsDir()
	}
	if home := os.Getenv("SDT_HOME"); home != "" {
		if p := filepath.Join(home, "rules", "endpoint-facts"); isDir(p) {
			return p, nil
		}
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		dir := filepath.Dir(exe)
		for level := 0; level < 4; level++ {
			if p := filepath.Join(dir, "rules", "endpoint-facts"); isDir(p) {
				return p, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if p := filepath.Join("rules", "endpoint-facts"); isDir(p) {
		return p, nil
	}
	return "", fmt.Errorf("rules/endpoint-facts not found (set SDT_HOME or run from the checkout)")
}

// opengrepBinary mirrors the scan engine lookup: env override, then opengrep,
// then semgrep. Empty when neither is installed.
func opengrepBinary() string {
	if bin := os.Getenv("SDT_OPENGREP_BIN"); bin != "" {
		if _, err := exec.LookPath(bin); err == nil {
			return bin
		}
		return ""
	}
	for _, name := range []string{"opengrep", "semgrep"} {
		if bin, err := exec.LookPath(name); err == nil {
			return bin
		}
	}
	return ""
}

// factExcludes keeps generated trees and test files out of the inventory:
// fixtures and tests register routes too, but they are not the service's API.
var factExcludes = []string{
	".git/*", "node_modules/*", "vendor/*", "dist/*", "build/*",
	"**/test/**", "**/tests/**", "**/__tests__/**",
	"*_test.go", "*.spec.*", "*.test.*",
}

// RunFacts runs the fact rules over dir and returns parsed facts.
func RunFacts(dir string) ([]Fact, error) {
	bin := opengrepBinary()
	if bin == "" {
		return nil, fmt.Errorf("opengrep is not installed (set SDT_OPENGREP_BIN)")
	}
	rules, err := factRulesDir()
	if err != nil {
		return nil, err
	}
	rules, err = filepath.Abs(rules)
	if err != nil {
		return nil, err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	args := []string{"scan", "--json", "--quiet", "--no-git-ignore"}
	for _, x := range factExcludes {
		args = append(args, "--exclude", x)
	}
	args = append(args, "--config", rules, ".")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = absDir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		// 0 = clean, 1 = facts found; anything else is an engine failure.
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			// Fall through: stdout still carries the results.
		} else {
			return nil, fmt.Errorf("opengrep failed: %v: %s", err, tail(stderr.String(), 400))
		}
	}
	return parseFacts(out, absDir)
}

func parseFacts(raw []byte, root string) ([]Fact, error) {
	var doc struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			Extra struct {
				Metadata struct {
					Fact string `json:"fact"`
				} `json:"metadata"`
				Metavars map[string]struct {
					AbstractContent string `json:"abstract_content"`
				} `json:"metavars"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("opengrep returned invalid JSON: %w", err)
	}
	var facts []Fact
	for _, r := range doc.Results {
		kind := r.Extra.Metadata.Fact
		if kind == "" {
			continue // not a fact rule result
		}
		mv := make(map[string]string, len(r.Extra.Metavars))
		for name, v := range r.Extra.Metavars {
			mv[name] = v.AbstractContent
		}
		facts = append(facts, Fact{Kind: kind, File: relFile(root, r.Path), Line: r.Start.Line, Metavars: mv})
	}
	return facts, nil
}

// relFile makes an engine path relative to the scanned dir, with slashes.
func relFile(root, p string) string {
	if filepath.IsAbs(p) {
		if rel, err := filepath.Rel(root, p); err == nil {
			p = rel
		}
	}
	p = filepath.ToSlash(filepath.Clean(p))
	return strings.TrimPrefix(p, "./")
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// BuildInventory runs the facts, resolves them into routes, and sorts the result.
func BuildInventory(dir string) (*Inventory, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	facts, err := RunFacts(absDir)
	if err != nil {
		return nil, err
	}
	routes, unresolved := resolveGo(facts, absDir)
	sort.Slice(routes, func(i, j int) bool {
		a, b := routes[i], routes[j]
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Method < b.Method
	})
	summary := map[string]int{}
	for _, r := range routes {
		summary[string(r.Protection)]++
	}
	return &Inventory{
		Schema:     Schema,
		Root:       ".",
		Routes:     routes,
		Summary:    summary,
		Unresolved: unresolved,
	}, nil
}
