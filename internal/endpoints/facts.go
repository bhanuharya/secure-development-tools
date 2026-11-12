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

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/execute"
)

// Fact is one engine result: what kind of fact, where, and its metavariables.
type Fact struct {
	Kind     string
	File     string // slash path relative to the scanned root
	Line     int
	Column   int // keeps several rules on one line in source order
	EndLine  int // last line of the match; scoping facts (chi.Route) need it
	Metavars map[string]string
	// MetavarLines is the source line of each metavariable. A rule whose match
	// span starts at a preceding annotation still reports the annotation's own
	// line, which is what evidence must name.
	MetavarLines map[string]int
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

// factExcludes keeps generated trees, frontend assets and test files out of
// the inventory: fixtures and tests register routes too, but they are not the
// service's API. The resolver repeats the JS path half for facts it is handed
// directly (jsFileExcluded).
var factExcludes = []string{
	".git/*", "node_modules/*", "vendor/*", "dist/*", "build/*",
	"*.jsx", "*.tsx", "**/src/main/webapp/**", "**/public/**", "**/static/**",
	"**/test/**", "**/tests/**", "**/__tests__/**",
	"*_test.go", "*.spec.*", "*.test.*",
}

// factRunTimeout bounds one fact-engine invocation.
const factRunTimeout = 2 * time.Minute

// factOutputGrace bounds pipe draining after the engine exits or its deadline
// stops it. A launcher's child that escaped the process group must not keep the
// inventory waiting.
const factOutputGrace = time.Second

// RunFacts runs the fact rules over dir and returns parsed facts.
func RunFacts(dir string) ([]Fact, error) {
	return runFactsWithTimeout(dir, factRunTimeout)
}

func runFactsWithTimeout(dir string, timeout time.Duration) ([]Fact, error) {
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

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = absDir
	// opengrep 1.29 dropped --metrics; the env var is the equivalent for the
	// semgrep fallback and keeps the run offline (SPEC §3).
	cmd.Env = append(os.Environ(), "SEMGREP_SEND_METRICS=off")
	// The engine may be a launcher whose children hold the output pipes. Stop
	// the whole group at the deadline and bound the wait for those pipes, so
	// the fact run returns even when an orphan outlives the launcher.
	execute.OwnProcessGroup(cmd)
	cmd.WaitDelay = factOutputGrace
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("opengrep timed out after %s", timeout)
		}
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
				Col  int `json:"col"`
			} `json:"start"`
			End struct {
				Line int `json:"line"`
			} `json:"end"`
			Extra struct {
				Metadata struct {
					Fact string `json:"fact"`
				} `json:"metadata"`
				Metavars map[string]struct {
					AbstractContent string `json:"abstract_content"`
					Start           struct {
						Line int `json:"line"`
					} `json:"start"`
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
		lines := make(map[string]int, len(r.Extra.Metavars))
		for name, v := range r.Extra.Metavars {
			mv[name] = v.AbstractContent
			lines[name] = v.Start.Line
		}
		facts = append(facts, Fact{Kind: kind, File: relFile(root, r.Path), Line: r.Start.Line, Column: r.Start.Col, EndLine: r.End.Line, Metavars: mv, MetavarLines: lines})
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
// cfg supplies the extra gate names, so a middleware unknown to the defaults
// can still protect a route (SPEC §7).
func BuildInventory(dir string, cfg config.EndpointsCfg) (*Inventory, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	facts, err := RunFacts(absDir)
	if err != nil {
		return nil, err
	}
	routes, unresolved := resolveFacts(facts, absDir, newGateMatcher(cfg.AuthGates))
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
