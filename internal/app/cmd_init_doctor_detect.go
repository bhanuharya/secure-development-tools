package app

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bhanuharya/secure-development-tools/internal/detect"
	"github.com/bhanuharya/secure-development-tools/internal/rules"
	"github.com/bhanuharya/secure-development-tools/internal/scanner"
)

// gitToplevel returns the enclosing worktree root for the process CWD.
func gitToplevel() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

const preCommitHook = `#!/bin/sh
# sdt pre-commit hook (managed by "sdt init --hook"). Fast staged scan.
# Bypass for a single commit: SKIP_SDT=1 git commit ...
# CI remains the authoritative gate; this hook is the fast net.
if [ "${SKIP_SDT:-0}" = "1" ]; then exit 0; fi
if ! command -v sdt >/dev/null 2>&1; then
  echo "sdt: not on PATH, skipping pre-commit scan (CI remains the gate)" >&2
  exit 0
fi
exec sdt scan --staged
`

func newInitCmd() *cobra.Command {
	var force, dryRun, hook bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create starter configuration after preview",
		RunE: func(cmd *cobra.Command, args []string) error {
			starter := `apiVersion: secure-dev/v1alpha1
kind: ScanConfiguration
metadata:
  name: repository-default
project:
  root: .
  defaultBranch: main
profiles:
  pr:
    mode: changed
    scanners: [opengrep, gitleaks, trivy-fs]
    requiredScanners: [opengrep, gitleaks, trivy-fs]
    timeout: 15m
    parallelism: 3
    missingHistory: fail
  full:
    mode: repository
    scanners: [opengrep, gitleaks, trivy-fs]
    requiredScanners: [opengrep, gitleaks, trivy-fs]
    timeout: 45m
    parallelism: 3
    missingHistory: fail
  release:
    mode: repository
    scanners: [opengrep, gitleaks, trivy-fs, trivy-image]
    requiredScanners: [opengrep, gitleaks, trivy-fs, trivy-image]
    requireImage: true
    timeout: 60m
    parallelism: 2
    updateMode: locked
`
			fmt.Fprintln(cmd.OutOrStdout(), "Proposed .secure-dev.yaml:")
			fmt.Fprintln(cmd.OutOrStdout(), starter)
			if dryRun {
				return nil
			}
			if _, err := os.Stat(".secure-dev.yaml"); err == nil && !force {
				return failf(ExitInvalidInput, ".secure-dev.yaml exists (use --force to overwrite)")
			}
			if err := os.WriteFile(".secure-dev.yaml", []byte(starter), 0o644); err != nil {
				return failf(ExitInternalError, "write config: %v", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "wrote .secure-dev.yaml")
			if !hook {
				return nil
			}
			hookPath, err := installHook(force)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (bypass: SKIP_SDT=1 git commit ...)\n", hookPath)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing config")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview only")
	cmd.Flags().BoolVar(&hook, "hook", false, "also install a pre-commit hook running `sdt scan --staged`")
	return cmd
}

// installHook writes the pre-commit hook into the current repo's .git/hooks.
func installHook(force bool) (string, error) {
	top, err := gitToplevel()
	if err != nil {
		return "", failf(ExitInvalidInput, "init --hook needs a git worktree: %v", err)
	}
	hookPath := filepath.Join(top, ".git", "hooks", "pre-commit")
	if _, err := os.Stat(hookPath); err == nil && !force {
		return "", failf(ExitInvalidInput, "%s exists (use --force to overwrite)", hookPath)
	}
	if err := os.WriteFile(hookPath, []byte(preCommitHook), 0o755); err != nil {
		return "", failf(ExitInternalError, "write hook: %v", err)
	}
	return hookPath, nil
}

func newDoctorCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Validate environment and explain blockers",
		RunE: func(cmd *cobra.Command, args []string) error {
			type check struct {
				Name   string `json:"name"`
				OK     bool   `json:"ok"`
				Detail string `json:"detail"`
			}
			var checks []check
			cwd, _ := os.Getwd()
			// Git context.
			facts := detect.Inspect(cwd)
			checks = append(checks, check{"git", facts.HasGit, boolStr(facts.HasGit, "worktree", "not a git worktree")})
			checks = append(checks, check{"history", !facts.Shallow, boolStr(!facts.Shallow, "complete", "shallow clone detected")})
			// Config.
			_, _, _, _, err := effectiveConfig()
			checks = append(checks, check{"config", err == nil, errStr(err)})
			// Tools.
			for _, id := range scanner.All() {
				a, ok := scanner.Lookup(id)
				if !ok {
					continue
				}
				_, tool, _ := a.Identity()
				bin := findBin(tool)
				checks = append(checks, check{"tool:" + id, bin != "", binOrMissing(bin, tool)})
			}
			// Rules.
			rules := countRules(cwd)
			checks = append(checks, check{"rules", rules > 0, fmt.Sprintf("%d rule files", rules)})
			// Paths.
			for _, p := range []string{g.Output, g.Cache} {
				e := os.MkdirAll(p, 0o755)
				checks = append(checks, check{"path:" + p, e == nil, errStr(e)})
			}
			ok := true
			for _, c := range checks {
				if !c.OK && (c.Name == "git" || c.Name == "config") {
					ok = false
				}
			}
			if jsonOut {
				raw, _ := json.MarshalIndent(checks, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(raw))
			} else {
				for _, c := range checks {
					mark := "ok"
					if !c.OK {
						mark = "BLOCKED"
					}
					fmt.Fprintf(cmd.OutOrStdout(), "%-16s %-7s %s\n", c.Name, mark, c.Detail)
				}
			}
			if !ok {
				return failf(ExitInvalidInput, "doctor found blockers")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")
	return cmd
}

func newDetectCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "detect",
		Short: "List repository capabilities and applicable scanners",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, _ := os.Getwd()
			facts := detect.Inspect(cwd)
			type row struct {
				Scanner string `json:"scanner"`
				State   string `json:"state"`
				Reason  string `json:"reason"`
			}
			var rows []row
			for _, id := range scanner.All() {
				a, ok := scanner.Lookup(id)
				if !ok {
					continue
				}
				app := a.Detect(cwd, facts.Languages)
				rows = append(rows, row{id, app.State, app.Reason})
			}
			if jsonOut {
				raw, _ := json.MarshalIndent(map[string]any{"facts": facts, "scanners": rows}, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(raw))
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "languages: %v manifests: %v iac=%v shallow=%v\n", facts.Languages, facts.Manifests, facts.HasIaC, facts.Shallow)
			for _, r := range rows {
				fmt.Fprintf(cmd.OutOrStdout(), "  %-12s %-14s %s\n", r.Scanner, r.State, r.Reason)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")
	return cmd
}

func boolStr(ok bool, t, f string) string {
	if ok {
		return t
	}
	return f
}

func errStr(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func binOrMissing(bin, tool string) string {
	if bin != "" {
		return bin
	}
	return tool + " not on PATH"
}

func countRules(root string) int {
	// Authoritative recursive discovery, same roots `rules verify` uses.
	// (An earlier two-level directory count reported e.g. 24 files while
	// verify saw 137 — same bundle, different ruler. Never again.)
	files, err := rules.DiscoverRuleFiles(rules.RuleRoots())
	if err != nil || len(files) == 0 {
		return fallbackShallowCount(root)
	}
	return len(files)
}

func fallbackShallowCount(root string) int {
	n := 0
	for _, d := range []string{filepath.Join(root, "rules", "opengrep-rules"), "rules/opengrep-rules", filepath.Join(root, ".secure-dev", "rules")} {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				n++
			}
		}
		// Count one level deep.
		for _, e := range entries {
			if e.IsDir() {
				sub, _ := os.ReadDir(filepath.Join(d, e.Name()))
				n += len(sub)
			}
		}
		if n > 0 {
			return n
		}
	}
	return n
}
