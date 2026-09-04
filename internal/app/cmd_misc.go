package app

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/bhanuharya/secure-development-tools/internal/publish"
	"github.com/bhanuharya/secure-development-tools/internal/report"
	"github.com/bhanuharya/secure-development-tools/internal/version"
)

// loadCanonical reads a saved findings.json and its sibling manifest status.
func loadCanonical(path string) (*report.CanonicalReport, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", failf(ExitInvalidInput, "read report %s: %v (run scan first)", path, err)
	}
	var rep report.CanonicalReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, "", failf(ExitInvalidInput, "parse report: %v", err)
	}
	status := rep.Status
	if mraw, err := os.ReadFile(filepath.Join(filepath.Dir(path), "run-manifest.json")); err == nil {
		var m struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(mraw, &m) == nil && m.Status != "" {
			status = m.Status
		}
	}
	return &rep, status, nil
}

func writeFile(path string, data []byte) error {
	if err := report.WriteAtomic(path, data, 0o644); err != nil {
		return failf(ExitInternalError, "write %s: %v", path, err)
	}
	return nil
}

func newPublishCmd() *cobra.Command {
	var provider, from string
	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Publish saved results to a provider (no rescan)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, _, _, err := effectiveConfig()
			if err != nil {
				return err
			}
			if !cfg.Publish.Enabled {
				return failf(ExitInvalidInput, "publish is disabled (publish.enabled=false)")
			}
			if provider == "" || provider == "auto" {
				provider = cfg.Publish.Provider
			}
			outDir := cfg.Outputs.Directory
			if g.Output != "" {
				outDir = g.Output
			}
			if from == "" {
				from = outDir + "/findings.json"
			}
			rep, manifestStatus, err := loadCanonical(from)
			if err != nil {
				return err
			}
			var ids []string
			for _, b := range rep.Policy.Blockers {
				ids = append(ids, b.FindingID)
			}
			blockers := publish.Blockers(ids)
			switch provider {
			case "github":
				anns, summary := publish.GitHub(rep.Findings, blockers, manifestStatus)
				if err := writeFile(outDir+"/github-annotations.json", anns); err != nil {
					return err
				}
				if err := writeFile(outDir+"/github-step-summary.md", []byte(summary)); err != nil {
					return err
				}
			case "bitbucket":
				if err := writeFile(outDir+"/bitbucket-code-insights.json", publish.Bitbucket(rep.Findings, blockers, manifestStatus)); err != nil {
					return err
				}
			case "gitlab":
				if err := writeFile(outDir+"/gitlab-codequality.json", publish.GitLab(rep.Findings, blockers)); err != nil {
					return err
				}
			default:
				return failf(ExitInvalidInput, "unsupported provider %q (want github|bitbucket|gitlab)", provider)
			}
			// Publication never rewrites the recorded scan decision.
			fmt.Fprintf(cmd.OutOrStdout(), "publish: provider=%s status=%s findings=%d (recorded decision unchanged)\n", provider, manifestStatus, len(rep.Findings))
			return nil
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "", "provider name (github|bitbucket|gitlab)")
	cmd.Flags().StringVar(&from, "from", "", "canonical findings.json path")
	return cmd
}

func newExplainCmd() *cobra.Command {
	var findingID, from string
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Generate optional advisory explanation (opt-in, never authoritative)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, _, _, err := effectiveConfig()
			if err != nil {
				return err
			}
			if !cfg.AI.Enabled {
				return failf(ExitInvalidInput, "ai is disabled by default (ai.enabled=false); no explanation generated")
			}
			outDir := cfg.Outputs.Directory
			if g.Output != "" {
				outDir = g.Output
			}
			if from == "" {
				from = outDir + "/findings.json"
			}
			rep, status, err := loadCanonical(from)
			if err != nil {
				return err
			}
			targets := rep.Findings
			if findingID != "" {
				targets = nil
				for _, f := range rep.Findings {
					if f.ID == findingID || f.Fingerprint.Value == findingID {
						targets = append(targets, f)
					}
				}
				if len(targets) == 0 {
					return failf(ExitInvalidInput, "finding %q not in report", findingID)
				}
			}
			doc := explainDoc(cfg, targets, status)
			dest := outDir + "/ai-explanation.md"
			if err := writeFile(dest, []byte(doc)); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), doc)
			return nil
		},
	}
	cmd.Flags().StringVar(&findingID, "finding", "", "finding ID or fingerprint to explain (default: all)")
	cmd.Flags().StringVar(&from, "from", "", "canonical findings.json path")
	return cmd
}

func newVersionCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Report CLI, schema, adapters, and bundled tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := map[string]any{
				"cli":      version.CLI,
				"schema":   version.Schema,
				"finding":  version.Finding,
				"manifest": version.Manifest,
				"adapters": version.Adapters(),
			}
			if jsonOut {
				raw, _ := json.MarshalIndent(info, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(raw))
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "sdt %s (schema %s)\n", version.CLI, version.Schema)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")
	return cmd
}

func gitHead() (string, error) {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	s := string(out)
	if len(s) > 40 {
		s = s[:40]
	}
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	return s, nil
}

func findBin(tool string) string {
	for _, name := range []string{tool} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	// opengrep falls back to semgrep.
	if tool == "opengrep" {
		if p, err := exec.LookPath("semgrep"); err == nil {
			return p
		}
	}
	return ""
}
