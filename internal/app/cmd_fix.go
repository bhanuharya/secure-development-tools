package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/bhanuharya/secure-development-tools/internal/fix"
)

func newFixCmd() *cobra.Command {
	var from, onlyRule, patchOut string
	var apply, skipValidation bool
	cmd := &cobra.Command{
		Use:   "fix",
		Short: "Propose or apply safe mechanical remediations (never commits)",
		Long: `Dry-run by default: prints a diff of whitelisted, versioned
transforms applied to exact finding lines. --apply writes the working tree
(per-file atomic, syntax-validated). Review and commit stay human. Secret
findings are never modified.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, _, _, err := effectiveConfig()
			if err != nil {
				return err
			}
			outDir := cfg.Outputs.Directory
			if g.Output != "" {
				outDir = g.Output
			}
			if from == "" {
				from = filepath.Join(outDir, "findings.json")
			}
			rep, _, err := loadCanonical(from)
			if err != nil {
				return err
			}
			quarantine := loadQuarantine()
			matched, pre := fix.Plan(rep.Findings, quarantine, onlyRule)
			root, err := ScanRoot(cfg)
			if err != nil {
				return err
			}
			if !apply {
				edits, skipped := fix.Preview(root, matched)
				skipped = append(skipped, pre.Skipped...)
				printFixReport(cmd, edits, pre.Suggestions, skipped, pre.Quarantined, false)
				if patchOut != "" {
					if err := writeFile(patchOut, []byte(fix.Diff(edits))); err != nil {
						return err
					}
					fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", patchOut)
				}
				return nil
			}
			applied, err := fix.ApplyEdits(root, matched, skipValidation)
			if applied != nil {
				applied.Skipped = append(applied.Skipped, pre.Skipped...)
				applied.Quarantined = append(applied.Quarantined, pre.Quarantined...)
				applied.Suggestions = append(applied.Suggestions, pre.Suggestions...)
				printFixReport(cmd, applied.Edits, applied.Suggestions, applied.Skipped, applied.Quarantined, true)
			}
			if err != nil {
				return failf(ExitInternalError, "fix apply: %v", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Review the changes and commit yourself; re-run sdt scan to confirm.")
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "canonical findings.json path")
	cmd.Flags().StringVar(&onlyRule, "only", "", "restrict to one rule ID")
	cmd.Flags().StringVar(&patchOut, "patch", "", "write diff to file (dry-run)")
	cmd.Flags().BoolVar(&apply, "apply", false, "write the working tree (default: dry-run diff only)")
	cmd.Flags().BoolVar(&skipValidation, "skip-validation", false, "apply without syntax validation (not recommended)")
	return cmd
}

func printFixReport(cmd *cobra.Command, edits []fix.Edit, suggestions []fix.Suggestion, skipped, quarantined []string, applied bool) {
	mode := "dry-run (no files written)"
	if applied {
		mode = "applied to working tree (uncommitted)"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "fix: %s — %d edit(s), %d suggestion(s), %d skipped, %d quarantined\n",
		mode, len(edits), len(suggestions), len(skipped), len(quarantined))
	if len(edits) > 0 {
		fmt.Fprint(cmd.OutOrStdout(), fix.Diff(edits))
	}
	for _, s := range suggestions {
		fmt.Fprintf(cmd.OutOrStdout(), "  review %s %s (%s): %s\n", s.FindingID, s.RuleID, s.Location, s.Note)
	}
	for _, s := range skipped {
		fmt.Fprintf(cmd.OutOrStdout(), "  skip %s\n", s)
	}
	for _, q := range quarantined {
		fmt.Fprintf(cmd.OutOrStdout(), "  quarantine %s\n", q)
	}
}

// loadQuarantine reads disabled transform IDs from .secure-dev/fix-quarantine.yaml.
func loadQuarantine() map[string]bool {
	out := map[string]bool{}
	raw, err := os.ReadFile(".secure-dev/fix-quarantine.yaml")
	if err != nil {
		return out
	}
	var doc struct {
		Disabled []string `yaml:"disabled"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return out
	}
	for _, id := range doc.Disabled {
		out[id] = true
	}
	return out
}
