package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/bhanuharya/secure-development-tools/internal/baseline"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
	"github.com/bhanuharya/secure-development-tools/internal/report"
	"github.com/bhanuharya/secure-development-tools/internal/rules"
	"github.com/bhanuharya/secure-development-tools/internal/scanner"
)

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "baseline", Short: "Baseline operations"}
	var from string
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a baseline from a canonical report",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, digest, _, err := effectiveConfig()
			if err != nil {
				return err
			}
			if from == "" {
				from = filepath.Join(cfg.Outputs.Directory, "findings.json")
			}
			raw, err := os.ReadFile(from)
			if err != nil {
				return failf(ExitInvalidInput, "read report: %v", err)
			}
			var rep report.CanonicalReport
			if err := json.Unmarshal(raw, &rep); err != nil {
				return failf(ExitInvalidInput, "parse report: %v", err)
			}
			head := ""
			if out, err := gitHead(); err == nil {
				head = out
			}
			path := cfg.Baseline.File
			if path == "" {
				path = ".secure-dev/baseline.json"
			}
			_ = os.MkdirAll(filepath.Dir(path), 0o755)
			if err := baseline.Create(path, rep.Findings, digest, head); err != nil {
				return failf(ExitInternalError, "write baseline: %v", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "baseline created: %s (%d entries)\n", path, len(rep.Findings))
			return nil
		},
	}
	create.Flags().StringVar(&from, "from", "", "canonical findings.json path")
	compare := &cobra.Command{
		Use:   "compare",
		Short: "Show new, existing, and resolved states",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, _, _, err := effectiveConfig()
			if err != nil {
				return err
			}
			if from == "" {
				from = filepath.Join(cfg.Outputs.Directory, "findings.json")
			}
			raw, err := os.ReadFile(from)
			if err != nil {
				return failf(ExitInvalidInput, "read report: %v", err)
			}
			var rep report.CanonicalReport
			if err := json.Unmarshal(raw, &rep); err != nil {
				return failf(ExitInvalidInput, "parse report: %v", err)
			}
			path := cfg.Baseline.File
			if path == "" {
				path = ".secure-dev/baseline.json"
			}
			bl, err := baseline.Load(path)
			if err != nil {
				return failf(ExitInvalidInput, "load baseline: %v", err)
			}
			resolved := bl.Apply(rep.Findings)
			counts := map[string]int{}
			for _, f := range rep.Findings {
				counts[f.BaselineState]++
			}
			fmt.Fprintf(cmd.OutOrStdout(), "new=%d existing=%d resolved=%d\n", counts[finding.StateNew], counts[finding.StateExisting], len(resolved))
			for _, fp := range resolved {
				fmt.Fprintf(cmd.OutOrStdout(), "  resolved %s\n", fp)
			}
			return nil
		},
	}
	compare.Flags().StringVar(&from, "from", "", "canonical findings.json path")
	cmd.AddCommand(create, compare)
	return cmd
}

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Policy operations"}
	var from string
	test := &cobra.Command{
		Use:   "test",
		Short: "Evaluate policy against a saved canonical report",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, _, _, err := effectiveConfig()
			if err != nil {
				return err
			}
			if from == "" {
				from = filepath.Join(cfg.Outputs.Directory, "findings.json")
			}
			raw, err := os.ReadFile(from)
			if err != nil {
				return failf(ExitInvalidInput, "read report: %v", err)
			}
			var rep report.CanonicalReport
			if err := json.Unmarshal(raw, &rep); err != nil {
				return failf(ExitInvalidInput, "parse report: %v", err)
			}
			out := policy.Evaluate(cfg, rep.Findings)
			raw2, _ := json.MarshalIndent(out, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(raw2))
			if out.Status == "policy_failed" {
				return &ExitError{Code: ExitPolicyFailed, Msg: "policy_failed"}
			}
			return nil
		},
	}
	test.Flags().StringVar(&from, "from", "", "canonical findings.json path")
	cmd.AddCommand(test)
	return cmd
}

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "Rule bundle operations"}
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Validate rules, checksums, licenses, and rule tests",
		RunE: func(cmd *cobra.Command, args []string) error {
			roots := rules.RuleRoots()
			files, err := rules.DiscoverRuleFiles(roots)
			if err != nil {
				return failf(ExitInternalError, "discover rules: %v", err)
			}
			total, invalid := rules.CountRules(files)
			for _, inv := range invalid {
				fmt.Fprintln(cmd.ErrOrStderr(), "invalid "+inv)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "rules: %d files, %d rules, %d invalid\n", len(files), total, len(invalid))
			if len(files) == 0 {
				return failf(ExitInvalidInput, "no rules: visible configuration failure (no rule files found)")
			}
			if len(invalid) > 0 {
				return failf(ExitInvalidInput, "%d invalid rule files", len(invalid))
			}
			// Manifest enforcement: expected counts, per-file and bundle hashes.
			cwd, _ := os.Getwd()
			manifestPath := rules.RuleManifestPath()
			manifestProblems := []string{"manifest missing: " + manifestPath}
			if m, err := rules.LoadManifest(manifestPath); err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+err.Error())
			} else {
				manifestProblems = rules.EnforceManifest(cwd, files, m)
				for _, p := range manifestProblems {
					fmt.Fprintln(cmd.ErrOrStderr(), "manifest: "+p)
				}
			}
			if len(manifestProblems) > 0 {
				return failf(ExitInvalidInput, "%d manifest problems", len(manifestProblems))
			}
			// Engine validation + per-rule annotated tests.
			bin := scanner.OpengrepBinary()
			if bin == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: opengrep not installed; engine validation and rule tests skipped")
				return nil
			}
			var dirs []string
			for _, r := range roots {
				if fi, err := os.Stat(r); err == nil && fi.IsDir() {
					dirs = append(dirs, r)
				}
			}
			if err := rules.Validate(bin, dirs, 300); err != nil {
				return failf(ExitInvalidInput, "rule validation failed: %v", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "validate: clean")
			// Shared upstream fixtures (e.g. pickle.py covering four rules)
			// are discovered via ruleid:/ok: annotations, not just filename.
			annotationIndex := rules.IndexAnnotations(roots)
			tested, untested, failed := 0, 0, 0
			intrafile := scanner.IsOpenGrep(bin)
			for _, f := range files {
				testSet := map[string]bool{}
				for _, t := range rules.FindTests(f) {
					testSet[t] = true
				}
				for _, id := range rules.RuleIDs(f) {
					for _, t := range annotationIndex[id] {
						testSet[t] = true
					}
				}
				var tests []string
				for t := range testSet {
					tests = append(tests, t)
				}
				if len(tests) == 0 {
					untested++
					continue
				}
				if err := rules.TestRule(bin, f, tests, intrafile, 120); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "test failure %s: %v\n", f, err)
					failed++
					continue
				}
				tested++
			}
			fmt.Fprintf(cmd.OutOrStdout(), "tests: %d rule files passed, %d without tests, %d failed\n", tested, untested, failed)
			if failed > 0 {
				return failf(ExitInvalidInput, "%d rule tests failed", failed)
			}
			return nil
		},
	}
	var propFrom, propOut string
	var propTop int
	propose := &cobra.Command{
		Use:   "propose",
		Short: "Rank repeat findings and draft custom rule skeletons from history",
		Long: `Clusters saved findings by (adapter, rule, category) and writes
inert rule drafts (*.yaml.proposed, never discovered as rules) plus
annotated TP test cases built from redacted evidence. Mining proposes;
a human fills the pattern, promotes the filename, and proves it with
sdt rules verify. Secret findings contribute no evidence.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			from, outDir, top := propFrom, propOut, propTop
			cfg, _, _, _, err := effectiveConfig()
			if err != nil {
				return err
			}
			defOut := cfg.Outputs.Directory
			if g.Output != "" {
				defOut = g.Output
			}
			if from == "" {
				from = filepath.Join(defOut, "findings.json")
			}
			if outDir == "" {
				outDir = ".secure-dev/proposed"
			}
			reports, err := rules.LoadReportFindings(from)
			if err != nil {
				return failf(ExitInvalidInput, "load reports: %v", err)
			}
			clusters := rules.ClusterFindings(reports...)
			if top > 0 && len(clusters) > top {
				clusters = clusters[:top]
			}
			if len(clusters) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "propose: no findings in history; nothing to mine")
				return nil
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return failf(ExitInternalError, "create %s: %v", outDir, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "# Repeat-offender clusters (mined, human review required)")
			for i, c := range clusters {
				ruleFile, ruleYAML, testFile, testBody := rules.Skeleton(c)
				if err := os.WriteFile(filepath.Join(outDir, ruleFile), []byte(ruleYAML), 0o644); err != nil {
					return failf(ExitInternalError, "write skeleton: %v", err)
				}
				if err := os.WriteFile(filepath.Join(outDir, testFile), []byte(testBody), 0o644); err != nil {
					return failf(ExitInternalError, "write skeleton: %v", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%d. %s %s (%s, %s): %d findings, e.g. %s\n   draft: %s + %s\n",
					i+1, c.Adapter, c.RuleID, c.Category, c.Severity, c.Count,
					firstLoc(c), filepath.Join(outDir, ruleFile), testFile)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Fill patterns, rename .yaml.proposed -> .yaml under rules/, prove with sdt rules verify.\n")
			return nil
		},
	}
	propose.Flags().StringVar(&propFrom, "from", "", "findings.json file or directory of reports")
	propose.Flags().StringVar(&propOut, "out", "", "skeleton output dir (default .secure-dev/proposed)")
	propose.Flags().IntVar(&propTop, "top", 10, "propose at most N clusters")
	cmd.AddCommand(verify, propose)
	return cmd
}

func firstLoc(c rules.Cluster) string {
	if c.Example != nil && c.Example.Location != nil {
		return c.Example.Location.Path
	}
	return "-"
}
