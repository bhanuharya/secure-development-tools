package app

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
	"github.com/bhanuharya/secure-development-tools/internal/plan"
	"github.com/bhanuharya/secure-development-tools/internal/scanner"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Configuration operations"}
	cmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate schema and referenced files",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, path, digest, warns, err := effectiveConfig()
			if err != nil {
				return err
			}
			for _, w := range warns {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+w)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "config valid (%s) digest=%s profiles=%d\n", pathOrDefault(path), digest, len(cfg.Profiles))
			return nil
		},
	})
	var showEffective bool
	show := &cobra.Command{
		Use:   "show",
		Short: "Render effective redacted configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, _, warns, err := effectiveConfig()
			if err != nil {
				return err
			}
			for _, w := range warns {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+w)
			}
			raw, _ := yaml.Marshal(cfg)
			fmt.Fprintln(cmd.OutOrStdout(), string(raw))
			return nil
		},
	}
	show.Flags().BoolVar(&showEffective, "effective", false, "render merged effective config")
	cmd.AddCommand(show)
	return cmd
}

func newPlanCmd() *cobra.Command {
	var dryRun bool
	var out string
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Create the immutable scan plan without execution",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, _, warns, err := effectiveConfig()
			if err != nil {
				return err
			}
			for _, w := range warns {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+w)
			}
			prof, ok := cfg.Profiles[g.Profile]
			if !ok {
				return failf(ExitInvalidInput, "unknown profile %q", g.Profile)
			}
			ctx, cwarns, err := resolveContext(cfg)
			if err != nil {
				return err
			}
			for _, w := range cwarns {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+w)
			}
			if prof.RequireImage && ctx.ImageReference == "" && g.Image == "" {
				// Image comes from flag/env; resolveContext doesn't set it. Check here.
				return failf(ExitInvalidInput, "profile %q requires an image reference (--image or SDT_IMAGE)", g.Profile)
			}
			if g.Image != "" {
				ctx.ImageReference = g.Image
			}
			root, err := ScanRoot(cfg)
			if err != nil {
				return err
			}
			pendingReportPaths = map[string]string{}
			tasks, skipped := planTasks(cfg, g.Profile, ctx, root)
			// Fail closed like scan: changed profiles need a merge base,
			// and an empty task set must never read as a clean plan.
			if prof.Mode == "changed" && !ctx.Staged && ctx.MergeBase == "" {
				return failf(ExitInvalidInput, "profile %q mode changed requires a merge base (--base or SDT_BASE resolving to a merge-base with --head); refusing unbounded fallback", g.Profile)
			}
			if len(tasks) == 0 {
				return failf(ExitInvalidInput, "profile %q produced zero effective scanners; refusing empty plan", g.Profile)
			}
			// Planning must not execute anything: drop the empty report
			// placeholders created while resolving task arguments.
			for _, rp := range pendingReportPaths {
				_ = os.Remove(rp)
			}
			pendingReportPaths = map[string]string{}
			p, err := plan.Build(cfg, g.Profile, ctx, tasks, skipped)
			if err != nil {
				return err
			}
			raw, _ := json.MarshalIndent(p, "", "  ")
			if out != "" {
				if err := os.WriteFile(out, append(raw, '\n'), 0o644); err != nil {
					return failf(ExitInternalError, "write plan: %v", err)
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(raw))
			_ = dryRun
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "validate and plan only (default behavior)")
	cmd.Flags().StringVar(&out, "out", "", "write plan JSON to file")
	return cmd
}

// planTasks runs adapter validate/detect/plan for profile scanners.
func planTasks(cfg *config.ScanConfiguration, profile string, ctx *sdtctx.ScanContext, root string) ([]plan.Task, []plan.Skip) {
	return planTasksFull(cfg, profile, ctx, root)
}

func pathOrDefault(p string) string {
	if p == "" {
		return "(compiled defaults)"
	}
	return p
}

var _ = json.Marshal
var _ = scanner.All
var _ = config.APIVersion
