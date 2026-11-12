package app

import (
	"bytes"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
	"github.com/bhanuharya/secure-development-tools/internal/report"
)

func newEndpointsCmd() *cobra.Command {
	var out string
	var format string
	var findingsPath string
	cmd := &cobra.Command{
		Use:   "endpoints [DIR]",
		Short: "Inventory HTTP routes and their effective access control",
		Long: "Inventories HTTP routes from the framework facts under rules/endpoint-facts\n" +
			"and shows the protection each route effectively has (SPEC §2).\n" +
			"--findings also writes the convention findings (SPEC §6) as finding JSON.\n" +
			"DIR defaults to the current directory.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			info, err := os.Stat(dir)
			if err != nil || !info.IsDir() {
				return failf(ExitInvalidInput, "%q is not a directory", dir)
			}
			if format == "" {
				// SPEC §2: table by default; JSON when writing to a file.
				if out == "" {
					format = "table"
				} else {
					format = "json"
				}
			}
			switch format {
			case "json", "csv", "table":
			default:
				return failf(ExitInvalidInput, "unknown format %q (want json|csv|table)", format)
			}

			// Convention thresholds and gate names come from the same repo
			// config sdt scan reads (--config, else .secure-dev.yaml when present).
			cfg, _, _, _, err := effectiveConfig()
			if err != nil {
				return err
			}
			convCfg := cfg.Endpoints

			inv, err := endpoints.BuildInventory(dir, convCfg)
			if err != nil {
				// Engine/config failures are execution failures (exit 3), not
				// bad user input: the directory was valid.
				return failf(ExitExecutionFailed, "endpoint inventory: %v", err)
			}
			if findingsPath != "" {
				findings, err := endpoints.Analyze(inv, convCfg)
				if err != nil {
					return failf(ExitInvalidInput, "endpoint convention config: %v", err)
				}
				raw, err := report.MarshalRedacted(findings)
				if err != nil {
					return failf(ExitInternalError, "render convention findings: %v", err)
				}
				if err := os.WriteFile(findingsPath, append(raw, '\n'), 0o644); err != nil {
					return failf(ExitInvalidInput, "write %s: %v", findingsPath, err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "endpoints: %d convention finding(s) written to %s\n", len(findings), findingsPath)
			}
			if out == "" {
				if err := endpoints.Write(cmd.OutOrStdout(), inv, format); err != nil {
					return failf(ExitInternalError, "write inventory: %v", err)
				}
				return nil
			}
			var buf bytes.Buffer
			if err := endpoints.Write(&buf, inv, format); err != nil {
				return failf(ExitInternalError, "render inventory: %v", err)
			}
			if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
				return failf(ExitInvalidInput, "write %s: %v", out, err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "endpoints: %d route(s) written to %s\n", len(inv.Routes), out)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "write the inventory to FILE instead of stdout")
	cmd.Flags().StringVar(&format, "format", "", "output format: json|csv|table (default table, or json with -o)")
	cmd.Flags().StringVar(&findingsPath, "findings", "", "also write the convention findings (SPEC §6) to FILE as JSON")
	return cmd
}
