package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// hookMarker is how sdt knows a pre-commit hook as its own.
const hookMarker = "# sdt pre-commit hook"

const preCommitHook = `#!/bin/sh
` + hookMarker + ` (written by "sdt hook install"; remove with "sdt hook uninstall").
# Checks the lines this commit adds for secrets and code weaknesses.
# Commit without the check: SKIP_SDT=1 git commit ...
# The scan of the pull request remains the gate; this is the early warning.
if [ "${SKIP_SDT:-0}" = "1" ]; then exit 0; fi
if ! command -v sdt >/dev/null 2>&1; then
  echo "sdt: not on PATH, the staged changes were not checked (the pull request scan still runs)" >&2
  exit 0
fi
exec sdt scan --staged
`

func newHookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Install or remove the pre-commit check of this repository",
	}
	var force bool
	install := &cobra.Command{
		Use:   "install",
		Short: "Check the lines of every commit before it is made (`sdt scan --staged`)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := installHook(force)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\ncommit without the check: %s\n", path, stagedBypass)
			return nil
		},
	}
	install.Flags().BoolVar(&force, "force", false, "replace a pre-commit hook that sdt did not write")
	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the pre-commit hook that sdt wrote",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := hookPath()
			if err != nil {
				return err
			}
			current, err := os.ReadFile(path)
			if os.IsNotExist(err) {
				fmt.Fprintf(cmd.OutOrStdout(), "no hook at %s\n", path)
				return nil
			}
			if err != nil {
				return failf(ExitInternalError, "read hook: %v", err)
			}
			if !strings.Contains(string(current), hookMarker) {
				return failf(ExitInvalidInput, "%s was not written by sdt; it is left as it is", path)
			}
			if err := os.Remove(path); err != nil {
				return failf(ExitInternalError, "remove hook: %v", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", path)
			return nil
		},
	}
	cmd.AddCommand(install, uninstall)
	return cmd
}

// hookPath is where git looks for this repository's pre-commit hook. Git is
// asked: the folder differs in a linked worktree, and when core.hooksPath
// names one (as hook managers do).
func hookPath() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", failf(ExitInternalError, "%v", err)
	}
	out, err := gitIn(cwd, "rev-parse", "--git-path", "hooks")
	if err != nil {
		return "", failf(ExitInvalidInput, "the hook needs a git worktree: %v", err)
	}
	dir := strings.TrimSpace(out)
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(cwd, dir)
	}
	return filepath.Join(dir, "pre-commit"), nil
}

// installHook writes the pre-commit hook. A hook that something else wrote is
// kept unless force is set: the one line to add to it is in the message.
func installHook(force bool) (string, error) {
	path, err := hookPath()
	if err != nil {
		return "", err
	}
	if current, err := os.ReadFile(path); err == nil && !force && !strings.Contains(string(current), hookMarker) {
		return "", failf(ExitInvalidInput, "%s exists and was not written by sdt.\nAdd this line to it, or use --force to replace it:\n  sdt scan --staged || exit 1", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", failf(ExitInternalError, "write hook: %v", err)
	}
	if err := os.WriteFile(path, []byte(preCommitHook), 0o755); err != nil {
		return "", failf(ExitInternalError, "write hook: %v", err)
	}
	return path, nil
}
