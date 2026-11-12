//go:build !unix

package execute

import "os/exec"

// OwnProcessGroup is a no-op where process groups do not exist: cancellation
// stops the scanner's own process, as exec.CommandContext does by default.
func OwnProcessGroup(cmd *exec.Cmd) {}
