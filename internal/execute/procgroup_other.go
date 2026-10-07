//go:build !unix

package execute

import "os/exec"

// ownProcessGroup is a no-op where process groups do not exist: cancellation
// stops the scanner's own process, as exec.CommandContext does by default.
func ownProcessGroup(cmd *exec.Cmd) {}
