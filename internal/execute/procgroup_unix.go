//go:build unix

package execute

import (
	"os"
	"os/exec"
	"syscall"
)

// OwnProcessGroup starts the scanner as the leader of a process group of its
// own, and makes cancellation stop that whole group. A scanner is often a
// launcher around the real engine (opengrep -> opengrep-cli -> opengrep-core):
// stopping the launcher alone leaves the engine running, and holding the
// output pipes open, long after its time limit. Exported for the endpoint
// fact runner, which owns its engine invocation but needs the same guarantee.
func OwnProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
}
