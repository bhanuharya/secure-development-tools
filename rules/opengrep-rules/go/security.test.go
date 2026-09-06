package security_test

import "os/exec"

// Annotated tests for go/security.yaml.
func tainted(arg string) {
	// ruleid: scp.go.injection.command
	exec.Command("sh", "-c", arg)
}

func safe(arg string) {
	// ok: scp.go.injection.command
	exec.Command("echo", arg)
}
