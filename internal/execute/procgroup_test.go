//go:build unix

package execute

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// launcher is a scanner shaped like opengrep: a wrapper that starts the real
// work as a child, which inherits the output pipes and runs for a minute.
func launcher(t *testing.T) (Task, func() int) {
	t.Helper()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	script := fmt.Sprintf("sleep 60 & echo $! > %s; wait", pidFile)
	child := func() int {
		raw, err := os.ReadFile(pidFile)
		if err != nil {
			t.Fatalf("the launcher did not start its child: %v", err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return pid
	}
	return Task{Adapter: "launcher", Executable: "sh", Args: []string{"-c", script}, TimeoutSeconds: 1}, child
}

func stopped(pid int) bool {
	for i := 0; i < 50; i++ {
		if syscall.Kill(pid, 0) == syscall.ESRCH {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// The time limit applies to everything the scanner started, and the run does
// not wait for a child that is still holding the output open.
func TestTimeoutStopsTheScannersChildProcesses(t *testing.T) {
	task, child := launcher(t)
	start := time.Now()
	r := RunOne(context.Background(), task, nil)
	if waited := time.Since(start); waited > 20*time.Second {
		t.Fatalf("the run waited %s for a child of the stopped scanner", waited.Round(time.Second))
	}
	if !r.TimedOut || r.Classify() != HealthTimeout {
		t.Fatalf("want a timeout, got %s (%v)", r.Classify(), r.Err)
	}
	if pid := child(); !stopped(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("the scanner's child kept running after the time limit")
	}
}

// Stopping the run (profile time limit, or a signal to sdt) stops them as well.
func TestCancellationStopsTheScannersChildProcesses(t *testing.T) {
	task, child := launcher(t)
	task.TimeoutSeconds = 120
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(time.Second, cancel)
	start := time.Now()
	r := RunOne(ctx, task, nil)
	if waited := time.Since(start); waited > 20*time.Second {
		t.Fatalf("the run waited %s after it was cancelled", waited.Round(time.Second))
	}
	if r.Err == nil || !strings.Contains(r.Err.Error(), "cancelled") {
		t.Fatalf("want a cancelled task, got %v", r.Err)
	}
	if pid := child(); !stopped(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("the scanner's child kept running after the run was cancelled")
	}
}
