package endpoints

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// A launcher around the engine may leave a child holding stdout after the
// deadline. The fact run must stop the whole process group and return.
func TestFactsDeadlineStopsChildProcesses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process groups are not available")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SDT_HOME", root)
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-opengrep")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nsleep 2 &\nwait\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SDT_OPENGREP_BIN", bin)

	started := time.Now()
	_, err = runFactsWithTimeout(dir, 100*time.Millisecond)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("fact run returned after %v, past the deadline and grace", elapsed)
	}
}
