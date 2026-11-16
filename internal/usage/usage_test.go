package usage

import (
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestOfProcessCountsCPUAndMemory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rusage is a unix measurement")
	}
	// A shell busy for a moment: enough CPU to measure, no external tools.
	cmd := exec.Command("sh", "-c", "i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done")
	start := time.Now()
	if err := cmd.Run(); err != nil {
		t.Skipf("sh not available: %v", err)
	}
	u := OfProcess(cmd.ProcessState, time.Since(start))
	if u.CPU <= 0 || u.MaxRSSKB <= 0 || u.Wall <= 0 {
		t.Fatalf("child cost not measured: %+v", u)
	}
	if OfProcess(nil, time.Second).CPU != 0 {
		t.Fatal("no process, no CPU")
	}
}

func TestSoFarCountsThisProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rusage is a unix measurement")
	}
	busy := time.Now()
	for time.Since(busy) < 30*time.Millisecond {
	}
	if p := SoFar(); p.CPU < 20*time.Millisecond || p.SelfMaxRSSKB <= 0 {
		t.Fatalf("this process's cost not measured: %+v", p)
	}
}
