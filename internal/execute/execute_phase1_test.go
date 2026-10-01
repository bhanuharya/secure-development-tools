package execute

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Results must come back in input task order regardless of completion order.
func TestRunAllDeterministicOrder(t *testing.T) {
	tasks := []Task{
		{Adapter: "slow", Executable: "sh", Args: []string{"-c", "sleep 0.4; echo first"}, TimeoutSeconds: 10},
		{Adapter: "fast", Executable: "sh", Args: []string{"-c", "echo second"}, TimeoutSeconds: 10},
		{Adapter: "mid", Executable: "sh", Args: []string{"-c", "sleep 0.1; echo third"}, TimeoutSeconds: 10},
	}
	for i := 0; i < 5; i++ {
		got := RunAll(context.Background(), tasks, 3, nil)
		if len(got) != 3 {
			t.Fatalf("want 3 results, got %d", len(got))
		}
		for j, want := range []string{"slow", "fast", "mid"} {
			if got[j].Adapter != want {
				t.Fatalf("iter %d: results[%d]=%q, want %q (nondeterministic order)", i, j, got[j].Adapter, want)
			}
		}
		if !strings.Contains(string(got[0].Stdout), "first") || !strings.Contains(string(got[1].Stdout), "second") {
			t.Fatalf("outputs misaligned with adapters: %q %q", got[0].Stdout, got[1].Stdout)
		}
	}
}

// Timeout must be preserved with its cause, and classify as timeout.
func TestRunOneTimeoutPreserved(t *testing.T) {
	r := RunOne(context.Background(), Task{
		Adapter: "sleeper", Executable: "sh", Args: []string{"-c", "sleep 30"}, TimeoutSeconds: 1,
	}, nil)
	if !r.TimedOut {
		t.Fatal("expected TimedOut")
	}
	if r.Err == nil || !strings.Contains(r.Err.Error(), "timed out") {
		t.Fatalf("timeout cause lost: %v", r.Err)
	}
	if r.Classify() != HealthTimeout {
		t.Fatalf("classify=%s, want timeout", r.Classify())
	}
}

// A declared native report that is missing must fail, never pass silently.
func TestRunOneMissingNativeReport(t *testing.T) {
	r := RunOne(context.Background(), Task{
		Adapter: "ghost", Executable: "sh", Args: []string{"-c", "echo hi"},
		TimeoutSeconds: 10, ReportPath: filepath.Join(t.TempDir(), "nope", "missing.json"),
	}, nil)
	if r.Err == nil {
		t.Fatal("expected error for missing native report")
	}
	if r.Classify() == HealthCompleted {
		t.Fatal("missing report must not classify as completed")
	}
}

// An empty native report with empty stdout must also fail.
func TestRunOneEmptyNativeReport(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	r := RunOne(context.Background(), Task{
		Adapter: "empty", Executable: "sh", Args: []string{"-c", "true"},
		TimeoutSeconds: 10, ReportPath: empty,
	}, nil)
	if r.Err == nil {
		t.Fatal("expected error for empty native report")
	}
}

// Parent cancellation (profile timeout path) must be preserved, not dropped.
func TestRunOneParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := RunOne(ctx, Task{
		Adapter: "cancelled", Executable: "sh", Args: []string{"-c", "sleep 5"}, TimeoutSeconds: 60,
	}, nil)
	if r.Err == nil {
		t.Fatal("expected cancellation error")
	}
	_ = time.Now
}
