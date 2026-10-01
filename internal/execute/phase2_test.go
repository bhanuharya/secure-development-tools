package execute

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMissingReportIsFailureNotSuccess(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.json")
	r := RunOne(context.Background(), Task{Adapter: "x", Executable: "true", ReportPath: missing}, nil)
	if r.Err == nil {
		t.Fatal("missing native report must be an error")
	}
	if got := r.Classify(); got != HealthFailed {
		t.Fatalf("missing report must classify failed, got %s", got)
	}
}

func TestEmptyReportWithStdoutIsFailure(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	// /bin/echo writes stdout but the declared report is empty.
	r := RunOne(context.Background(), Task{Adapter: "x", Executable: "/bin/echo", Args: []string{"hi"}, ReportPath: empty}, nil)
	if r.Err == nil {
		t.Fatal("empty native report must be an error even with stdout")
	}
	if got := r.Classify(); got != HealthFailed {
		t.Fatalf("empty report must classify failed, got %s", got)
	}
}

func TestParentCancellationPreserved(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := RunOne(ctx, Task{Adapter: "x", Executable: "/bin/echo", Args: []string{"hi"}}, nil)
	if r.Err == nil {
		t.Fatal("cancelled parent must produce an error")
	}
	if got := r.Classify(); got != HealthFailed {
		t.Fatalf("cancelled run must not be completed, got %s", got)
	}
	_ = time.Now
}
