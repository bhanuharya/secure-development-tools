package execute

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bhanuharya/secure-development-tools/internal/usage"
)

func TestInProcessTaskReturnsItsReportAndCost(t *testing.T) {
	r := RunOne(context.Background(), Task{Adapter: "inv", TimeoutSeconds: 5,
		Run: func(ctx context.Context) ([]byte, usage.Usage, error) {
			return []byte(`{"ok":true}`), usage.Usage{CPU: 3 * time.Second, MaxRSSKB: 2048}, nil
		}}, nil)
	if r.Classify() != HealthCompleted || string(r.Stdout) != `{"ok":true}` || r.CPU != 3*time.Second || r.MaxRSSKB != 2048 {
		t.Fatalf("result = %+v", r)
	}
}

func TestInProcessTaskTimesOutLikeAScanner(t *testing.T) {
	r := RunOne(context.Background(), Task{Adapter: "inv", TimeoutSeconds: 1,
		Run: func(ctx context.Context) ([]byte, usage.Usage, error) {
			<-ctx.Done()
			return nil, usage.Usage{}, ctx.Err()
		}}, nil)
	if r.Classify() != HealthTimeout {
		t.Fatalf("an in-process task past its time limit must be a timeout, got %s (%v)", r.Classify(), r.Err)
	}
}

func TestInProcessTaskErrorIsAFailure(t *testing.T) {
	r := RunOne(context.Background(), Task{Adapter: "inv", TimeoutSeconds: 5,
		Run: func(ctx context.Context) ([]byte, usage.Usage, error) {
			return []byte("partial"), usage.Usage{}, errors.New("fact engine failed")
		}}, nil)
	if r.Classify() != HealthFailed || r.Stdout != nil {
		t.Fatalf("a failed in-process task must not hand a report to Parse: %s %q", r.Classify(), r.Stdout)
	}
}

func TestInProcessTaskIsNotStartedAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	r := RunOne(ctx, Task{Adapter: "inv", TimeoutSeconds: 5,
		Run: func(context.Context) ([]byte, usage.Usage, error) { called = true; return nil, usage.Usage{}, nil }}, nil)
	if called || r.Err == nil {
		t.Fatalf("cancelled scan started in-process work: called=%v err=%v", called, r.Err)
	}
}
