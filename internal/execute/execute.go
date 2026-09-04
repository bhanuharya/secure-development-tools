// Package execute runs scanner tasks concurrently within bounds
// (PRD EXEC-001/EXEC-002): argv-only spawn, timeouts, cancellation,
// partial-result survival.
package execute

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

// Task is a bounded unit of work.
type Task struct {
	Adapter        string
	Executable     string
	Args           []string
	TimeoutSeconds int
	Dir            string
	ReportPath     string
}

// Result captures a completed task.
type Result struct {
	Adapter        string
	NativeExit     int
	Stdout         []byte
	StderrRedacted string
	TimedOut       bool
	Duration       time.Duration
	Err            error
}

// Health classifies the outcome.
type Health string

const (
	HealthCompleted   Health = "completed"
	HealthPartial     Health = "partial"
	HealthTimeout     Health = "timeout"
	HealthMalformed   Health = "malformed"
	HealthFailed      Health = "failed"
	HealthUnavailable Health = "unavailable"
)

// RunAll executes tasks with max parallelism; one failure never erases others.
func RunAll(ctx context.Context, tasks []Task, parallelism int, redact func(string) string) []Result {
	if parallelism < 1 {
		parallelism = 1
	}
	sem := make(chan struct{}, parallelism)
	var mu sync.Mutex
	results := make([]Result, 0, len(tasks))
	var wg sync.WaitGroup
	for _, t := range tasks {
		t := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				results = append(results, Result{Adapter: t.Adapter, Err: ctx.Err()})
				mu.Unlock()
				return
			}
			r := RunOne(ctx, t, redact)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

// RunOne invokes executable+argv directly (never a shell).
func RunOne(ctx context.Context, t Task, redact func(string) string) Result {
	timeout := time.Duration(t.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, t.Executable, t.Args...)
	if t.Dir != "" {
		cmd.Dir = t.Dir
	}
	var stdout, stderr bytes.Buffer
	// Bound output: 32 MiB cap.
	cmd.Stdout = &limitedWriter{W: &stdout, N: 32 << 20}
	cmd.Stderr = &limitedWriter{W: &stderr, N: 4 << 20}
	start := time.Now()
	err := cmd.Run()
	dur := time.Since(start)
	r := Result{Adapter: t.Adapter, Duration: dur}
	if cctx.Err() == context.DeadlineExceeded {
		r.TimedOut = true
		r.Err = fmt.Errorf("%s timed out after %s", t.Adapter, timeout)
		return r
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			r.NativeExit = ee.ExitCode()
			r.Err = fmt.Errorf("%s exited %d", t.Adapter, ee.ExitCode())
		} else {
			r.Err = err
		}
	}
	r.Stdout = stdout.Bytes()
	if t.ReportPath != "" {
		if data, err := readFile(t.ReportPath); err == nil {
			r.Stdout = data
		}
	}
	if redact != nil {
		r.StderrRedacted = redact(stderr.String())
	} else {
		r.StderrRedacted = stderr.String()
	}
	return r
}

// Classify maps a result to health.
func (r Result) Classify() Health {
	if r.TimedOut {
		return HealthTimeout
	}
	if r.Err != nil {
		if r.NativeExit == 0 && len(r.Stdout) > 0 {
			return HealthPartial
		}
		return HealthFailed
	}
	return HealthCompleted
}

type limitedWriter struct {
	W *bytes.Buffer
	N int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	remain := l.N - l.W.Len()
	if remain <= 0 {
		return len(p), nil // discard beyond cap
	}
	if len(p) > remain {
		p = p[:remain]
	}
	return l.W.Write(p)
}
