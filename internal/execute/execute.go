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
	"strings"
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
// Results are returned in input task order (deterministic) regardless of
// completion order.
func RunAll(ctx context.Context, tasks []Task, parallelism int, redact func(string) string) []Result {
	if parallelism < 1 {
		parallelism = 1
	}
	sem := make(chan struct{}, parallelism)
	results := make([]Result, len(tasks))
	var wg sync.WaitGroup
	for i, t := range tasks {
		i, t := i, t
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = Result{Adapter: t.Adapter, Err: ctx.Err()}
				return
			}
			results[i] = RunOne(ctx, t, redact)
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
	r.Stdout = stdout.Bytes()
	if redact != nil {
		r.StderrRedacted = redact(stderr.String())
	} else {
		r.StderrRedacted = stderr.String()
	}
	// Timeout/cancellation is authoritative: never lose it beneath a later
	// parse or exit-code check. Preserve partial output for diagnostics.
	if cctx.Err() == context.DeadlineExceeded {
		r.TimedOut = true
		r.Err = fmt.Errorf("%s timed out after %s", t.Adapter, timeout)
		return r
	}
	if ctx.Err() != nil {
		// Parent cancellation (e.g. profile timeout): authoritative even
		// when the child already exited. Never report completed.
		r.Err = fmt.Errorf("%s cancelled: %w", t.Adapter, ctx.Err())
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
	// Native report contract: adapters that declare a ReportPath must
	// produce a non-empty machine-output file. The file is authoritative:
	// a missing/empty report is an execution failure even when the tool
	// also wrote stdout (stdout never promotes it back to success).
	if t.ReportPath != "" {
		data, rerr := readFile(t.ReportPath)
		if rerr != nil {
			if r.Err == nil {
				r.Err = fmt.Errorf("%s: missing native report %s: %v", t.Adapter, t.ReportPath, rerr)
			}
		} else if len(data) == 0 {
			if r.Err == nil {
				r.Err = fmt.Errorf("%s: empty native report %s", t.Adapter, t.ReportPath)
			}
		} else {
			r.Stdout = data
		}
	}
	return r
}

// Classify maps a result to health.
func (r Result) Classify() Health {
	if r.TimedOut {
		return HealthTimeout
	}
	if r.Err != nil {
		// A missing/empty native report is a hard failure: preserved
		// stdout is diagnostic only and never softens it to partial.
		if strings.Contains(r.Err.Error(), "native report") {
			return HealthFailed
		}
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
