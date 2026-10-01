// Package scanner defines the adapter contract (PRD §16) and built-in adapters.
package scanner

import (
	"fmt"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// Health mirrors execute health for policy decisions.
type Health string

const (
	HealthCompleted   Health = "completed"
	HealthPartial     Health = "partial"
	HealthTimeout     Health = "timeout"
	HealthMalformed   Health = "malformed"
	HealthFailed      Health = "failed"
	HealthUnavailable Health = "unavailable"
	HealthSkipped     Health = "skipped"
)

// Applicability is detect() output.
type Applicability struct {
	State  string // applicable|not_applicable|unknown
	Reason string
}

// Task is an immutable scanner invocation.
// ReportPath, when set, is a file the tool writes machine output to; the
// orchestrator reads it back and feeds the bytes to Parse as stdout.
type Task struct {
	Adapter        string
	Tool           string
	Executable     string
	Args           []string
	Targets        []string
	TimeoutSeconds int
	RuleBundle     string
	RuleChecksums  []string
	ReportPath     string
	// Mode records adapter-specific scan mode (e.g. gitleaks tree|changed|full).
	Mode string
}

// ParseResult is adapter parse output.
type ParseResult struct {
	Findings    []*finding.Finding
	Diagnostics []string
	Health      Health
}

// Adapter implements identify/validate/detect/plan/parse/redact.
type Adapter interface {
	Identity() (adapterID, tool string, categories []string)
	Validate(cfg *config.ScanConfiguration) []string
	Detect(root string, languages []string) Applicability
	Plan(ctx *sdtctx.ScanContext, cfg *config.ScanConfiguration, root string) (Task, error)
	// Parse normalizes native output. root is the scan root: adapters must
	// record repository-relative paths so fingerprints hold across machines.
	Parse(toolVersion string, root string, stdout []byte, stderrRedacted string, nativeExit int) ParseResult
}

var registry = map[string]Adapter{}

// Register adds an adapter.
func Register(a Adapter) {
	id, _, _ := a.Identity()
	registry[id] = a
}

// Lookup returns an adapter by ID.
func Lookup(id string) (Adapter, bool) {
	a, ok := registry[id]
	return a, ok
}

// All returns registered adapter IDs in stable order.
func All() []string {
	out := []string{"opengrep", "gitleaks", "trivy-fs", "trivy-image"}
	var extra []string
	for id := range registry {
		found := false
		for _, k := range out {
			if k == id {
				found = true
			}
		}
		if !found {
			extra = append(extra, id)
		}
	}
	return append(out, extra...)
}

// ToolVersion resolves a binary version via --version (best effort).
func ToolVersion(executable string) string {
	if executable == "" {
		return ""
	}
	out, err := runVersion(executable)
	if err != nil {
		return ""
	}
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

func UnknownScanner(id string) error {
	return fmt.Errorf("unknown scanner %q", id)
}
