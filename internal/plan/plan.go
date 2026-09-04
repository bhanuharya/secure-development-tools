// Package plan produces the immutable scan plan (PRD PLAN-001/002).
package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
)

const SchemaVersion = "secure-dev/plan/v1alpha1"

// Task is one immutable scanner invocation.
type Task struct {
	Adapter           string   `json:"adapter"`
	Tool              string   `json:"tool"`
	VersionConstraint string   `json:"versionConstraint,omitempty"`
	Executable        string   `json:"executable"`
	Args              []string `json:"args"`
	Targets           []string `json:"targets,omitempty"`
	Excludes          []string `json:"excludes,omitempty"`
	TimeoutSeconds    int      `json:"timeoutSeconds"`
	Mode              string   `json:"mode,omitempty"`
	RuleBundle        string   `json:"ruleBundle,omitempty"`
	RuleChecksums     []string `json:"ruleChecksums,omitempty"`
	Database          string   `json:"database,omitempty"`
	UpdateMode        string   `json:"updateMode,omitempty"`
}

// Skip records a capability-based skip with reason.
type Skip struct {
	Adapter string `json:"adapter"`
	Reason  string `json:"reason"`
}

// Plan is the immutable pre-execution description.
type Plan struct {
	SchemaVersion string `json:"schemaVersion"`
	PlanID        string `json:"planId"`
	Profile       string `json:"profile"`
	// Mode records the scan fast path ("staged" for pre-commit scans).
	// Included in the digest: staged vs full must never plan identically.
	Mode          string   `json:"mode,omitempty"`
	ContextDigest string   `json:"contextDigest"`
	ConfigDigest  string   `json:"configDigest"`
	PolicyDigest  string   `json:"policyDigest"`
	PlanDigest    string   `json:"planDigest"`
	Tasks         []Task   `json:"tasks"`
	Skipped       []Skip   `json:"skipped"`
	Outputs       []string `json:"outputs"`
	OutputRoot    string   `json:"outputRoot"`
	CacheRoot     string   `json:"cacheRoot"`
	Prerequisites []string `json:"prerequisites,omitempty"`
}

// Build constructs a plan from effective config + context. Adapters register
// their task constructors; unknown scanners fail closed.
func Build(cfg *config.ScanConfiguration, profileName string, ctx *sdtctx.ScanContext, tasks []Task, skipped []Skip) (*Plan, error) {
	prof, ok := cfg.Profiles[profileName]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q", profileName)
	}
	_ = prof
	outputs := append([]string{}, cfg.Outputs.Formats...)
	if len(outputs) == 0 {
		outputs = []string{"console", "json", "sarif", "manifest"}
	}
	sort.Strings(outputs)
	mode := ""
	if ctx.Staged {
		mode = "staged"
	}
	p := &Plan{
		SchemaVersion: SchemaVersion,
		Profile:       profileName,
		Mode:          mode,
		ContextDigest: ctx.Digest(),
		ConfigDigest:  config.EffectiveDigest(cfg),
		Tasks:         tasks,
		Skipped:       skipped,
		Outputs:       outputs,
		OutputRoot:    ctx.OutputRoot,
		CacheRoot:     ctx.CacheRoot,
	}
	p.PlanID = p.computeDigest()
	p.PlanDigest = p.PlanID
	// Policy digest: reuse config digest slice for correlation.
	p.PolicyDigest = config.EffectiveDigest(cfg)
	return p, nil
}

func (p *Plan) computeDigest() string {
	canonical, _ := json.Marshal(struct {
		V       string   `json:"v"`
		Profile string   `json:"profile"`
		Mode    string   `json:"mode"`
		Ctx     string   `json:"ctx"`
		Cfg     string   `json:"cfg"`
		Tasks   []Task   `json:"tasks"`
		Skip    []Skip   `json:"skip"`
		Out     []string `json:"out"`
	}{p.SchemaVersion, p.Profile, p.Mode, p.ContextDigest, p.ConfigDigest, p.Tasks, p.Skipped, p.Outputs})
	h := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(h[:])
}
