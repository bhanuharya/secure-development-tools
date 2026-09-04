// Package policy evaluates ordered deterministic rules over canonical
// findings (PRD POL-001/002).
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// Outcome aggregates rule evaluation.
type Outcome struct {
	Status   string       `json:"status"` // passed|policy_failed|inconclusive|execution_failed|invalid_input
	Blockers []Match      `json:"blockers,omitempty"`
	Warnings []Match      `json:"warnings,omitempty"`
	Trace    []TraceEntry `json:"trace"`
}

// Match links a finding to the rule that fired.
type Match struct {
	FindingID   string `json:"findingId"`
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"ruleId"`
	Action      string `json:"action"`
}

// TraceEntry explains one rule application.
type TraceEntry struct {
	RuleID   string `json:"ruleId"`
	Action   string `json:"action"`
	Findings int    `json:"findings"`
}

// Evaluate runs ordered rules; first matching rule wins per finding.
func Evaluate(cfg *config.ScanConfiguration, findings []*finding.Finding) Outcome {
	out := Outcome{Status: "passed"}
	for _, f := range findings {
		action, ruleID := applyRules(cfg, f)
		switch action {
		case "fail":
			out.Blockers = append(out.Blockers, Match{FindingID: f.ID, Fingerprint: f.Fingerprint.Value, RuleID: ruleID, Action: action})
		case "warn":
			out.Warnings = append(out.Warnings, Match{FindingID: f.ID, Fingerprint: f.Fingerprint.Value, RuleID: ruleID, Action: action})
		}
	}
	// Build trace.
	byRule := map[string]*TraceEntry{}
	order := []string{}
	for _, m := range append(append([]Match{}, out.Blockers...), out.Warnings...) {
		e, ok := byRule[m.RuleID]
		if !ok {
			e = &TraceEntry{RuleID: m.RuleID, Action: m.Action}
			byRule[m.RuleID] = e
			order = append(order, m.RuleID)
		}
		e.Findings++
	}
	for _, id := range order {
		out.Trace = append(out.Trace, *byRule[id])
	}
	if out.Trace == nil {
		out.Trace = []TraceEntry{}
	}
	if len(out.Blockers) > 0 {
		out.Status = "policy_failed"
	}
	return out
}

func applyRules(cfg *config.ScanConfiguration, f *finding.Finding) (string, string) {
	for _, r := range cfg.Policy.Rules {
		if matchRule(r, f) {
			return r.Action, r.ID
		}
	}
	return cfg.Policy.DefaultActionOr("report"), ""
}

// Digest is the stable policy digest.
func Digest(cfg *config.ScanConfiguration) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|", cfg.Policy.DefaultAction, cfg.Policy.BehaviorOnRequiredScannerError)
	for _, r := range cfg.Policy.Rules {
		fmt.Fprintf(h, "%s=%s;", r.ID, r.Action)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func matchRule(r config.PolicyRule, f *finding.Finding) bool {
	m := r.Match
	if len(m.Categories) > 0 && !contains(m.Categories, f.Category) {
		return false
	}
	if len(m.Severities) > 0 && !contains(m.Severities, f.Severity.Canonical) {
		return false
	}
	if len(m.BaselineStates) > 0 && !contains(m.BaselineStates, f.BaselineState) {
		return false
	}
	if m.FixAvailable != nil {
		hasFix := f.Remediation != nil && f.Remediation.FixedVersion != ""
		if hasFix != *m.FixAvailable {
			return false
		}
	}
	if len(m.Reachable) > 0 {
		if f.Reachability == nil || !contains(m.Reachable, f.Reachability.State) {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
