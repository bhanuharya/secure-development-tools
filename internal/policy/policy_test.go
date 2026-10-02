package policy

import (
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func mk(category, sev, state string) *finding.Finding {
	return &finding.Finding{
		ID:            "t:00001",
		Fingerprint:   finding.Fingerprint{Algorithm: finding.FingerprintVersion, Value: "sha256:x"},
		Category:      category,
		Severity:      finding.Severity{Canonical: sev},
		BaselineState: state,
	}
}

func TestSecretsAlwaysBlock(t *testing.T) {
	cfg := config.Defaults()
	for _, st := range []string{"new", "existing", "unknown"} {
		out := Evaluate(cfg, []*finding.Finding{mk("secret", "high", st)})
		if out.Status != "policy_failed" || len(out.Blockers) != 1 {
			t.Fatalf("secret %s not blocked: %+v", st, out)
		}
		if out.Blockers[0].RuleID != "block-secrets" {
			t.Fatalf("missing rule trace: %+v", out.Blockers[0])
		}
	}
}

func TestExistingSastNotBlocked(t *testing.T) {
	cfg := config.Defaults()
	out := Evaluate(cfg, []*finding.Finding{mk("sast", "high", "existing")})
	if out.Status != "passed" {
		t.Fatalf("existing sast should not block: %+v", out)
	}
}

func dep(sev, reach string) *finding.Finding {
	f := mk("dependency-vulnerability", sev, "new")
	if reach != "" {
		f.Reachability = &finding.Reachability{State: reach, Reason: "test"}
	}
	return f
}

func TestReachableDimension(t *testing.T) {
	cfg := config.Defaults()
	cfg.Policy.Rules = []config.PolicyRule{{
		ID:     "block-reachable-critical-deps",
		Match:  config.PolicyMatch{Categories: []string{"dependency-vulnerability"}, Severities: []string{"critical"}, BaselineStates: []string{"new"}, Reachable: []string{"reachable"}},
		Action: "fail",
	}}
	cfg.Policy.DefaultAction = "report"
	if out := Evaluate(cfg, []*finding.Finding{dep("critical", "reachable")}); out.Status != "policy_failed" {
		t.Fatal("reachable critical dep must block")
	}
	if out := Evaluate(cfg, []*finding.Finding{dep("critical", "unreachable")}); out.Status != "passed" {
		t.Fatalf("unreachable critical dep must not block, got %s", out.Status)
	}
}

// Unknown reachability must never match reachable NOR unreachable: uncertainty
// can neither trigger nor silence a rule.
func TestUnknownReachabilityMatchesNeither(t *testing.T) {
	mkcfg := func(states ...string) *config.ScanConfiguration {
		cfg := config.Defaults()
		cfg.Policy.Rules = []config.PolicyRule{{
			ID:     "r",
			Match:  config.PolicyMatch{Categories: []string{"dependency-vulnerability"}, Reachable: states},
			Action: "fail",
		}}
		cfg.Policy.DefaultAction = "report"
		return cfg
	}
	for _, states := range [][]string{{"reachable"}, {"unreachable"}, {"reachable", "unreachable"}} {
		if out := Evaluate(mkcfg(states...), []*finding.Finding{dep("critical", "unknown")}); out.Status != "passed" {
			t.Fatalf("unknown must match neither (states=%v), got %s", states, out.Status)
		}
		if out := Evaluate(mkcfg(states...), []*finding.Finding{dep("critical", "")}); out.Status != "passed" {
			t.Fatalf("unanalyzed must match neither (states=%v), got %s", states, out.Status)
		}
	}
}

func TestDeterministic(t *testing.T) {
	cfg := config.Defaults()
	fs := []*finding.Finding{mk("sast", "critical", "new"), mk("secret", "high", "new")}
	a := Evaluate(cfg, fs)
	b := Evaluate(cfg, fs)
	if len(a.Blockers) != len(b.Blockers) || a.Status != b.Status {
		t.Fatal("non-deterministic policy")
	}
}

// The opt-in recipe: block what is reachable or undecided, warn on what is
// proven unreachable. Unknown and unanalyzed findings must stay blocking.
func TestBlockUnlessProvenUnreachable(t *testing.T) {
	cfg := config.Defaults()
	match := config.PolicyMatch{Categories: []string{"dependency-vulnerability"}, Severities: []string{"critical"}, BaselineStates: []string{"new"}}
	block, warn := match, match
	block.Reachable = []string{"reachable", "unknown"}
	warn.Reachable = []string{"unreachable"}
	cfg.Policy.Rules = []config.PolicyRule{
		{ID: "block-critical-dependencies", Match: block, Action: "fail"},
		{ID: "warn-unreachable-critical-dependencies", Match: warn, Action: "warn"},
	}
	cfg.Policy.DefaultAction = "report"
	for _, state := range []string{"reachable", "unknown", ""} {
		if out := Evaluate(cfg, []*finding.Finding{dep("critical", state)}); out.Status != "policy_failed" {
			t.Fatalf("state %q must block, got %s", state, out.Status)
		}
	}
	out := Evaluate(cfg, []*finding.Finding{dep("critical", "unreachable")})
	if out.Status != "passed" || len(out.Warnings) != 1 {
		t.Fatalf("unreachable must warn, not block: %s warnings=%d", out.Status, len(out.Warnings))
	}
}

// Built-in policy: reachability is opt-in, so a new critical dependency blocks
// whatever its reachability state.
func TestDefaultPolicyBlocksCriticalDependencyRegardlessOfReachability(t *testing.T) {
	cfg := config.Defaults()
	for _, state := range []string{"reachable", "unknown", "unreachable", ""} {
		if out := Evaluate(cfg, []*finding.Finding{dep("critical", state)}); out.Status != "policy_failed" {
			t.Fatalf("state %q must block by default, got %s", state, out.Status)
		}
	}
}
