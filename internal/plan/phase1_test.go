package plan

import (
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
)

func phase1Ctx() *sdtctx.ScanContext {
	return &sdtctx.ScanContext{
		SchemaVersion: sdtctx.SchemaVersion, Event: sdtctx.EventLocal,
		HeadRevision: "head", OutputRoot: "reports", CacheRoot: ".cache/sdt",
	}
}

// The plan digest must bind the policy digest: identical tasks with
// different policies must never plan identically.
func TestPlanDigestIncludesPolicy(t *testing.T) {
	tasks := []Task{{
		Adapter: "gitleaks", Tool: "gitleaks", Executable: "/bin/gitleaks",
		Args: []string{"detect"}, TimeoutSeconds: 600,
	}}
	a, err := Build(config.Defaults(), "pr", phase1Ctx(), tasks, nil)
	if err != nil {
		t.Fatal(err)
	}
	changed := config.Defaults()
	changed.Policy.Rules = append(changed.Policy.Rules, config.PolicyRule{
		ID: "extra", Match: config.PolicyMatch{Categories: []string{"secret"}}, Action: "fail",
	})
	b, err := Build(changed, "pr", phase1Ctx(), tasks, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.PlanDigest == b.PlanDigest {
		t.Fatal("policy change must alter plan digest")
	}
	if a.PolicyDigest == b.PolicyDigest {
		t.Fatal("policy digest field must reflect policy change")
	}
	if a.PolicyDigest != policy.Digest(config.Defaults()) {
		t.Fatal("plan PolicyDigest must equal policy.Digest(cfg)")
	}
}
