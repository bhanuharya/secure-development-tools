package plan

import (
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
)

func testPlanCtx() *sdtctx.ScanContext {
	return &sdtctx.ScanContext{
		SchemaVersion: sdtctx.SchemaVersion, Event: sdtctx.EventLocal,
		HeadRevision: "head", OutputRoot: "reports", CacheRoot: ".cache/sdt",
	}
}

// Rule content changes must alter the plan digest: determinism runs over
// contents, not just file paths.
func TestPlanDigestSensitiveToRuleContents(t *testing.T) {
	cfg := config.Defaults()
	mk := func(sums []string) *Plan {
		p, err := Build(cfg, "pr", testPlanCtx(), []Task{{
			Adapter: "opengrep", Tool: "opengrep", Executable: "/bin/opengrep",
			Args: []string{"scan"}, TimeoutSeconds: 600,
			RuleBundle: "secure-default", RuleChecksums: sums,
		}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := mk([]string{"sha256:aaa"})
	b := mk([]string{"sha256:aaa"})
	if a.PlanDigest != b.PlanDigest {
		t.Fatal("identical inputs must digest identically")
	}
	c := mk([]string{"sha256:bbb"})
	if a.PlanDigest == c.PlanDigest {
		t.Fatal("changed rule contents must alter the plan digest")
	}
}
