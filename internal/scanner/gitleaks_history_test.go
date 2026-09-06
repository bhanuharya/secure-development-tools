package scanner

import (
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
)

func testCtx() *sdtctx.ScanContext {
	return &sdtctx.ScanContext{
		SchemaVersion: sdtctx.SchemaVersion, Event: sdtctx.EventPullRequest,
		HeadRevision: "head123", BaseRevision: "base456", MergeBase: "base456",
		OutputRoot: "reports", CacheRoot: "/tmp/sdt-test-cache",
	}
}

func TestGitleaksChangedModeUsesRange(t *testing.T) {
	cfg := config.Defaults()
	a := &GitleaksAdapter{}
	task, err := a.PlanForProfile(testCtx(), cfg, "/repo", "pr")
	if err != nil {
		t.Skipf("gitleaks not installed: %v", err)
	}
	joined := strings.Join(task.Args, " ")
	if !strings.Contains(joined, "--log-opts=base456..head123") {
		t.Fatalf("changed mode must scan the commit range, got: %s", joined)
	}
	if task.Mode != "changed" {
		t.Fatalf("mode=%q", task.Mode)
	}
}

func TestGitleaksFullModeUsesAll(t *testing.T) {
	cfg := config.Defaults()
	a := &GitleaksAdapter{}
	task, err := a.PlanForProfile(testCtx(), cfg, "/repo", "full")
	if err != nil {
		t.Skipf("gitleaks not installed: %v", err)
	}
	if !strings.Contains(strings.Join(task.Args, " "), "--log-opts=--all") {
		t.Fatalf("full mode must scan all history: %v", task.Args)
	}
}

func TestGitleaksChangedWithoutBaseFallsBackToTree(t *testing.T) {
	cfg := config.Defaults()
	a := &GitleaksAdapter{}
	ctx := testCtx()
	ctx.BaseRevision, ctx.MergeBase = "", ""
	task, err := a.PlanForProfile(ctx, cfg, "/repo", "pr")
	if err != nil {
		t.Skipf("gitleaks not installed: %v", err)
	}
	if !strings.Contains(strings.Join(task.Args, " "), "--no-git") {
		t.Fatalf("missing base must fall back to tree: %v", task.Args)
	}
}

func TestGitleaksHistoryCommitRecorded(t *testing.T) {
	raw := []byte(`[{"RuleID":"r","File":"a.py","Description":"d","Match":"m","Secret":"s","Commit":"abc123def456"}]`)
	a := &GitleaksAdapter{}
	pr := a.Parse("8.30.1", "/repo", raw, "", 0)
	if len(pr.Findings) != 1 {
		t.Fatalf("want 1, got %d", len(pr.Findings))
	}
	if pr.Findings[0].Metadata["commit"] != "abc123def456" {
		t.Fatalf("commit not recorded: %+v", pr.Findings[0].Metadata)
	}
}
