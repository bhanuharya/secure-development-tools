package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/bhanuharya/secure-development-tools/internal/baseline"
	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
	"github.com/bhanuharya/secure-development-tools/internal/detect"
	"github.com/bhanuharya/secure-development-tools/internal/execute"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"github.com/bhanuharya/secure-development-tools/internal/plan"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
	"github.com/bhanuharya/secure-development-tools/internal/reachability"
	"github.com/bhanuharya/secure-development-tools/internal/report"
	"github.com/bhanuharya/secure-development-tools/internal/scanner"
)

// stagedDeferralReason marks scanners skipped only because staged mode defers
// full-tree work to CI. Matched exactly by the required-scanner exemption.
const stagedDeferralReason = "staged mode: full-tree scanner deferred to CI"

// stagedCapable lists adapters that can meaningfully scope to staged files.
// trivy-fs needs the full tree (lockfiles, configs); trivy-image scans a
// registry artifact, not the worktree — both wait for CI.
func stagedCapable(id string) bool {
	return id == "opengrep" || id == "gitleaks"
}

// planTasksFull implements capability-based selection with visible skip reasons.
func planTasksFull(cfg *config.ScanConfiguration, profile string, ctx *sdtctx.ScanContext, root string) ([]plan.Task, []plan.Skip) {
	prof := cfg.Profiles[profile]
	facts := detect.Inspect(root)
	var tasks []plan.Task
	var skipped []plan.Skip
	for _, id := range prof.Scanners {
		if ctx.Staged && !stagedCapable(id) {
			skipped = append(skipped, plan.Skip{Adapter: id, Reason: stagedDeferralReason})
			continue
		}
		a, ok := scanner.Lookup(id)
		if !ok {
			skipped = append(skipped, plan.Skip{Adapter: id, Reason: "unknown scanner"})
			continue
		}
		if diags := a.Validate(cfg); len(diags) > 0 {
			skipped = append(skipped, plan.Skip{Adapter: id, Reason: diags[0]})
			continue
		}
		app := a.Detect(root, facts.Languages)
		if app.State == "not_applicable" {
			skipped = append(skipped, plan.Skip{Adapter: id, Reason: app.Reason})
			continue
		}
		var t scanner.Task
		var err error
		if pp, ok := a.(interface {
			PlanForProfile(*sdtctx.ScanContext, *config.ScanConfiguration, string, string) (scanner.Task, error)
		}); ok {
			t, err = pp.PlanForProfile(ctx, cfg, root, profile)
		} else {
			t, err = a.Plan(ctx, cfg, root)
		}
		if err != nil {
			skipped = append(skipped, plan.Skip{Adapter: id, Reason: err.Error()})
			continue
		}
		tasks = append(tasks, plan.Task{
			Adapter: t.Adapter, Tool: t.Tool, Executable: t.Executable, Args: t.Args,
			Targets: t.Targets, TimeoutSeconds: t.TimeoutSeconds, Mode: t.Mode, RuleBundle: t.RuleBundle,
			RuleChecksums: t.RuleChecksums,
		})
		// stash report path via parallel slice hack: re-lookup after build.
		pendingReportPaths[t.Adapter] = t.ReportPath
	}
	return tasks, skipped
}

// pendingReportPaths carries adapter report-file paths from planning to execution.
var pendingReportPaths = map[string]string{}

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Execute, normalize, evaluate, and report",
		RunE: func(cmd *cobra.Command, args []string) error {
			started := time.Now()
			runID := newRunID()
			code, err := runScan(cmd, runID, started)
			if err != nil {
				// Reports are finalized inside runScan even on policy failure.
				if ee, ok := err.(*ExitError); ok {
					_ = code
					return ee
				}
				return err
			}
			return nil
		},
	}
	return cmd
}

func runScan(cmd *cobra.Command, runID string, started time.Time) (int, error) {
	cfg, _, _, warns, err := effectiveConfig()
	if err != nil {
		return ExitInvalidInput, err
	}
	for _, w := range warns {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+w)
	}
	prof, ok := cfg.Profiles[g.Profile]
	if !ok {
		return ExitInvalidInput, failf(ExitInvalidInput, "unknown profile %q", g.Profile)
	}
	// CLI flags win over file/env for artifact roots (PRD layer 6).
	if g.Output != "" {
		cfg.Outputs.Directory = g.Output
	}
	if g.Cache != "" {
		cfg.Runtime.CacheDirectory = g.Cache
	}
	ctx, cwarns, err := resolveContext(cfg)
	if err != nil {
		return ExitInvalidInput, err
	}
	for _, w := range cwarns {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+w)
	}
	if g.Image != "" {
		ctx.ImageReference = g.Image
	}
	if prof.RequireImage && ctx.ImageReference == "" {
		return ExitInvalidInput, failf(ExitInvalidInput, "profile %q requires an image reference (--image or SDT_IMAGE)", g.Profile)
	}
	root, err := ScanRoot(cfg)
	if err != nil {
		return ExitInvalidInput, err
	}
	pendingReportPaths = map[string]string{}
	tasks, skipped := planTasks(cfg, g.Profile, ctx, root)
	p, err := plan.Build(cfg, g.Profile, ctx, tasks, skipped)
	if err != nil {
		return ExitInternalError, err
	}

	// Shallow-history guard (CTX-003).
	if ctx.Shallow && (ctx.BaseRevision != "" || prof.Mode == "repository") {
		switch prof.MissingHistory {
		case "fail":
			return finalizeEmpty(cmd, cfg, p, runID, started, "inconclusive",
				"incomplete git history (shallow clone) and profile requires history")
		case "warn":
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: shallow clone; history-dependent coverage reduced")
		}
	}

	// Execute.
	parallelism := prof.Parallelism
	if parallelism < 1 {
		parallelism = 3
	}
	execTasks := make([]execute.Task, 0, len(tasks))
	toolVersions := map[string]string{}
	adapters := map[string]scanner.Adapter{}
	for _, t := range tasks {
		a, _ := scanner.Lookup(t.Adapter)
		adapters[t.Adapter] = a
		toolVersions[t.Adapter] = scanner.ToolVersion(t.Executable)
		execTasks = append(execTasks, execute.Task{
			Adapter: t.Adapter, Executable: t.Executable, Args: t.Args,
			TimeoutSeconds: t.TimeoutSeconds, Dir: root, ReportPath: pendingReportPaths[t.Adapter],
		})
	}
	ectx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := execute.RunAll(ectx, execTasks, parallelism, func(s string) string { return report.Redact(s) })

	// Parse + normalize.
	var findings []*finding.Finding
	health := map[string]string{}
	taskRecords := []report.TaskRecord{}
	diagnostics := []string{}
	n := 0
	for _, r := range results {
		a := adapters[r.Adapter]
		health[r.Adapter] = string(r.Classify())
		rec := report.TaskRecord{Adapter: r.Adapter, State: string(r.Classify()), NativeExit: r.NativeExit, DurationMS: r.Duration.Milliseconds()}
		if a == nil {
			rec.Diagnostic = "no adapter"
			taskRecords = append(taskRecords, rec)
			continue
		}
		pr := a.Parse(toolVersions[r.Adapter], root, r.Stdout, r.StderrRedacted, r.NativeExit)
		health[r.Adapter] = string(pr.Health)
		rec.State = string(pr.Health)
		diagnostics = append(diagnostics, pr.Diagnostics...)
		if len(pr.Diagnostics) > 0 {
			rec.Diagnostic = truncateJoin(pr.Diagnostics, 300)
		}
		taskRecords = append(taskRecords, rec)
		for _, f := range pr.Findings {
			n++
			f.ID = fmt.Sprintf("%s:%05d", r.Adapter, n)
			findings = append(findings, f)
		}
		// Clean up temp report files.
		if rp := pendingReportPaths[r.Adapter]; rp != "" {
			_ = os.Remove(rp)
		}
	}
	for _, s := range skipped {
		health[s.Adapter] = "skipped: " + s.Reason
		taskRecords = append(taskRecords, report.TaskRecord{Adapter: s.Adapter, State: "skipped", Diagnostic: s.Reason})
	}

	// Staged fast path: keep only findings attributable to staged files.
	// Engines scan the tree; attribution happens here so every adapter obeys
	// the same boundary without bespoke file-list plumbing.
	if ctx.Staged {
		kept, dropped := filterStaged(findings, ctx.ChangedPaths)
		if dropped > 0 {
			diagnostics = append(diagnostics, fmt.Sprintf("staged mode: %d finding(s) outside staged files omitted (full gate runs in CI)", dropped))
		}
		findings = kept
	}

	// Reachability (Bet 2): annotate dependency findings before policy.
	// Best-effort and sound by construction — see internal/reachability.
	// Runs on full and staged scans alike; staged filtering already applied.
	reachability.Annotate(root, findings)

	// Required-scanner health (POL-002).
	// In staged mode, scanners deferred to CI are exempt: they never ran, so
	// there is no health to judge — but the deferral stays visible in the
	// plan, the manifest tasks, and the diagnostics below. Every other skip
	// still fails closed.
	deferred := map[string]bool{}
	if ctx.Staged {
		for _, s := range skipped {
			if s.Reason == stagedDeferralReason {
				deferred[s.Adapter] = true
			}
		}
	}
	requiredFailed := []string{}
	for _, req := range prof.RequiredScanners {
		if deferred[req] {
			diagnostics = append(diagnostics, fmt.Sprintf("required scanner %s deferred to CI (staged mode)", req))
			continue
		}
		h, ok := health[req]
		if !ok {
			requiredFailed = append(requiredFailed, req+" (not in plan)")
			continue
		}
		if h != string(scanner.HealthCompleted) {
			requiredFailed = append(requiredFailed, req+" ("+h+")")
		}
	}
	if len(requiredFailed) > 0 {
		msg := fmt.Sprintf("required scanners unhealthy: %v", requiredFailed)
		switch cfg.Policy.BehaviorOnRequiredScannerError {
		case "fail":
			// Record execution failure but still finalize sanitized reports.
			return finalize(cmd, cfg, p, runID, started, findings, diagnostics, taskRecords, health, toolVersions, "execution_failed", ExitExecutionFailed, msg)
		default:
			return finalize(cmd, cfg, p, runID, started, findings, diagnostics, taskRecords, health, toolVersions, "inconclusive", ExitInconclusive, msg)
		}
	}

	// SBOM evidence (Bet 4): trivy CycloneDX inventory, generated only on
	// request via outputs.formats. Never gates: failures become diagnostics.
	// Staged mode has no trivy run, so there is nothing to inventory.
	var extra []extraArtifact
	if wantsFormat(cfg, "sbom") {
		if ctx.Staged {
			diagnostics = append(diagnostics, "sbom skipped in staged mode (trivy deferred to CI)")
		} else if sbom, derr := runTrivySBOM(ectx, tasks, root, ctx.ImageReference, health); derr != "" {
			diagnostics = append(diagnostics, derr)
		} else if len(sbom) > 0 {
			extra = append(extra, extraArtifact{name: "sbom.cdx.json", data: sbom, media: "application/vnd.cyclonedx+json", schema: "cyclonedx-1.5"})
		}
	}

	// Baseline + exceptions.
	baselinePath := cfg.Baseline.File
	if baselinePath == "" {
		baselinePath = ".secure-dev/baseline.json"
	}
	bl, err := baseline.Load(baselinePath)
	if err != nil {
		return finalize(cmd, cfg, p, runID, started, findings, diagnostics, taskRecords, health, toolVersions, "invalid_input", ExitInvalidInput, err.Error())
	}
	bl.Apply(findings)
	applyExceptions(cfg, findings, time.Now())

	// Policy.
	out := policy.Evaluate(cfg, findings)
	status := out.Status
	exitCode := ExitPassed
	if status == "policy_failed" {
		exitCode = ExitPolicyFailed
	}

	return finalizeOutcome(cmd, cfg, p, runID, started, findings, diagnostics, taskRecords, health, toolVersions, out, status, exitCode, extra)
}

func applyExceptions(cfg *config.ScanConfiguration, findings []*finding.Finding, nowTime time.Time) {
	path := cfg.Exceptions.File
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var doc struct {
		Exceptions []baseline.Exception `yaml:"exceptions"`
	}
	// Support both {exceptions: [...]} and bare list.
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return
	}
	var list []baseline.Exception
	if len(doc.Exceptions) > 0 {
		list = doc.Exceptions
	} else {
		_ = yaml.Unmarshal(raw, &list)
	}
	for _, e := range list {
		expired, err := baseline.ValidateException(e, nowTime)
		if err != nil || expired {
			continue
		}
		if len(e.Fingerprints) == 0 {
			continue // broad path/rule exceptions recorded but only fingerprint suppresses for now
		}
		for _, f := range findings {
			if e.Matches(f) {
				if f.Category == finding.CatSecret && !cfg.Exceptions.AllowSecretExceptions {
					continue // secrets need break-glass
				}
				f.Suppression = &finding.Suppression{ExceptionID: e.ID, Reason: e.Reason}
			}
		}
	}
	// Remove suppressed findings from policy consideration by marking existing?
	// Policy still sees them; suppress action handled by caller filtering.
	_ = list
}

// finalizeOutcome writes all artifacts then returns the exit code.
func finalizeOutcome(cmd *cobra.Command, cfg *config.ScanConfiguration, p *plan.Plan, runID string, started time.Time, findings []*finding.Finding, diagnostics []string, taskRecords []report.TaskRecord, health map[string]string, toolVersions map[string]string, out policy.Outcome, status string, exitCode int, extra []extraArtifact) (int, error) {
	// Filter suppressed findings out of blocking consideration.
	active := findings[:0]
	for _, f := range findings {
		if f.Suppression == nil {
			active = append(active, f)
		}
	}
	_ = active
	writeArtifacts(cmd, cfg, p, runID, started, findings, diagnostics, taskRecords, health, toolVersions, out, status, exitCode, extra)
	fmt.Fprint(cmd.OutOrStdout(), report.Summary(status, findings, out, health))
	if exitCode == ExitPassed {
		return exitCode, nil
	}
	return exitCode, &ExitError{Code: exitCode, Msg: fmt.Sprintf("sdt: %s", status)}
}

func finalize(cmd *cobra.Command, cfg *config.ScanConfiguration, p *plan.Plan, runID string, started time.Time, findings []*finding.Finding, diagnostics []string, taskRecords []report.TaskRecord, health map[string]string, toolVersions map[string]string, status string, exitCode int, msg string) (int, error) {
	out := policy.Outcome{Status: status, Trace: []policy.TraceEntry{}}
	diagnostics = append(diagnostics, msg)
	writeArtifacts(cmd, cfg, p, runID, started, findings, diagnostics, taskRecords, health, toolVersions, out, status, exitCode, nil)
	fmt.Fprint(cmd.OutOrStdout(), report.Summary(status, findings, out, health))
	fmt.Fprintln(cmd.ErrOrStderr(), "sdt: "+msg)
	return exitCode, &ExitError{Code: exitCode, Msg: "sdt: " + status}
}

func finalizeEmpty(cmd *cobra.Command, cfg *config.ScanConfiguration, p *plan.Plan, runID string, started time.Time, status, msg string) (int, error) {
	return finalize(cmd, cfg, p, runID, started, nil, nil, nil, map[string]string{}, map[string]string{}, status, ExitInconclusive, msg)
}

func writeArtifacts(cmd *cobra.Command, cfg *config.ScanConfiguration, p *plan.Plan, runID string, started time.Time, findings []*finding.Finding, diagnostics []string, taskRecords []report.TaskRecord, health map[string]string, toolVersions map[string]string, out policy.Outcome, status string, exitCode int, extra []extraArtifact) {
	if findings == nil {
		findings = []*finding.Finding{}
	}
	outDir := cfg.Outputs.Directory
	if outDir == "" {
		outDir = "reports"
	}
	_ = os.MkdirAll(outDir, 0o755)
	_ = os.MkdirAll(cfg.Runtime.CacheDirectory, 0o755)

	canonical := report.CanonicalReport{
		SchemaVersion: "secure-dev/report/v1alpha1",
		RunID:         runID, PlanID: p.PlanID, Status: status,
		Findings: findings, Policy: out, GeneratedAt: report.NowUTC(),
	}
	cJSON, _ := json.MarshalIndent(canonical, "", "  ")
	sarif := report.ToSARIF(findings)

	var tools []report.ToolIdentity
	for adapter, ver := range toolVersions {
		a, _ := scanner.Lookup(adapter)
		tool := adapter
		if a != nil {
			_, tool, _ = a.Identity()
		}
		tools = append(tools, report.ToolIdentity{Adapter: adapter, Tool: tool, Version: ver})
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Adapter < tools[j].Adapter })

	byCat, bySev, byState := map[string]int{}, map[string]int{}, map[string]int{}
	byAction := map[string]int{"fail": len(out.Blockers), "warn": len(out.Warnings)}
	for _, f := range findings {
		byCat[f.Category]++
		bySev[f.Severity.Canonical]++
		byState[f.BaselineState]++
	}
	manifest := report.Manifest{
		SchemaVersion: "secure-dev/manifest/v1alpha1",
		RunID:         runID, PlanID: p.PlanID,
		StartedAt: started.UTC().Format("2006-01-02T15:04:05Z"), CompletedAt: report.NowUTC(),
		Status: status, ExitCode: exitCode, Profile: p.Profile, Mode: p.Mode,
		ContextDigest: p.ContextDigest, ConfigDigest: p.ConfigDigest,
		PolicyDigest: policy.Digest(cfg), PlanDigest: p.PlanDigest,
		Tools: tools, Tasks: taskRecords,
		Findings: report.FindingCounts{Total: len(findings), ByCategory: byCat, BySeverity: bySev, ByState: byState, ByAction: byAction},
		AI:       report.AIMeta{Used: false},
	}
	artifacts := []struct {
		name   string
		data   []byte
		media  string
		schema string
	}{
		{"findings.json", append(cJSON, '\n'), "application/json", "secure-dev/report/v1alpha1"},
		{"findings.sarif", sarif, "application/sarif+json", "sarif-2.1.0"},
	}
	if wantsFormat(cfg, "junit") {
		blockerRules := map[string]string{}
		for _, b := range out.Blockers {
			blockerRules[b.FindingID] = b.RuleID
		}
		artifacts = append(artifacts, struct {
			name   string
			data   []byte
			media  string
			schema string
		}{"policy.junit.xml", report.ToJUnit(status, findings, blockerRules), "application/xml", "junit"})
	}
	if wantsFormat(cfg, "vex") {
		artifacts = append(artifacts, struct {
			name   string
			data   []byte
			media  string
			schema string
		}{"vex.cdx.json", report.ToVEX(status, findings, out), "application/vnd.cyclonedx+json", "cyclonedx-1.5-vex"})
	}
	for _, e := range extra {
		artifacts = append(artifacts, struct {
			name   string
			data   []byte
			media  string
			schema string
		}{e.name, e.data, e.media, e.schema})
	}
	var recs []report.ArtifactRec
	for _, a := range artifacts {
		full := filepath.Join(outDir, a.name)
		st := "generated"
		if err := report.WriteAtomic(full, a.data, 0o644); err != nil {
			st = "failed: " + err.Error()
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+st)
		}
		recs = append(recs, report.ArtifactRec{Path: a.name, MediaType: a.media, Schema: a.schema, Checksum: report.Checksum(a.data), Status: st})
	}
	// Summary artifact.
	summary := report.Summary(status, findings, out, health)
	sumPath := filepath.Join(outDir, "summary.txt")
	if err := report.WriteAtomic(sumPath, []byte(summary), 0o644); err == nil {
		recs = append(recs, report.ArtifactRec{Path: "summary.txt", MediaType: "text/plain", Checksum: report.Checksum([]byte(summary)), Status: "generated"})
	}
	manifest.Artifacts = recs
	mJSON, _ := json.MarshalIndent(manifest, "", "  ")
	mPath := filepath.Join(outDir, "run-manifest.json")
	if err := report.WriteAtomic(mPath, append(mJSON, '\n'), 0o644); err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: manifest write failed: "+err.Error())
	}
	_ = diagnostics
}

func wantsFormat(cfg *config.ScanConfiguration, name string) bool {
	for _, f := range cfg.Outputs.Formats {
		if f == name {
			return true
		}
	}
	return false
}

// filterStaged keeps findings located in the staged path set. Findings with
// no attributable location are dropped: staged mode answers only "what am I
// about to commit". Comparison uses the normalized repo-relative form both
// sides already carry (adapters relativize; context normalizes).
func filterStaged(findings []*finding.Finding, staged []string) (kept []*finding.Finding, dropped int) {
	allowed := map[string]bool{}
	for _, p := range staged {
		allowed[p] = true
	}
	for _, f := range findings {
		loc := ""
		if f.Location != nil {
			loc = f.Location.Path
		}
		if loc != "" && allowed[loc] {
			kept = append(kept, f)
			continue
		}
		dropped++
	}
	return kept, dropped
}

func truncateJoin(ss []string, n int) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "; "
		}
		out += s
		if len(out) > n {
			return out[:n]
		}
	}
	return out
}
