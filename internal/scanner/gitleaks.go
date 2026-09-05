package scanner

import (
	"encoding/json"
	"fmt"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"github.com/bhanuharya/secure-development-tools/internal/report"
)

func init() { Register(&GitleaksAdapter{}) }

// GitleaksAdapter supports current-tree / changed-history / full-history modes.
type GitleaksAdapter struct{}

func (a *GitleaksAdapter) Identity() (string, string, []string) {
	return "gitleaks", "gitleaks", []string{finding.CatSecret}
}

func (a *GitleaksAdapter) Validate(cfg *config.ScanConfiguration) []string { return nil }

func (a *GitleaksAdapter) Detect(root string, languages []string) Applicability {
	return Applicability{State: "applicable", Reason: "secret scan always applicable"}
}

// historyMode resolves the scan mode: explicit config history map wins,
// otherwise the profile scan mode decides (changed -> changed-history,
// repository -> full-history).
func gitleaksHistoryMode(cfg *config.ScanConfiguration, profile string, ctx *sdtctx.ScanContext) string {
	if m := cfg.Scanners.Gitleaks.History; len(m) > 0 {
		if v, ok := m[profile]; ok && v != "" {
			return v
		}
		if v, ok := m["default"]; ok && v != "" {
			return v
		}
	}
	if p, ok := cfg.Profiles[profile]; ok && p.Mode == "repository" {
		return "full"
	}
	return "changed"
}

func (a *GitleaksAdapter) Plan(ctx *sdtctx.ScanContext, cfg *config.ScanConfiguration, root string) (Task, error) {
	return a.PlanForProfile(ctx, cfg, root, "")
}

// PlanForProfile plans with an explicit profile name (history map lookup).
func (a *GitleaksAdapter) PlanForProfile(ctx *sdtctx.ScanContext, cfg *config.ScanConfiguration, root, profile string) (Task, error) {
	bin := whichBin(envOr("SDT_GITLEAKS_BIN", "gitleaks"))
	if bin == "" {
		return Task{}, fmt.Errorf("gitleaks executable not found")
	}
	reportPath, err := nativeReportPath(ctx.CacheRoot, "gitleaks.json")
	if err != nil {
		return Task{}, err
	}
	mode := gitleaksHistoryMode(cfg, profile, ctx)
	args := []string{"detect", "--source", root, "--report-format", "json", "--report-path", reportPath, "--redact", "--no-banner", "--exit-code", "0"}
	targets := []string{root}
	switch mode {
	case "full":
		args = append(args, "--log-opts=--all")
		targets = []string{root + "@history:all"}
	case "changed":
		base := ctx.MergeBase
		if base == "" {
			base = ctx.BaseRevision
		}
		if base != "" {
			args = append(args, "--log-opts="+base+".."+ctx.HeadRevision)
			targets = []string{root + "@history:" + base + "..HEAD"}
		} else {
			// No boundary: current tree only, visibly reduced coverage.
			args = append(args, "--no-git")
			mode = "tree (changed requested, no base revision)"
		}
	default: // "tree"
		args = append(args, "--no-git")
		mode = "tree"
	}
	if custom := cfg.Scanners.Gitleaks.Config; custom != "" {
		args = append(args, "--config", custom)
	}
	return Task{Adapter: "gitleaks", Tool: "gitleaks", Executable: bin, Args: args, Targets: targets, TimeoutSeconds: 600, ReportPath: reportPath, Mode: mode}, nil
}

func (a *GitleaksAdapter) Parse(toolVersion string, root string, stdout []byte, stderrRedacted string, nativeExit int) ParseResult {
	// gitleaks JSON comes from --report-path file; stdout carries the payload
	// when tests inject it directly. A missing/empty report is a failure,
	// never a silent zero-finding pass.
	payload := stdout
	if len(payload) == 0 {
		return ParseResult{Health: HealthMalformed, Diagnostics: []string{"gitleaks produced no native report (missing/empty output)"}}
	}
	var items []map[string]any
	if err := json.Unmarshal(payload, &items); err != nil {
		return ParseResult{Health: HealthMalformed, Diagnostics: []string{"gitleaks produced unreadable JSON"}}
	}
	var out []*finding.Finding
	for i, it := range items {
		ruleID, _ := it["RuleID"].(string)
		rawFile, _ := it["File"].(string)
		file := relToRoot(root, rawFile)
		desc, _ := it["Description"].(string)
		match, _ := it["Match"].(string)
		secret, _ := it["Secret"].(string)
		commit, _ := it["Commit"].(string)
		var sl, el *int
		if v, ok := it["StartLine"].(float64); ok {
			n := int(v)
			sl = &n
		}
		if v, ok := it["EndLine"].(float64); ok {
			n := int(v)
			el = &n
		}
		// Mandatory redaction: never persist raw secret/match.
		snippet := report.Redact(truncate(match, 200), secret)
		f := &finding.Finding{
			SchemaVersion: finding.SchemaVersion,
			ID:            fmt.Sprintf("gitleaks:%05d", i+1),
			Scanner:       finding.ScannerID{Adapter: "gitleaks", Tool: "gitleaks", Version: toolVersion},
			Category:      finding.CatSecret,
			Rule:          finding.Rule{ID: ruleID},
			Severity:      finding.Severity{Canonical: finding.SevHigh, Original: "high"},
			Message:       report.Redact(truncate(desc, 1000), secret),
			BaselineState: finding.StateUnknown,
			Redaction:     finding.Redaction{Applied: true},
		}
		if file != "" {
			f.Location = &finding.Location{Path: file, StartLine: sl, EndLine: el}
		}
		if snippet != "" {
			f.Evidence = &finding.Evidence{Text: snippet}
		}
		f.Remediation = &finding.Remediation{Guidance: "Rotate the leaked secret and remove it from source. Use CI/CD secrets or a vault."}
		if commit != "" {
			f.Message += " (commit " + shortHash(commit) + ")"
			f.Metadata = map[string]any{"commit": commit}
		}
		semCtx := ruleID + "\n" + file
		f.Fingerprint = finding.Fingerprint{Algorithm: finding.FingerprintVersion, Value: finding.FingerprintValue(f.Category, "gitleaks", ruleID, file, semCtx)}
		out = append(out, f)
	}
	return ParseResult{Findings: out, Health: HealthCompleted}
}
