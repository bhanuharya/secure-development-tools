package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"github.com/bhanuharya/secure-development-tools/internal/report"
)

func init() { Register(&OpengrepAdapter{}) }

// OpengrepBinary resolves the engine binary for out-of-band invocations
// (rule validation and testing). Empty when no engine is installed.
func OpengrepBinary() string {
	return whichBin(envOr("SDT_OPENGREP_BIN", "opengrep"), "semgrep")
}

// IsOpenGrep reports whether the resolved engine supports OpenGrep-only
// flags such as --taint-intrafile.
func IsOpenGrep(bin string) bool {
	return bin != "" && !strings.Contains(filepath.Base(bin), "semgrep")
}

// OpengrepAdapter runs locked Semgrep-compatible rules and normalizes SAST findings.
type OpengrepAdapter struct{}

func (a *OpengrepAdapter) Identity() (string, string, []string) {
	return "opengrep", "opengrep", []string{finding.CatSAST}
}

func (a *OpengrepAdapter) Validate(cfg *config.ScanConfiguration) []string {
	return nil
}

func (a *OpengrepAdapter) Detect(root string, languages []string) Applicability {
	rules := ruleFiles(root, languages)
	if len(rules) == 0 {
		return Applicability{State: "not_applicable", Reason: "no matching local rules for detected languages"}
	}
	return Applicability{State: "applicable", Reason: fmt.Sprintf("%d rule files", len(rules))}
}

func (a *OpengrepAdapter) Plan(ctx *sdtctx.ScanContext, cfg *config.ScanConfiguration, root string) (Task, error) {
	bin := whichBin(envOr("SDT_OPENGREP_BIN", "opengrep"), "semgrep")
	if bin == "" {
		return Task{}, fmt.Errorf("opengrep executable not found")
	}
	langs := detectLanguages(root)
	rules := ruleFiles(root, langs)
	if len(rules) == 0 {
		return Task{}, fmt.Errorf("no rules: visible configuration failure (no matching rule files)")
	}
	args := []string{"scan", "--json", "--no-git-ignore"}
	isOpenGrep := IsOpenGrep(bin)
	if isOpenGrep {
		args = append(args, "-q", "--timeout", "60", "--max-target-bytes", "5000000",
			// Cross-function taint within one file: OpenGrep's depth edge
			// over Semgrep CE. Required for taint-mode rules to track
			// sources to sinks across function boundaries. Semgrep CE
			// rejects the flag, so it stays OpenGrep-only.
			"--taint-intrafile")
	} else {
		args = append(args, "--quiet")
	}
	for _, r := range rules {
		args = append(args, "--config", r)
	}
	for _, x := range opengrepExcludes() {
		args = append(args, "--exclude", x)
	}
	target := root
	args = append(args, target)
	timeout := 600
	return Task{Adapter: "opengrep", Tool: "opengrep", Executable: bin, Args: args, Targets: []string{target}, TimeoutSeconds: timeout, RuleBundle: "secure-default", RuleChecksums: checksumFiles(rules)}, nil
}

func (a *OpengrepAdapter) Parse(toolVersion string, root string, stdout []byte, stderrRedacted string, nativeExit int) ParseResult {
	if nativeExit != 0 && nativeExit != 1 {
		if nativeExit >= 2 && nativeExit <= 8 {
			return ParseResult{Health: HealthFailed, Diagnostics: []string{fmt.Sprintf("opengrep rule/config error (exit %d): %s", nativeExit, truncate(stderrRedacted, 300))}}
		}
		return ParseResult{Health: HealthFailed, Diagnostics: []string{fmt.Sprintf("opengrep exited %d: %s", nativeExit, truncate(stderrRedacted, 300))}}
	}
	var data struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
				Col  int `json:"col"`
			} `json:"start"`
			End struct {
				Line int `json:"line"`
				Col  int `json:"col"`
			} `json:"end"`
			Extra struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
				Fix      string `json:"fix"`
				Metadata struct {
					CWE        any    `json:"cwe"`
					OWASP      any    `json:"owasp"`
					References any    `json:"references"`
					Category   string `json:"category"`
				} `json:"metadata"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout, &data); err != nil {
		return ParseResult{Health: HealthMalformed, Diagnostics: []string{"opengrep returned invalid JSON"}}
	}
	var out []*finding.Finding
	for i, r := range data.Results {
		sev := finding.MapSeverity(r.Extra.Severity)
		if sev.Canonical == finding.SevInfo && r.Extra.Metadata.Category == "security" {
			sev.Canonical = finding.SevMedium
		}
		ruleID := cleanRuleID(r.CheckID)
		msg := report.Redact(truncate(r.Extra.Message, 1000))
		sl, el := r.Start.Line, r.End.Line
		rel := relToRoot(root, r.Path)
		f := &finding.Finding{
			SchemaVersion: finding.SchemaVersion,
			ID:            fmt.Sprintf("opengrep:%05d", i+1),
			Scanner:       finding.ScannerID{Adapter: "opengrep", Tool: "opengrep", Version: toolVersion},
			Category:      finding.CatSAST,
			Rule:          finding.Rule{ID: ruleID, CWE: toStringList(r.Extra.Metadata.CWE, true)},
			Severity:      sev,
			Message:       msg,
			Location:      &finding.Location{Path: rel, StartLine: &sl, EndLine: &el},
			BaselineState: finding.StateUnknown,
			Redaction:     finding.Redaction{Applied: true},
		}
		if r.Extra.Fix != "" {
			f.Remediation = &finding.Remediation{Guidance: truncate(r.Extra.Fix, 1000)}
		}
		semCtx := ruleID + "\n" + msg
		f.Fingerprint = finding.Fingerprint{Algorithm: finding.FingerprintVersion, Value: finding.FingerprintValue(f.Category, "opengrep", ruleID, rel, semCtx)}
		out = append(out, f)
	}
	return ParseResult{Findings: out, Health: HealthCompleted}
}

func ruleFiles(root string, languages []string) []string {
	pack := envOr("SDT_RULES_PACK_DIR", filepath.Join(root, "rules", "opengrep-rules"))
	// Fall back to repo-bundled rules when scanning fixtures elsewhere.
	if _, err := os.Stat(pack); err != nil {
		if alt := envOr("SDT_DEFAULT_RULES_DIR", "rules/opengrep-rules"); alt != "" {
			if _, err2 := os.Stat(alt); err2 == nil {
				pack = alt
			}
		}
	}
	var files []string
	subs := append([]string{"common"}, languages...)
	for _, s := range subs {
		d := filepath.Join(pack, s)
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			if isRuleFile(n) {
				files = append(files, filepath.Join(d, n))
			}
		}
	}
	// Vendored third-party.
	vendor := filepath.Join(pack, "vendor")
	_ = filepath.Walk(vendor, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if isRuleFile(filepath.Base(p)) {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	// Dedupe.
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		h := sha256.Sum256([]byte(f))
		k := hex.EncodeToString(h[:])
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
