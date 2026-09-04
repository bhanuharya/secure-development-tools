package scanner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"github.com/bhanuharya/secure-development-tools/internal/report"
)

func init() { Register(&TrivyFSAdapter{}) }

// TrivyFSAdapter scans filesystem vulnerability + misconfiguration.
// Secret scanning is intentionally disabled (Gitleaks owns secrets).
type TrivyFSAdapter struct{}

func (a *TrivyFSAdapter) Identity() (string, string, []string) {
	return "trivy-fs", "trivy", []string{finding.CatDepVuln, finding.CatMisconfig}
}

func (a *TrivyFSAdapter) Validate(cfg *config.ScanConfiguration) []string { return nil }

func (a *TrivyFSAdapter) Detect(root string, languages []string) Applicability {
	return Applicability{State: "applicable", Reason: "filesystem scan always applicable"}
}

func (a *TrivyFSAdapter) Plan(ctx *sdtctx.ScanContext, cfg *config.ScanConfiguration, root string) (Task, error) {
	bin := whichBin(envOr("SDT_TRIVY_BIN", "trivy"))
	if bin == "" {
		return Task{}, fmt.Errorf("trivy executable not found")
	}
	reportPath, err := nativeReportPath(ctx.CacheRoot, "trivy-fs.json")
	if err != nil {
		return Task{}, err
	}
	sev := envOr("SDT_TRIVY_SEVERITY", "CRITICAL,HIGH,MEDIUM")
	args := []string{"fs", "--quiet", "--format", "json",
		"--scanners", "vuln,misconfig",
		"--severity", sev,
		"--no-progress", "--exit-code", "0",
		"--skip-dirs", ".git,node_modules,vendor,dist,build,.venv,venv,target,__pycache__",
		"--output", reportPath, root}
	timeout := 1200
	return Task{Adapter: "trivy-fs", Tool: "trivy", Executable: bin, Args: args, Targets: []string{root}, TimeoutSeconds: timeout, ReportPath: reportPath}, nil
}

func (a *TrivyFSAdapter) Parse(toolVersion string, root string, stdout []byte, stderrRedacted string, nativeExit int) ParseResult {
	if nativeExit != 0 {
		return ParseResult{Health: HealthFailed, Diagnostics: []string{fmt.Sprintf("trivy exited %d: %s", nativeExit, truncate(stderrRedacted, 300))}}
	}
	if len(stdout) == 0 {
		return ParseResult{Health: HealthCompleted}
	}
	var data struct {
		SchemaVersion int    `json:"SchemaVersion"`
		ArtifactName  string `json:"ArtifactName"`
		Results       []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string   `json:"VulnerabilityID"`
				PkgName          string   `json:"PkgName"`
				InstalledVersion string   `json:"InstalledVersion"`
				FixedVersion     string   `json:"FixedVersion"`
				Severity         string   `json:"Severity"`
				Description      string   `json:"Description"`
				CweIDs           []string `json:"CweIDs"`
				References       []string `json:"References"`
			} `json:"Vulnerabilities"`
			Misconfigurations []struct {
				ID            string `json:"ID"`
				Title         string `json:"Title"`
				Message       string `json:"Message"`
				Severity      string `json:"Severity"`
				CauseMetadata struct {
					StartLine int `json:"StartLine"`
					EndLine   int `json:"EndLine"`
				} `json:"CauseMetadata"`
			} `json:"Misconfigurations"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(stdout, &data); err != nil {
		return ParseResult{Health: HealthMalformed, Diagnostics: []string{"trivy produced unreadable JSON"}}
	}
	var out []*finding.Finding
	n := 0
	for _, target := range data.Results {
		tgt := relToRoot(root, target.Target)
		for _, v := range target.Vulnerabilities {
			n++
			rem := fmt.Sprintf("Upgrade %s from %s", v.PkgName, v.InstalledVersion)
			if v.FixedVersion != "" {
				rem += " to " + v.FixedVersion
			}
			f := &finding.Finding{
				SchemaVersion: finding.SchemaVersion,
				ID:            fmt.Sprintf("trivy-fs:%05d", n),
				Scanner:       finding.ScannerID{Adapter: "trivy-fs", Tool: "trivy", Version: toolVersion},
				Category:      finding.CatDepVuln,
				Rule:          finding.Rule{ID: v.VulnerabilityID, CWE: v.CweIDs, References: v.References},
				Severity:      finding.MapSeverity(v.Severity),
				Message:       report.Redact(truncate(v.Description, 1000)),
				Artifact:      &finding.Artifact{Package: v.PkgName, InstalledVersion: v.InstalledVersion, FixedVersion: v.FixedVersion, Target: tgt},
				BaselineState: finding.StateUnknown,
				Redaction:     finding.Redaction{Applied: true},
			}
			f.Remediation = &finding.Remediation{FixedVersion: v.FixedVersion, Guidance: rem}
			semCtx := v.VulnerabilityID + "\n" + v.PkgName + "@" + v.InstalledVersion + "\n" + tgt
			f.Fingerprint = finding.Fingerprint{Algorithm: finding.FingerprintVersion, Value: finding.FingerprintValue(f.Category, "trivy-fs", v.VulnerabilityID, tgt, semCtx)}
			out = append(out, f)
		}
		for _, m := range target.Misconfigurations {
			n++
			sl, el := m.CauseMetadata.StartLine, m.CauseMetadata.EndLine
			f := &finding.Finding{
				SchemaVersion: finding.SchemaVersion,
				ID:            fmt.Sprintf("trivy-fs:%05d", n),
				Scanner:       finding.ScannerID{Adapter: "trivy-fs", Tool: "trivy", Version: toolVersion},
				Category:      finding.CatMisconfig,
				Rule:          finding.Rule{ID: m.ID},
				Severity:      finding.MapSeverity(m.Severity),
				Message:       report.Redact(truncate(m.Title, 1000)),
				BaselineState: finding.StateUnknown,
				Redaction:     finding.Redaction{Applied: true},
				Remediation:   &finding.Remediation{Guidance: truncate(m.Message, 1000)},
			}
			if tgt != "" {
				f.Location = &finding.Location{Path: tgt}
				if sl != 0 {
					f.Location.StartLine = &sl
				}
				if el != 0 {
					f.Location.EndLine = &el
				}
			}
			semCtx := m.ID + "\n" + tgt
			f.Fingerprint = finding.Fingerprint{Algorithm: finding.FingerprintVersion, Value: finding.FingerprintValue(f.Category, "trivy-fs", m.ID, tgt, semCtx)}
			out = append(out, f)
		}
	}
	_ = strings.TrimSpace
	return ParseResult{Findings: out, Health: HealthCompleted}
}
