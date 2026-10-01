package scanner

import (
	"encoding/json"
	"fmt"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"github.com/bhanuharya/secure-development-tools/internal/report"
)

func init() { Register(&TrivyImageAdapter{}) }

// TrivyImageAdapter scans an explicit image reference (release profiles).
type TrivyImageAdapter struct{}

func (a *TrivyImageAdapter) Identity() (string, string, []string) {
	return "trivy-image", "trivy", []string{finding.CatImgVuln, finding.CatMisconfig}
}

func (a *TrivyImageAdapter) Validate(cfg *config.ScanConfiguration) []string { return nil }

func (a *TrivyImageAdapter) Detect(root string, languages []string) Applicability {
	return Applicability{State: "applicable", Reason: "release image scan (requires --image)"}
}

func (a *TrivyImageAdapter) Plan(ctx *sdtctx.ScanContext, cfg *config.ScanConfiguration, root string) (Task, error) {
	if ctx.ImageReference == "" {
		return Task{}, fmt.Errorf("release profile requires an image reference (--image or SDT_IMAGE)")
	}
	bin := whichBin(envOr("SDT_TRIVY_BIN", "trivy"))
	if bin == "" {
		return Task{}, fmt.Errorf("trivy executable not found")
	}
	reportPath, err := nativeReportPath(ctx.CacheRoot, "trivy-image.json")
	if err != nil {
		return Task{}, err
	}
	args := []string{"image", "--quiet", "--format", "json",
		"--scanners", "vuln,misconfig",
		"--no-progress", "--exit-code", "0",
		"--output", reportPath, ctx.ImageReference}
	return Task{Adapter: "trivy-image", Tool: "trivy", Executable: bin, Args: args, Targets: []string{ctx.ImageReference}, TimeoutSeconds: 1800, ReportPath: reportPath}, nil
}

func (a *TrivyImageAdapter) Parse(toolVersion string, root string, stdout []byte, stderrRedacted string, nativeExit int) ParseResult {
	if nativeExit != 0 {
		return ParseResult{Health: HealthFailed, Diagnostics: []string{fmt.Sprintf("trivy image exited %d: %s", nativeExit, truncate(stderrRedacted, 300))}}
	}
	// A missing/empty native report is a failure, never a silent zero-finding pass.
	if len(stdout) == 0 {
		return ParseResult{Health: HealthMalformed, Diagnostics: []string{"trivy image produced no native report (missing/empty output)"}}
	}
	var data struct {
		Metadata struct {
			ImageID     string   `json:"ImageID"`
			RepoDigests []string `json:"RepoDigests"`
		} `json:"Metadata"`
		Results []struct {
			Target          string `json:"Target"`
			Class           string `json:"Class"`
			Type            string `json:"Type"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Description      string `json:"Description"`
			} `json:"Vulnerabilities"`
			Misconfigurations []struct {
				ID       string `json:"ID"`
				Title    string `json:"Title"`
				Message  string `json:"Message"`
				Desc     string `json:"Description"`
				Severity string `json:"Severity"`
			} `json:"Misconfigurations"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(stdout, &data); err != nil {
		return ParseResult{Health: HealthMalformed, Diagnostics: []string{"trivy image produced unreadable JSON"}}
	}
	// Resolved image identity: RepoDigest when the registry reports one,
	// otherwise the content ImageID. Recorded on every finding (SCAN-004).
	resolved := ""
	for _, digest := range data.Metadata.RepoDigests {
		if digest != "" {
			resolved = digest
			break
		}
	}
	if resolved == "" && data.Metadata.ImageID != "" {
		resolved = "imageID:" + data.Metadata.ImageID
	}
	if resolved == "" {
		return ParseResult{Health: HealthMalformed, Diagnostics: []string{"trivy image omitted immutable image identity"}}
	}
	var out []*finding.Finding
	n := 0
	for _, target := range data.Results {
		for _, v := range target.Vulnerabilities {
			n++
			f := &finding.Finding{
				SchemaVersion: finding.SchemaVersion,
				ID:            fmt.Sprintf("trivy-image:%05d", n),
				Scanner:       finding.ScannerID{Adapter: "trivy-image", Tool: "trivy", Version: toolVersion},
				Category:      finding.CatImgVuln,
				Rule:          finding.Rule{ID: v.VulnerabilityID},
				Severity:      finding.MapSeverity(v.Severity),
				Message:       report.Redact(truncate(v.Description, 1000)),
				Artifact:      &finding.Artifact{Package: v.PkgName, InstalledVersion: v.InstalledVersion, FixedVersion: v.FixedVersion, Target: target.Target, Image: resolved},
				BaselineState: finding.StateUnknown,
				Redaction:     finding.Redaction{Applied: true},
			}
			// Immutable image identity anchors the fingerprint: the same
			// CVE in two different images must never share an identity.
			semCtx := resolved + "\n" + v.VulnerabilityID + "\n" + v.PkgName + "@" + v.InstalledVersion
			f.Fingerprint = finding.Fingerprint{Algorithm: finding.FingerprintVersion, Value: finding.FingerprintValue(f.Category, "trivy-image", v.VulnerabilityID, target.Target+"|"+resolved, semCtx)}
			out = append(out, f)
		}
		for _, m := range target.Misconfigurations {
			n++
			guidance := m.Message
			if guidance == "" {
				guidance = m.Desc
			}
			f := &finding.Finding{
				SchemaVersion: finding.SchemaVersion,
				ID:            fmt.Sprintf("trivy-image:%05d", n),
				Scanner:       finding.ScannerID{Adapter: "trivy-image", Tool: "trivy", Version: toolVersion},
				Category:      finding.CatMisconfig,
				Rule:          finding.Rule{ID: m.ID},
				Severity:      finding.MapSeverity(m.Severity),
				Message:       report.Redact(truncate(m.Title, 1000)),
				Artifact:      &finding.Artifact{Target: target.Target, Image: resolved},
				BaselineState: finding.StateUnknown,
				Redaction:     finding.Redaction{Applied: true},
				Remediation:   &finding.Remediation{Guidance: report.Redact(truncate(guidance, 1000))},
			}
			semCtx := resolved + "\n" + m.ID + "\n" + target.Target
			f.Fingerprint = finding.Fingerprint{Algorithm: finding.FingerprintVersion, Value: finding.FingerprintValue(f.Category, "trivy-image", m.ID, target.Target+"|"+resolved, semCtx)}
			out = append(out, f)
		}
	}
	return ParseResult{Findings: out, Health: HealthCompleted}
}
