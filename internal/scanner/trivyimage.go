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
	if len(stdout) == 0 {
		return ParseResult{Health: HealthCompleted}
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
		} `json:"Results"`
	}
	if err := json.Unmarshal(stdout, &data); err != nil {
		return ParseResult{Health: HealthMalformed, Diagnostics: []string{"trivy image produced unreadable JSON"}}
	}
	// Resolved image identity: RepoDigest when the registry reports one,
	// otherwise the content ImageID. Recorded on every finding (SCAN-004).
	resolved := ""
	if len(data.Metadata.RepoDigests) > 0 {
		resolved = data.Metadata.RepoDigests[0]
	} else if data.Metadata.ImageID != "" {
		resolved = "imageID:" + data.Metadata.ImageID
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
			semCtx := v.VulnerabilityID + "\n" + v.PkgName + "@" + v.InstalledVersion
			f.Fingerprint = finding.Fingerprint{Algorithm: finding.FingerprintVersion, Value: finding.FingerprintValue(f.Category, "trivy-image", v.VulnerabilityID, target.Target, semCtx)}
			out = append(out, f)
		}
	}
	return ParseResult{Findings: out, Health: HealthCompleted}
}
