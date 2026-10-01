package app

import (
	"fmt"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

const explainTemplateVersion = "sdt-explain/v1"

// explainDoc renders a local, template-based advisory explanation over
// redacted canonical findings (PRD AI-001, local mode).
//
// Guarantees: no network, secret-category evidence replaced with a
// placeholder, output labeled advisory and never authoritative.
func explainDoc(cfg *config.ScanConfiguration, findings []*finding.Finding, status string) string {
	var sb strings.Builder
	fmt.Fprintln(&sb, "# Advisory explanation (not authoritative)")
	fmt.Fprintln(&sb)
	fmt.Fprintln(&sb, "Do not treat this file as a policy decision. The recorded scan")
	fmt.Fprintf(&sb, "status is `%s`; this explanation cannot change severity,\n", status)
	fmt.Fprintln(&sb, "fingerprint, baseline state, suppression, or run status.")
	fmt.Fprintln(&sb)
	fmt.Fprintln(&sb, "Provenance:")
	fmt.Fprintln(&sb, "- provider: local-template (no network, no model call)")
	fmt.Fprintf(&sb, "- template: %s\n", explainTemplateVersion)
	fmt.Fprintf(&sb, "- findings: %d (secret evidence withheld)\n", len(findings))
	fmt.Fprintln(&sb, "- data-sharing: local-only")
	fmt.Fprintln(&sb)
	n := cfg.AI.SourceContextLines
	if n <= 0 {
		n = 20
	}
	for _, f := range findings {
		loc := ""
		if f.Location != nil {
			loc = f.Location.Path
			if f.Location.StartLine != nil {
				loc += fmt.Sprintf(":%d", *f.Location.StartLine)
			}
		}
		if f.Artifact != nil && f.Artifact.Package != "" {
			loc = f.Artifact.Package + " " + f.Artifact.InstalledVersion + " (" + f.Artifact.Target + ")"
		}
		fmt.Fprintf(&sb, "## %s — %s\n\n", f.ID, f.Rule.ID)
		fmt.Fprintf(&sb, "- Category: %s | Severity: %s | Baseline: %s\n", f.Category, f.Severity.Canonical, f.BaselineState)
		fmt.Fprintf(&sb, "- Where: %s\n", loc)
		fmt.Fprintf(&sb, "- Summary: %s\n", f.Message)
		if f.Category == finding.CatSecret {
			fmt.Fprintln(&sb, "- Evidence: [withheld: secret-category evidence is never sent to explanations]")
		} else if f.Evidence != nil && f.Evidence.Text != "" {
			fmt.Fprintf(&sb, "- Evidence (redacted): %s\n", firstLines(f.Evidence.Text, n))
		}
		if f.Remediation != nil && (f.Remediation.Guidance != "" || f.Remediation.FixedVersion != "") {
			g := f.Remediation.Guidance
			if f.Remediation.FixedVersion != "" {
				g = "Fixed version: " + f.Remediation.FixedVersion + ". " + g
			}
			fmt.Fprintf(&sb, "- Suggested next step: %s\n", g)
		}
		fmt.Fprintln(&sb)
	}
	return sb.String()
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
