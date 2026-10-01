// Package report: CycloneDX SBOM merge + VEX statement builders (Bet 4).
//
// VEX honesty rules, enforced by construction:
//   - Only dependency/image vulnerability findings become statements.
//     SAST, secrets, and misconfigurations are out of VEX scope.
//   - "not_affected" is never emitted: sdt cannot prove non-exploitability.
//     Suppressed findings map to in_triage with the suppression recorded,
//     never to a clean bill of health.
//   - Component refs are best-effort purls derived from the scan target.
//     Exact trivy-purl alignment is a documented limitation.
package report

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
)

// ToVEX renders CycloneDX 1.5 VEX statements for dependency/image findings.
// blockers maps finding IDs that failed policy.
func ToVEX(status string, findings []*finding.Finding, out policy.Outcome) []byte {
	_ = status
	blockerRules := map[string]string{}
	for _, b := range out.Blockers {
		blockerRules[b.FindingID] = b.RuleID
	}
	type rating struct {
		Severity string `json:"severity"`
		Method   string `json:"method"`
	}
	type analysis struct {
		State  string `json:"state"`
		Detail string `json:"detail,omitempty"`
	}
	type affect struct {
		Ref string `json:"ref"`
	}
	type vuln struct {
		BomRef string `json:"bomRef"`
		ID     string `json:"id"`
		Source struct {
			Name string `json:"name"`
		} `json:"source"`
		Ratings  []rating `json:"ratings"`
		Analysis analysis `json:"analysis"`
		Affects  []affect `json:"affects"`
	}
	var vulns []vuln
	for _, f := range findings {
		if f.Category != finding.CatDepVuln && f.Category != finding.CatImgVuln {
			continue
		}
		if f.Artifact == nil || f.Artifact.Package == "" {
			continue
		}
		ref := componentRef(f)
		v := vuln{BomRef: ref, ID: f.Rule.ID}
		v.Source.Name = "sdt"
		v.Ratings = []rating{{Severity: vexSeverity(f.Severity.Canonical), Method: "other"}}
		state := "in_triage"
		detail := ""
		if _, ok := blockerRules[f.ID]; ok {
			state = "exploitable"
		}
		if f.Suppression != nil {
			state = "in_triage"
			detail = fmt.Sprintf("suppressed by %s: %s", f.Suppression.ExceptionID, f.Suppression.Reason)
		}
		v.Analysis = analysis{State: state, Detail: detail}
		v.Affects = []affect{{Ref: ref}}
		vulns = append(vulns, v)
	}
	if vulns == nil {
		vulns = []vuln{}
	}
	sort.Slice(vulns, func(i, j int) bool {
		if vulns[i].ID != vulns[j].ID {
			return vulns[i].ID < vulns[j].ID
		}
		return vulns[i].BomRef < vulns[j].BomRef
	})
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"timestamp": NowUTC(),
			"tools": []any{map[string]any{
				"vendor": "secure-development-tools",
				"name":   "sdt",
			}},
		},
		"vulnerabilities": vulns,
	}
	raw, _ := json.MarshalIndent(doc, "", "  ")
	return append(raw, '\n')
}

func vexSeverity(canonical string) string {
	switch canonical {
	case "critical", "high", "medium", "low", "info":
		return canonical
	default:
		return "unknown"
	}
}

// componentRef builds a best-effort purl for a dependency finding from its
// scan target filename. OS packages from image scans (no ecosystem signal in
// the finding) fall back to pkg:generic.
func componentRef(f *finding.Finding) string {
	name := f.Artifact.Package
	ver := f.Artifact.InstalledVersion
	target := ""
	if f.Artifact.Target != "" {
		target = filepath.Base(f.Artifact.Target)
	}
	typ := "generic"
	lower := strings.ToLower(name)
	switch target {
	case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
		typ = "npm"
	case "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "setup.py", "setup.cfg", "pyproject.toml":
		typ = "pypi"
		lower = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		name = lower
	case "go.mod", "go.sum":
		typ = "golang"
	case "pom.xml":
		typ = "maven"
	case "build.gradle", "build.gradle.kts":
		typ = "maven"
	case "Cargo.lock", "Cargo.toml":
		typ = "cargo"
	case "Gemfile.lock", "Gemfile":
		typ = "gem"
	case "composer.lock", "composer.json":
		typ = "composer"
	case "packages.config", ".csproj":
		typ = "nuget"
	}
	// purl-escape the name minimally (scope slashes are legal in purls).
	name = strings.ReplaceAll(name, " ", "%20")
	if ver != "" {
		return fmt.Sprintf("pkg:%s/%s@%s", typ, name, ver)
	}
	return fmt.Sprintf("pkg:%s/%s", typ, name)
}

// MergeCycloneDX merges trivy CycloneDX documents (fs + image) into one bom:
// components concatenated and deduped by bom-ref, services/vulnerabilities
// concatenated, metadata serialNumber refreshed with an sdt note.
func MergeCycloneDX(docs ...[]byte) ([]byte, error) {
	var merged map[string]any
	var components []any
	seen := map[string]bool{}
	var vulns []any
	var serials []string
	for _, d := range docs {
		if len(d) == 0 {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(d, &doc); err != nil {
			return nil, fmt.Errorf("parse cyclonedx doc: %w", err)
		}
		if merged == nil {
			merged = doc
		}
		if s, _ := doc["serialNumber"].(string); s != "" {
			serials = append(serials, s)
		}
		if cs, ok := doc["components"].([]any); ok {
			for _, c := range cs {
				ref := ""
				if m, ok := c.(map[string]any); ok {
					ref, _ = m["bom-ref"].(string)
				}
				if ref == "" {
					if raw, err := json.Marshal(c); err == nil {
						ref = "no-ref:" + Checksum(raw)
					}
				}
				if seen[ref] {
					continue
				}
				seen[ref] = true
				components = append(components, c)
			}
		}
		if vs, ok := doc["vulnerabilities"].([]any); ok {
			vulns = append(vulns, vs...)
		}
	}
	if merged == nil {
		return nil, fmt.Errorf("no cyclonedx documents to merge")
	}
	merged["components"] = components
	if vulns != nil {
		merged["vulnerabilities"] = vulns
	}
	if md, ok := merged["metadata"].(map[string]any); ok {
		md["timestamp"] = NowUTC()
	} else {
		merged["metadata"] = map[string]any{"timestamp": NowUTC()}
	}
	delete(merged, "serialNumber")
	if len(serials) > 0 {
		merged["metadata"].(map[string]any)["comment"] = fmt.Sprintf("merged by sdt from %d trivy bom(s)", len(serials))
	}
	raw, _ := json.MarshalIndent(merged, "", "  ")
	return append(raw, '\n'), nil
}
