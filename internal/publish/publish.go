// Package publish translates finalized SDT reports into provider payloads.
//
// Boundary (PRD PUB-001): consumes saved findings.json/run-manifest.json,
// never reruns scanners or reevaluates policy, never rewrites the recorded
// decision. All writers are offline file builders; delivery (API calls)
// stays outside the MVP core.
package publish

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

const maxAnnotations = 50

// Blockers builds a blocker-ID set from finding IDs.
func Blockers(ids []string) map[string]bool {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// locOf extracts a SARIF-style relative location.
func locOf(f *finding.Finding) (path string, start, end int) {
	if f.Location == nil {
		return "", 0, 0
	}
	if f.Location.StartLine != nil {
		start = *f.Location.StartLine
	}
	if f.Location.EndLine != nil {
		end = *f.Location.EndLine
	} else {
		end = start
	}
	return f.Location.Path, start, end
}

func levelOf(sev string) string {
	switch sev {
	case "critical", "high":
		return "failure"
	case "medium":
		return "warning"
	default:
		return "notice"
	}
}

func titleOf(f *finding.Finding) string {
	return fmt.Sprintf("[%s] %s", f.Severity.Canonical, f.Rule.ID)
}

// ordered returns blocking findings first, then by severity rank.
func ordered(findings []*finding.Finding, blockers map[string]bool) []*finding.Finding {
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
	out := append([]*finding.Finding{}, findings...)
	sort.SliceStable(out, func(i, j int) bool {
		bi, bj := blockers[out[i].ID], blockers[out[j].ID]
		if bi != bj {
			return bi
		}
		return rank[out[i].Severity.Canonical] < rank[out[j].Severity.Canonical]
	})
	return out
}

// GitHub builds check-run annotations + a step summary (offline files).
func GitHub(findings []*finding.Finding, blockers map[string]bool, status string) (annotations []byte, summary string) {
	type annotation struct {
		Path            string `json:"path"`
		StartLine       int    `json:"start_line,omitempty"`
		EndLine         int    `json:"end_line,omitempty"`
		AnnotationLevel string `json:"annotation_level"`
		Message         string `json:"message"`
		Title           string `json:"title"`
	}
	var anns []annotation
	for _, f := range ordered(findings, blockers) {
		if len(anns) >= maxAnnotations {
			break
		}
		path, start, end := locOf(f)
		if path == "" {
			continue
		}
		anns = append(anns, annotation{
			Path: path, StartLine: start, EndLine: end,
			AnnotationLevel: levelOf(f.Severity.Canonical),
			Message:         f.Message, Title: titleOf(f),
		})
	}
	if anns == nil {
		anns = []annotation{}
	}
	raw, _ := json.MarshalIndent(anns, "", "  ")
	var sb strings.Builder
	fmt.Fprintf(&sb, "## sdt scan: %s\n\n", status)
	fmt.Fprintf(&sb, "Findings: %d (annotations capped at %d, blocking first)\n", len(findings), maxAnnotations)
	return append(raw, '\n'), sb.String()
}

// Bitbucket builds a Code Insights report payload (offline file).
func Bitbucket(findings []*finding.Finding, blockers map[string]bool, status string) []byte {
	type annotation struct {
		Path     string `json:"path"`
		Line     int    `json:"line,omitempty"`
		Message  string `json:"message"`
		Severity string `json:"severity"`
	}
	nBlock := 0
	for _, f := range findings {
		if blockers[f.ID] {
			nBlock++
		}
	}
	result := "PASS"
	if nBlock > 0 {
		result = "FAIL"
	}
	var anns []annotation
	for _, f := range ordered(findings, blockers) {
		if len(anns) >= maxAnnotations {
			break
		}
		path, start, _ := locOf(f)
		if path == "" {
			continue
		}
		anns = append(anns, annotation{Path: path, Line: start, Message: titleOf(f) + ": " + f.Message, Severity: strings.ToUpper(f.Severity.Canonical)})
	}
	if anns == nil {
		anns = []annotation{}
	}
	doc := map[string]any{
		"title": "sdt scan", "result": result, "reporter": "sdt",
		"details":     fmt.Sprintf("%d findings, %d blocking (status %s)", len(findings), nBlock, status),
		"annotations": anns,
	}
	raw, _ := json.MarshalIndent(doc, "", "  ")
	return append(raw, '\n')
}

// GitLab builds a Code Quality (Code Climate) report (offline file).
func GitLab(findings []*finding.Finding, blockers map[string]bool) []byte {
	type issue struct {
		Description string `json:"description"`
		Fingerprint string `json:"fingerprint"`
		Severity    string `json:"severity"`
		Location    struct {
			Path  string `json:"path"`
			Lines struct {
				Begin int `json:"begin"`
				End   int `json:"end,omitempty"`
			} `json:"lines"`
		} `json:"location"`
	}
	sevMap := map[string]string{"critical": "blocker", "high": "critical", "medium": "major", "low": "minor", "info": "info", "unknown": "info"}
	var out []issue
	for _, f := range ordered(findings, blockers) {
		if len(out) >= maxAnnotations {
			break
		}
		path, start, end := locOf(f)
		if path == "" {
			continue
		}
		var is issue
		is.Description = titleOf(f) + ": " + f.Message
		is.Fingerprint = f.Fingerprint.Value
		is.Severity = sevMap[f.Severity.Canonical]
		is.Location.Path = path
		is.Location.Lines.Begin = start
		is.Location.Lines.End = end
		out = append(out, is)
	}
	if out == nil {
		out = []issue{}
	}
	raw, _ := json.MarshalIndent(out, "", "  ")
	return append(raw, '\n')
}
