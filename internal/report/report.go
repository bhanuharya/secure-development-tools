// Package report finalizes run artifacts atomically (PRD OUT-001/002/003).
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"github.com/bhanuharya/secure-development-tools/internal/plan"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
)

// Manifest is the run-manifest minimum field set (PRD Appendix B).
type Manifest struct {
	SchemaVersion string         `json:"schemaVersion"`
	RunID         string         `json:"runId"`
	PlanID        string         `json:"planId"`
	StartedAt     string         `json:"startedAt"`
	CompletedAt   string         `json:"completedAt"`
	Status        string         `json:"status"`
	ExitCode      int            `json:"exitCode"`
	Profile       string         `json:"profile"`
	Mode          string         `json:"mode,omitempty"`
	ContextDigest string         `json:"contextDigest"`
	ConfigDigest  string         `json:"configDigest"`
	PolicyDigest  string         `json:"policyDigest"`
	PlanDigest    string         `json:"planDigest"`
	Tools         []ToolIdentity `json:"tools"`
	Tasks         []TaskRecord   `json:"tasks"`
	Findings      FindingCounts  `json:"findings"`
	Artifacts     []ArtifactRec  `json:"artifacts"`
	AI            AIMeta         `json:"ai"`
}

type ToolIdentity struct {
	Adapter string `json:"adapter"`
	Tool    string `json:"tool"`
	Version string `json:"version"`
}

type TaskRecord struct {
	Adapter    string `json:"adapter"`
	State      string `json:"state"`
	NativeExit int    `json:"nativeExit,omitempty"`
	DurationMS int64  `json:"durationMs,omitempty"`
	Diagnostic string `json:"diagnostic,omitempty"`
}

type FindingCounts struct {
	Total      int            `json:"total"`
	ByCategory map[string]int `json:"byCategory"`
	BySeverity map[string]int `json:"bySeverity"`
	ByState    map[string]int `json:"byState"`
	ByAction   map[string]int `json:"byAction"`
}

type ArtifactRec struct {
	Path      string `json:"path"`
	MediaType string `json:"mediaType"`
	Schema    string `json:"schema,omitempty"`
	Checksum  string `json:"checksum"`
	Status    string `json:"status"`
}

type AIMeta struct {
	Used bool `json:"used"`
}

// CanonicalReport is findings.json content.
type CanonicalReport struct {
	SchemaVersion string             `json:"schemaVersion"`
	RunID         string             `json:"runId"`
	PlanID        string             `json:"planId"`
	Status        string             `json:"status"`
	Findings      []*finding.Finding `json:"findings"`
	Policy        policy.Outcome     `json:"policy"`
	GeneratedAt   string             `json:"generatedAt"`
}

// WriteAtomic writes a file atomically (tmp + rename).
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// Summary renders the human console summary.
func Summary(status string, findings []*finding.Finding, out policy.Outcome, health map[string]string) string {
	var sb strings.Builder
	bySev := map[string]int{}
	for _, f := range findings {
		bySev[f.Severity.Canonical]++
	}
	fmt.Fprintf(&sb, "sdt: status=%s findings=%d (critical=%d high=%d medium=%d low=%d info=%d unknown=%d) blockers=%d warnings=%d\n",
		status, len(findings), bySev["critical"], bySev["high"], bySev["medium"], bySev["low"], bySev["info"], bySev["unknown"],
		len(out.Blockers), len(out.Warnings))
	var names []string
	for k := range health {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&sb, "  scanner %-12s %s\n", n, health[n])
	}
	for _, b := range out.Blockers {
		fmt.Fprintf(&sb, "  BLOCK %s %s (%s)\n", b.FindingID, b.Fingerprint[:min(19, len(b.Fingerprint))], b.RuleID)
	}
	return sb.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SARIF 2.1.0 generation from canonical findings.
func ToSARIF(findings []*finding.Finding) []byte {
	rules := map[string]map[string]any{}
	var results []map[string]any
	for _, f := range findings {
		if _, ok := rules[f.Rule.ID]; !ok {
			rules[f.Rule.ID] = map[string]any{
				"id":               f.Rule.ID,
				"shortDescription": map[string]string{"text": Redact(f.Message)},
				"helpUri":          firstRef(f),
			}
		}
		// locations must be omitted — never an empty object. An empty
		// physicalLocation NPEs strict SARIF consumers (e.g. Jenkins
		// Warnings NG) and fails the whole file. Dependency findings carry
		// no Location but do carry Artifact.Target (e.g. pom.xml): use it.
		var locs []any
		if f.Location != nil {
			region := map[string]any{}
			if f.Location.StartLine != nil {
				region["startLine"] = *f.Location.StartLine
			}
			if f.Location.EndLine != nil {
				region["endLine"] = *f.Location.EndLine
			}
			loc := map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]string{"uri": f.Location.Path},
			}}
			if len(region) > 0 {
				loc["physicalLocation"].(map[string]any)["region"] = region
			}
			locs = append(locs, loc)
		} else if f.Artifact != nil && f.Artifact.Target != "" {
			locs = append(locs, map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]string{"uri": f.Artifact.Target},
			}})
		}
		result := map[string]any{
			"ruleId":       f.Rule.ID,
			"level":        sarifLevel(f.Severity.Canonical),
			"message":      map[string]string{"text": Redact(f.Message)},
			"fingerprints": map[string]string{finding.FingerprintVersion: f.Fingerprint.Value},
		}
		if len(locs) > 0 {
			result["locations"] = locs
		}
		results = append(results, result)
	}
	var ruleList []map[string]any
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i]["id"].(string) < ruleList[j]["id"].(string) })
	if results == nil {
		results = []map[string]any{}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "sdt", "rules": ruleList}},
			"results": results,
		}},
	}
	raw, _ := json.MarshalIndent(doc, "", "  ")
	return append(raw, '\n')
}

func sarifLevel(canonical string) string {
	switch canonical {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func firstRef(f *finding.Finding) string {
	if len(f.Rule.References) > 0 {
		return f.Rule.References[0]
	}
	return ""
}

// ToJUnit renders policy status as JUnit XML for generic CI surfaces (OUT-004).
// One testsuite; one testcase per finding, failures for blockers.
func ToJUnit(status string, findings []*finding.Finding, blockers map[string]string) []byte {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	fmt.Fprintf(&sb, `<testsuite name="sdt-policy" tests="%d" failures="%d" status=%s>`+"\n",
		len(findings), len(blockers), xmlAttr(status))
	for _, f := range findings {
		fmt.Fprintf(&sb, `  <testcase classname="sdt.policy" name=%s>`, xmlAttr(f.ID+" "+f.Rule.ID))
		if rule, ok := blockers[f.ID]; ok {
			fmt.Fprintf(&sb, "\n"+`    <failure message=%s>%s</failure>`+"\n  ",
				xmlAttr("blocked by "+rule), xmlEsc(f.Message))
		}
		sb.WriteString("</testcase>\n")
	}
	sb.WriteString("</testsuite>\n")
	return []byte(sb.String())
}

func xmlAttr(s string) string {
	return `"` + xmlEsc(s) + `"`
}

func xmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// Checksum helper.
func Checksum(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// NowUTC returns RFC3339 UTC time.
func NowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// Ensure plan import is used.
var _ = plan.SchemaVersion
