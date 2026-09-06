// Package rules: history mining for proposed custom rules (Bet 5).
//
// propose clusters findings from saved reports by (adapter, rule,
// category), ranks repeat offenders, and emits human-finished skeletons:
// a .yaml.proposed rule draft plus an annotated TP test case built from
// redacted finding evidence. Mining proposes; the precision ladder
// (docs/rule-precision.md) disposes: skeletons are inert by naming
// (*.proposed is never discovered as a rule) until an engineer fills the
// pattern, promotes the filename, and passes `sdt rules verify`.
package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// Cluster is one repeat-offender group.
type Cluster struct {
	Adapter    string
	RuleID     string
	Category   string
	Severity   string
	Count      int
	Example    *finding.Finding
	Evidence   []string
	FindingIDs []string
}

// ClusterFindings groups findings and ranks by count (desc), ties broken
// deterministically by adapter/rule for stable output.
func ClusterFindings(all ...[]*finding.Finding) []Cluster {
	byKey := map[string]*Cluster{}
	var order []string
	for _, fs := range all {
		for _, f := range fs {
			key := f.Scanner.Adapter + "\x00" + f.Rule.ID + "\x00" + f.Category
			c, ok := byKey[key]
			if !ok {
				c = &Cluster{Adapter: f.Scanner.Adapter, RuleID: f.Rule.ID, Category: f.Category, Severity: f.Severity.Canonical, Example: f}
				byKey[key] = c
				order = append(order, key)
			}
			c.Count++
			c.FindingIDs = append(c.FindingIDs, f.ID)
			if f.Severity.Canonical == "critical" || (c.Severity != "critical" && f.Severity.Canonical == "high") {
				c.Severity = f.Severity.Canonical
				c.Example = f
			}
			if f.Evidence != nil && f.Evidence.Text != "" && len(c.Evidence) < 3 {
				dup := false
				for _, e := range c.Evidence {
					if e == f.Evidence.Text {
						dup = true
					}
				}
				if !dup {
					c.Evidence = append(c.Evidence, f.Evidence.Text)
				}
			}
		}
	}
	var out []Cluster
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Adapter != out[j].Adapter {
			return out[i].Adapter < out[j].Adapter
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// Slug derives a filesystem-safe rule slug from a cluster.
func Slug(c Cluster) string {
	s := nonAlnum.ReplaceAllString(strings.ToLower(c.RuleID), "-")
	s = strings.Trim(s, "-")
	if len(s) > 48 {
		s = s[:48]
	}
	if s == "" {
		s = "mined"
	}
	return s
}

var extLang = map[string]string{
	".py": "python", ".js": "javascript", ".ts": "typescript",
	".go": "go", ".java": "java", ".kt": "kotlin", ".rb": "ruby",
	".php": "php", ".c": "c", ".cpp": "cpp", ".h": "c",
	".cs": "csharp", ".swift": "swift", ".scala": "scala", ".rs": "rust",
}

// Skeleton renders the rule draft + annotated test for a cluster.
// Test evidence is redacted finding evidence (never raw secrets: secret
// findings carry no evidence by construction).
func Skeleton(c Cluster) (ruleFile, ruleYAML, testFile, testBody string) {
	slug := Slug(c)
	lang := "generic"
	ext := ".txt"
	if c.Example != nil && c.Example.Location != nil {
		if e := strings.ToLower(filepath.Ext(c.Example.Location.Path)); e != "" {
			ext = e
			if l, ok := extLang[e]; ok {
				lang = l
			}
		}
	}
	sev := "WARNING"
	if c.Severity == "critical" || c.Severity == "high" {
		sev = "ERROR"
	}
	msg := ""
	if c.Example != nil {
		msg = c.Example.Message
	}
	ruleFile = slug + ".yaml.proposed"
	ruleYAML = fmt.Sprintf(`rules:
  # MINED PROPOSAL from %s (%d findings, e.g. %s).
  # Fill in patterns:, then rename to .yaml and run: sdt rules verify
  - id: scp.mined.%s
    languages: [%s]
    message: %s
    severity: %s
    metadata:
      category: security
      confidence: LOW
      mined_from: %s
    patterns:
      - pattern: TODO_FILL_PATTERN
`,
		c.RuleID, c.Count, firstFindingID(c), slug, lang, yamlQuote(msg), sev, c.RuleID)
	var tb strings.Builder
	fmt.Fprintf(&tb, "# Proposed TP case for scp.mined.%s (from %s, redacted).\n", slug, c.RuleID)
	fmt.Fprintf(&tb, "# Fill the rule pattern until this fires and `sdt rules verify` is green.\n")
	if len(c.Evidence) == 0 {
		fmt.Fprintf(&tb, "# No evidence captured; craft a minimal reproducer manually.\n")
	} else {
		for _, ev := range c.Evidence {
			fmt.Fprintf(&tb, "# ruleid: scp.mined.%s\n%s\n", slug, ev)
		}
	}
	testFile = slug + ".test" + ext
	return ruleFile, ruleYAML, testFile, tb.String()
}

func firstFindingID(c Cluster) string {
	if len(c.FindingIDs) > 0 {
		return c.FindingIDs[0]
	}
	return ""
}

func yamlQuote(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 160 {
		s = s[:160]
	}
	return fmt.Sprintf("%q", s)
}

// LoadReportFindings reads findings from a findings.json file or from every
// findings.json directly under a directory.
func LoadReportFindings(from string) ([][]*finding.Finding, error) {
	fi, err := os.Stat(from)
	if err != nil {
		return nil, err
	}
	var paths []string
	if fi.IsDir() {
		entries, err := os.ReadDir(from)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() && e.Name() == "findings.json" {
				paths = append(paths, filepath.Join(from, e.Name()))
			}
		}
		// Also accept <dir>/reports/findings.json layout? No — exact contract.
		if len(paths) == 0 {
			// Try one level down (reports/<run>/findings.json archives).
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				cand := filepath.Join(from, e.Name(), "findings.json")
				if st, err := os.Stat(cand); err == nil && !st.IsDir() {
					paths = append(paths, cand)
				}
			}
		}
	} else {
		paths = []string{from}
	}
	var out [][]*finding.Finding
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		var rep struct {
			Findings []*finding.Finding `json:"findings"`
		}
		if err := json.Unmarshal(raw, &rep); err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		out = append(out, rep.Findings)
	}
	return out, nil
}
