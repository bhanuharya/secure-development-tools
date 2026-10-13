package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
	"github.com/bhanuharya/secure-development-tools/internal/report"
)

// staged carries two facts of a staged scan from where they are known to where
// the result is printed.
var staged struct {
	files int    // files the commit adds lines to
	note  string // why nothing was scanned, when nothing was
}

const stagedBypass = "SKIP_SDT=1 git commit ..."

const stagedCouldNotRun = "sdt: the staged changes were not checked. `sdt doctor` says what is missing.\n" +
	"sdt: to commit without the check: " + stagedBypass + "\n"

// stagedOutputDefaults moves the reports and the cache of a staged scan into
// the git directory, unless the caller chose a place. A hook must not leave
// files in the working tree for the next `git add` to pick up.
func stagedOutputDefaults(cmd *cobra.Command) {
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	state, err := stagedStateDir(cwd)
	if err != nil {
		return
	}
	if !cmd.Flags().Changed("output") && os.Getenv("SDT_OUTPUT_DIR") == "" {
		g.Output = filepath.Join(state, "reports")
	}
	if !cmd.Flags().Changed("cache") && os.Getenv("SDT_CACHE_DIR") == "" {
		g.Cache = filepath.Join(state, "cache")
	}
}

// stagedSummary is what the person committing reads: where, what and what to
// do, one entry per line of code. The scanners' own summary is for machines.
func stagedSummary(status string, findings []*finding.Finding, out policy.Outcome, health map[string]string, reportDir string, took time.Duration) string {
	if status != "passed" && status != "policy_failed" {
		return report.Summary(status, findings, out, health) + stagedCouldNotRun
	}
	if staged.note != "" {
		return "sdt: nothing to check: " + staged.note + "\n"
	}
	blocking := map[string]bool{}
	for _, b := range out.Blockers {
		blocking[b.FindingID] = true
	}
	// One entry per place: several rules often report the same line.
	type place struct {
		path     string
		line     int
		blocks   bool
		findings []*finding.Finding
	}
	places := map[string]*place{}
	for _, f := range findings {
		if f.Suppression != nil || f.Location == nil {
			continue
		}
		line := 0
		if f.Location.StartLine != nil {
			line = *f.Location.StartLine
		}
		key := fmt.Sprintf("%s:%d", f.Location.Path, line)
		if places[key] == nil {
			places[key] = &place{path: f.Location.Path, line: line}
		}
		places[key].findings = append(places[key].findings, f)
		places[key].blocks = places[key].blocks || blocking[f.ID]
	}
	if len(places) == 0 {
		return fmt.Sprintf("sdt: staged changes checked, nothing found (%s, %.1f s)\n", plural(staged.files, "file"), took.Seconds())
	}
	var ordered []*place
	blockers := 0
	for _, p := range places {
		// The finding that speaks for a place: one that blocks, then the most severe.
		sort.SliceStable(p.findings, func(i, j int) bool {
			a, b := p.findings[i], p.findings[j]
			if blocking[a.ID] != blocking[b.ID] {
				return blocking[a.ID]
			}
			return severityOrder[a.Severity.Canonical] < severityOrder[b.Severity.Canonical]
		})
		if p.blocks {
			blockers++
		}
		ordered = append(ordered, p)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.blocks != b.blocks {
			return a.blocks
		}
		if a.path != b.path {
			return a.path < b.path
		}
		return a.line < b.line
	})

	var text strings.Builder
	if blockers > 0 {
		fmt.Fprintf(&text, "sdt: %s in the lines being committed must be fixed first\n\n", plural(blockers, "problem"))
	} else {
		fmt.Fprintf(&text, "sdt: nothing blocks this commit; %s worth a look\n\n", plural(len(ordered), "place"))
	}
	for _, p := range ordered {
		first := p.findings[0]
		where := p.path
		if p.line > 0 {
			where = fmt.Sprintf("%s:%d", p.path, p.line)
		}
		name := shortRule(first.Rule.ID)
		if first.Category == finding.CatSecret {
			name = "secret (" + name + ")"
		}
		fmt.Fprintf(&text, "  %s  %s  %s", where, first.Severity.Canonical, name)
		if more := len(p.findings) - 1; more > 0 {
			fmt.Fprintf(&text, "  (+%s on this line)", plural(more, "more rule"))
		}
		if !p.blocks && blockers > 0 {
			text.WriteString("  (does not block)")
		}
		text.WriteString("\n")
		if message := brief(report.Redact(first.Message)); message != "" {
			fmt.Fprintf(&text, "      %s\n", message)
		}
		if first.Category == finding.CatSecret {
			text.WriteString("      Take it out before you commit. It has to be replaced only if it was pushed or shared before.\n")
		}
	}
	text.WriteString("\n")
	if blockers > 0 {
		fmt.Fprintf(&text, "Fix and commit again. To commit as it is: %s (the pull request scan reports the same).\n", stagedBypass)
	}
	fmt.Fprintf(&text, "Full report: %s\n", fromHere(filepath.Join(reportDir, "findings.json")))
	return text.String()
}

// fromHere is a path as seen from the working directory, when it is below it.
func fromHere(path string) string {
	if cwd, err := os.Getwd(); err == nil {
		if relative, err := filepath.Rel(cwd, path); err == nil && !strings.HasPrefix(relative, "..") {
			return relative
		}
	}
	return path
}

var severityOrder = map[string]int{
	finding.SevCritical: 0, finding.SevHigh: 1, finding.SevMedium: 2, finding.SevLow: 3, finding.SevInfo: 4, finding.SevUnknown: 5,
}

// shortRule is the part of a rule's id that names the weakness: the last
// element of a vendored rule's id ("tainted-sql-string"), the last two of a
// first-party one ("injection.command").
func shortRule(id string) string {
	parts := strings.Split(id, ".")
	if len(parts) > 2 && parts[0] != "vendor" {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return parts[len(parts)-1]
}

// brief is the opening of a message, on one line: its first sentence, or more
// when that is very short, and never more than a couple of lines of a terminal.
func brief(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	const enough, most = 80, 240
	if len(message) <= enough {
		return message
	}
	if end := strings.Index(message[enough:], ". "); end >= 0 && enough+end < most {
		return message[:enough+end+1]
	}
	if len(message) <= most {
		return message
	}
	cut := strings.LastIndex(message[:most], " ")
	if cut < enough {
		cut = most
	}
	return message[:cut] + " ..."
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
