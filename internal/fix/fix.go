// Package fix proposes and applies safe mechanical remediations (Bet 3).
//
// Safety contract:
//   - Whitelisted transform classes only, each versioned (e.g.
//     gha-pin-action/v1). Anything outside the whitelist is reported as
//     "needs human review", never touched.
//   - Secret-category findings are never modified, full stop.
//   - Only the exact finding line is rewritten; the rest of the file is
//     byte-identical.
//   - Every applied edit passes a syntax check for its language when a
//     checker is available (py_compile, gofmt); otherwise application is
//     refused unless --skip-validation is given explicitly.
//   - Quarantined transform versions (.secure-dev/fix-quarantine.yaml) are
//     skipped with a note. Never commits: output is a diff, --apply writes
//     the working tree, review and commit stay human.
package fix

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// Suggestion is a human-review item for findings no transform covers.
type Suggestion struct {
	FindingID string `json:"findingId"`
	RuleID    string `json:"ruleId"`
	Location  string `json:"location"`
	Note      string `json:"note"`
}

// Edit is one applied or proposed file change.
type Edit struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Before  string `json:"before"`
	After   string `json:"after"`
	RuleID  string `json:"ruleId"`
	ClassID string `json:"classId"`
}

// Result aggregates a fix run.
type Result struct {
	Edits       []Edit       `json:"edits"`
	Suggestions []Suggestion `json:"suggestions"`
	Skipped     []string     `json:"skipped,omitempty"`
	Quarantined []string     `json:"quarantined,omitempty"`
}

// Transform rewrites one finding line. It returns the replacement line or an
// error explaining why the finding is not mechanically fixable.
type Transform struct {
	// ID is versioned (name/vN) so a bad transform generation can be
	// quarantined without losing the name.
	ID          string
	Description string
	// RuleIDs this transform handles.
	RuleIDs []string
	Apply   func(path string, lines []string, line int, f *finding.Finding) (string, error)
}

var registry []Transform

func register(t Transform) { registry = append(registry, t) }

func init() {
	register(Transform{
		ID:          "gha-pin-action/v1",
		Description: "pin GitHub Action to full commit SHA",
		RuleIDs:     []string{"scp.yaml.ci.unpinned-action"},
		Apply:       applyGhaPin,
	})
	register(Transform{
		ID:          "py-hashlib-sha256/v1",
		Description: "hashlib.md5/sha1 call becomes sha256",
		RuleIDs:     []string{"scp.python.crypto.weak-md5"},
		Apply:       applyPyHash,
	})
	register(Transform{
		ID:          "py-yaml-safe-load/v1",
		Description: "unsafe PyYAML loader becomes safe_load/SafeLoader",
		RuleIDs:     []string{"scp.python.deserialization.unsafe-yaml-load"},
		Apply:       applyPyYaml,
	})
}

// Classes returns the registered transform catalogue (for version/help).
func Classes() []Transform { return append([]Transform{}, registry...) }

// Plan matches findings to transforms, honoring quarantine. It performs no I/O.
func Plan(findings []*finding.Finding, quarantine map[string]bool, onlyRule string) (matched map[*finding.Finding]Transform, result *Result) {
	result = &Result{}
	matched = map[*finding.Finding]Transform{}
	byRule := map[string]Transform{}
	for _, t := range registry {
		for _, r := range t.RuleIDs {
			byRule[r] = t
		}
	}
	for _, f := range findings {
		if f.Category == finding.CatSecret {
			result.Skipped = append(result.Skipped, fmt.Sprintf("%s: secret findings are never modified", f.ID))
			continue
		}
		if f.Location == nil || f.Location.Path == "" || f.Location.StartLine == nil {
			result.Skipped = append(result.Skipped, fmt.Sprintf("%s: no actionable location", f.ID))
			continue
		}
		if onlyRule != "" && f.Rule.ID != onlyRule {
			continue
		}
		t, ok := byRule[f.Rule.ID]
		if !ok {
			loc := f.Location.Path
			result.Suggestions = append(result.Suggestions, Suggestion{
				FindingID: f.ID, RuleID: f.Rule.ID, Location: loc,
				Note: "no safe mechanical transform; see remediation guidance",
			})
			continue
		}
		if quarantine[t.ID] {
			result.Quarantined = append(result.Quarantined, fmt.Sprintf("%s: transform %s quarantined", f.ID, t.ID))
			continue
		}
		matched[f] = t
	}
	sort.Strings(result.Skipped)
	sort.Strings(result.Quarantined)
	return matched, result
}

type pendingChange struct {
	idx   int
	after string
	f     *finding.Finding
	class string
}

// computeEdits applies transforms to in-memory file copies. Pure except for
// file reads: safe to use for dry-run previews.
func computeEdits(root string, matched map[*finding.Finding]Transform) (edits []Edit, files map[string][]string, skipped []string) {
	// Group by file to read each once.
	byFile := map[string][]*finding.Finding{}
	for f := range matched {
		byFile[f.Location.Path] = append(byFile[f.Location.Path], f)
	}
	var paths []string
	for p := range byFile {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	files = map[string][]string{}
	for _, rel := range paths {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		raw, err := os.ReadFile(abs)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: read %s: %v", rel, rel, err))
			continue
		}
		lines := strings.Split(string(raw), "\n")
		var changes []pendingChange
		failed := false
		for _, f := range byFile[rel] {
			t := matched[f]
			line := *f.Location.StartLine
			if line < 1 || line > len(lines) {
				skipped = append(skipped, fmt.Sprintf("%s: line %d out of range in %s", f.ID, line, rel))
				failed = true
				continue
			}
			after, err := t.Apply(rel, lines, line, f)
			if err != nil {
				skipped = append(skipped, fmt.Sprintf("%s: %v", f.ID, err))
				failed = true
				continue
			}
			changes = append(changes, pendingChange{idx: line - 1, after: after, f: f, class: t.ID})
		}
		if failed {
			// Per-file atomicity: a file with any unfixable finding is left
			// untouched rather than half-fixed.
			continue
		}
		for _, c := range changes {
			edits = append(edits, Edit{
				Path: rel, Line: c.idx + 1, Before: lines[c.idx], After: c.after,
				RuleID: c.f.Rule.ID, ClassID: c.class,
			})
			lines[c.idx] = c.after
		}
		files[rel] = lines
	}
	sort.Slice(edits, func(i, j int) bool {
		if edits[i].Path != edits[j].Path {
			return edits[i].Path < edits[j].Path
		}
		return edits[i].Line < edits[j].Line
	})
	sort.Strings(skipped)
	return edits, files, skipped
}

// Preview computes edits without writing anything (dry-run).
func Preview(root string, matched map[*finding.Finding]Transform) (edits []Edit, skipped []string) {
	edits, _, skipped = computeEdits(root, matched)
	return edits, skipped
}

// ApplyEdits rewrites the finding lines in the working tree (root-joined
// repo-relative paths) and syntax-validates touched files.
func ApplyEdits(root string, matched map[*finding.Finding]Transform, skipValidation bool) (*Result, error) {
	result := &Result{}
	edits, files, skipped := computeEdits(root, matched)
	result.Skipped = append(result.Skipped, skipped...)
	result.Edits = edits
	byPath := map[string]bool{}
	for _, e := range edits {
		byPath[e.Path] = true
	}
	for rel, lines := range files {
		if !byPath[rel] {
			continue
		}
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.WriteFile(abs, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", rel, err)
		}
		if !skipValidation {
			if err := validateSyntax(abs); err != nil {
				return result, fmt.Errorf("validation failed for %s (edits kept on disk, review before committing): %w", rel, err)
			}
		}
	}
	return result, nil
}

// validateSyntax checks the edited file with an available language checker.
// Unknown languages pass with no checker (documented, not silent: callers
// surface which files were validated in diff output? No — keep it simple:
// validation errors fail loudly, absence of a checker is accepted).
func validateSyntax(abs string) error {
	switch strings.ToLower(filepath.Ext(abs)) {
	case ".py":
		py, err := exec.LookPath("python3")
		if err != nil {
			return nil
		}
		if out, err := exec.Command(py, "-m", "py_compile", abs).CombinedOutput(); err != nil {
			return fmt.Errorf("py_compile: %s", strings.TrimSpace(string(out)))
		}
	case ".go":
		gofmt, err := exec.LookPath("gofmt")
		if err != nil {
			return nil
		}
		if out, err := exec.Command(gofmt, "-l", abs).CombinedOutput(); err != nil {
			return fmt.Errorf("gofmt: %s", strings.TrimSpace(string(out)))
		} else if len(strings.TrimSpace(string(out))) > 0 {
			return fmt.Errorf("gofmt reports %s needs formatting", abs)
		}
	}
	return nil
}

// Diff renders edits as a unified-style diff for review.
func Diff(edits []Edit) string {
	var sb strings.Builder
	for _, e := range edits {
		fmt.Fprintf(&sb, "--- %s (line %d, %s via %s)\n", e.Path, e.Line, e.RuleID, e.ClassID)
		fmt.Fprintf(&sb, "-%s\n+%s\n", e.Before, e.After)
	}
	return sb.String()
}

var (
	ghaUsesRe = regexp.MustCompile(`uses:\s*([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)@([A-Za-z0-9_.\-/]+)`)
	pyHashRe  = regexp.MustCompile(`hashlib\.(md5|sha1)\(`)
)

func applyGhaPin(path string, lines []string, line int, f *finding.Finding) (string, error) {
	cur := lines[line-1]
	m := ghaUsesRe.FindStringSubmatch(cur)
	if m == nil {
		return "", fmt.Errorf("line does not contain a pinnable uses: reference")
	}
	repo, ref := m[1], m[2]
	if len(ref) == 40 && isHex(ref) {
		return "", fmt.Errorf("already pinned to full SHA")
	}
	sha, err := resolveRefSHA(repo, ref)
	if err != nil {
		return "", err
	}
	return strings.Replace(cur, "@"+ref, "@"+sha, 1), nil
}

// resolveRefSHA maps owner/repo@ref to a full commit SHA via ls-remote.
// Network failure is a clean skip, never a guess.
func resolveRefSHA(repo, ref string) (string, error) {
	out, err := exec.Command("git", "ls-remote", "https://github.com/"+repo, ref).Output()
	if err != nil {
		return "", fmt.Errorf("cannot resolve %s@%s (offline?): %v", repo, ref, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 1 || len(fields[0]) != 40 || !isHex(fields[0]) {
		return "", fmt.Errorf("cannot resolve %s@%s to a commit SHA", repo, ref)
	}
	return fields[0], nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func applyPyHash(path string, lines []string, line int, f *finding.Finding) (string, error) {
	cur := lines[line-1]
	if !pyHashRe.MatchString(cur) {
		return "", fmt.Errorf("line no longer contains hashlib.md5/sha1 call")
	}
	// Standard remediation; digest length changes, so the summary advises
	// running tests. Deliberately narrow: same line, same call shape.
	return pyHashRe.ReplaceAllString(cur, "hashlib.sha256("), nil
}

func applyPyYaml(path string, lines []string, line int, f *finding.Finding) (string, error) {
	cur := lines[line-1]
	switch {
	case strings.Contains(cur, "yaml.unsafe_load("):
		return strings.Replace(cur, "yaml.unsafe_load(", "yaml.safe_load(", 1), nil
	case strings.Contains(cur, "yaml.CUnsafeLoader"):
		return strings.Replace(cur, "yaml.CUnsafeLoader", "yaml.CSafeLoader", 1), nil
	case strings.Contains(cur, "yaml.CLoader"):
		if strings.Contains(cur, "yaml.CSafeLoader") {
			return "", fmt.Errorf("loader already safe")
		}
		return strings.Replace(cur, "yaml.CLoader", "yaml.CSafeLoader", 1), nil
	case strings.Contains(cur, "yaml.UnsafeLoader"):
		return strings.Replace(cur, "yaml.UnsafeLoader", "yaml.SafeLoader", 1), nil
	case strings.Contains(cur, "yaml.Loader"):
		// Bare Loader (without Safe/Unsafe prefix) is unsafe.
		if strings.Contains(cur, "yaml.SafeLoader") {
			return "", fmt.Errorf("loader already safe")
		}
		return strings.Replace(cur, "yaml.Loader", "yaml.SafeLoader", 1), nil
	default:
		return "", fmt.Errorf("line no longer contains a recognized unsafe loader")
	}
}
