// Package rules implements the rule-governance harness behind
// `sdt rules verify`: discovery, manifest enforcement (counts + bundle
// hashes), engine validation, and per-rule annotated testing.
//
// Background: `opengrep test` pairs tests correctly only for single-rule
// invocations (whole-pack runs degenerate into a cartesian product), so the
// harness runs one `opengrep test --config <rule> <sibling-tests...>` per
// rule file. Taint-mode rules receive --taint-intrafile on OpenGrep,
// matching production scan flags.
package rules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// ManifestSource is one pinned rule source from rules/manifest.yaml.
type ManifestSource struct {
	ID                string            `yaml:"id"`
	Repository        string            `yaml:"repository"`
	License           string            `yaml:"license"`
	Revision          string            `yaml:"revision"`
	Profile           string            `yaml:"profile"`
	PathPrefixes      []string          `yaml:"path_prefixes"`
	ExpectedRuleCount int               `yaml:"expected_rule_count"`
	BundleSHA256      string            `yaml:"bundle_sha256"`
	Hashes            map[string]string `yaml:"hashes"`
}

// Manifest is the parsed rules/manifest.yaml.
type Manifest struct {
	Version int              `yaml:"version"`
	Sources []ManifestSource `yaml:"sources"`
}

// LoadManifest reads and parses the rule manifest.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// RulePackDir is the configured OpenGrep rule directory. Relative paths are
// resolved by the caller's working directory, matching scanner behavior.
func RulePackDir() string {
	if pack := os.Getenv("SDT_RULES_PACK_DIR"); pack != "" {
		return pack
	}
	return "rules/opengrep-rules"
}

// RuleManifestPath returns the manifest adjacent to the configured rule pack.
func RuleManifestPath() string {
	pack := RulePackDir()
	if filepath.Base(filepath.Clean(pack)) == "opengrep-rules" {
		return filepath.Join(filepath.Dir(pack), "manifest.yaml")
	}
	return filepath.Join(pack, "manifest.yaml")
}

// RuleRoots are the scanned rule trees.
func RuleRoots() []string {
	return []string{RulePackDir(), ".secure-dev/rules"}
}

// DiscoverRuleFiles returns sorted rule yamls under roots, excluding
// annotated test fixtures (<stem>.test.<ext>).
func DiscoverRuleFiles(roots []string) ([]string, error) {
	var out []string
	for _, r := range roots {
		err := filepath.Walk(r, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			base := filepath.Base(p)
			if strings.Contains(base, ".test.") || isTitleOverlay(p) {
				return nil
			}
			if strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") {
				out = append(out, p)
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

// isTitleOverlay reports whether p is the vendored-title overlay, which is
// data for `sdt rules verify`, not a rule file for the engine.
func isTitleOverlay(p string) bool {
	return filepath.Base(p) == "titles.yaml" && filepath.Base(filepath.Dir(p)) == "vendor"
}

// CountRules parses yamls and counts `rules:` entries. Files that fail to
// parse are reported as invalid paths.
func CountRules(files []string) (total int, invalid []string) {
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			invalid = append(invalid, f+": unreadable: "+err.Error())
			continue
		}
		var doc struct {
			Rules []any `yaml:"rules"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			invalid = append(invalid, f+": invalid YAML: "+err.Error())
			continue
		}
		total += len(doc.Rules)
	}
	return total, invalid
}

// MaxRuleTitleLength keeps titles readable in a table cell and in SonarQube's
// rule name column.
const MaxRuleTitleLength = 60

// TitleOverlayPath is the readable-name overlay for vendored rules. The
// vendored rule files are kept byte-for-byte as upstream ships them, so their
// names live here instead of in their metadata.
func TitleOverlayPath() string {
	return filepath.Join(RulePackDir(), "vendor", "titles.yaml")
}

// LoadTitles reads the overlay. Keys are the ids the engine reports for
// vendored rules: the rule's folder under the pack with dots for slashes,
// then the rule's own id.
func LoadTitles(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read titles: %w", err)
	}
	var titles map[string]string
	if err := yaml.Unmarshal(raw, &titles); err != nil {
		return nil, fmt.Errorf("parse titles: %w", err)
	}
	for id, title := range titles {
		titles[id] = strings.TrimSpace(title)
	}
	return titles, nil
}

// TitleProblems checks the readable name every rule must carry. First-party
// rules carry metadata.title; vendored rules must have an overlay entry so
// their files stay verbatim. Overlay entries for rules that no longer exist
// are stale and reported too.
func TitleProblems(files []string, titles map[string]string) []string {
	var problems []string
	present := map[string]bool{}
	packRoot, _ := filepath.Abs(RulePackDir())
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			problems = append(problems, f+": unreadable: "+err.Error())
			continue
		}
		var doc struct {
			Rules []struct {
				ID       string `yaml:"id"`
				Metadata struct {
					Title string `yaml:"title"`
				} `yaml:"metadata"`
			} `yaml:"rules"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			continue // CountRules already reports files that do not parse
		}
		for _, r := range doc.Rules {
			key, vendored := reportedRuleID(packRoot, f, r.ID)
			if vendored {
				present[key] = true
				title := strings.TrimSpace(titles[key])
				switch {
				case title == "":
					problems = append(problems, fmt.Sprintf("%s: rule %q has no overlay title in vendor/titles.yaml", f, r.ID))
				case utf8.RuneCountInString(title) > MaxRuleTitleLength:
					problems = append(problems, fmt.Sprintf("%s: rule %q overlay title is %d characters (max %d)",
						f, r.ID, utf8.RuneCountInString(title), MaxRuleTitleLength))
				}
				continue
			}
			title := strings.TrimSpace(r.Metadata.Title)
			switch {
			case title == "":
				problems = append(problems, fmt.Sprintf("%s: rule %q has no metadata.title", f, r.ID))
			case utf8.RuneCountInString(title) > MaxRuleTitleLength:
				problems = append(problems, fmt.Sprintf("%s: rule %q title is %d characters (max %d)",
					f, r.ID, utf8.RuneCountInString(title), MaxRuleTitleLength))
			}
		}
	}
	var stale []string
	for key := range titles {
		if !present[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		problems = append(problems, fmt.Sprintf("vendor/titles.yaml: overlay entry %q has no rule", key))
	}
	return problems
}

// reportedRuleID is the id the engine reports for a rule file: the file's
// directory relative to the pack with dots for slashes, then the rule id.
// Only files under vendor/ use the overlay; first-party rules are reported
// by their own id.
func reportedRuleID(packRoot, ruleFile, id string) (string, bool) {
	if id == "" {
		return "", false
	}
	absFile, err := filepath.Abs(ruleFile)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(packRoot, filepath.Dir(absFile))
	if err != nil {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	if rel != "vendor" && !strings.HasPrefix(rel, "vendor/") {
		return "", false
	}
	return strings.ReplaceAll(rel, "/", ".") + "." + id, true
}

// CountRulesIn counts rules in files under prefix (slash-separated, as in
// manifest path_prefixes, matched against rules/opengrep-rules/<prefix>).
// Matching is CWD-independent: any file path with that infix qualifies.
func CountRulesIn(files []string, prefix string) int {
	packRoot := RulePackDir()
	count := countRulesInRoot(files, packRoot, prefix)
	if count > 0 || os.Getenv("SDT_RULES_PACK_DIR") != "" || packRoot != "rules/opengrep-rules" {
		return count
	}
	return countRulesInCanonical(files, prefix)
}

func countRulesInCanonical(files []string, prefix string) int {
	needle := "rules/opengrep-rules/" + strings.Trim(filepath.ToSlash(prefix), "/")
	n := 0
	for _, f := range files {
		slashed := filepath.ToSlash(f)
		idx := strings.Index(slashed, needle)
		if idx < 0 {
			continue
		}
		rest := slashed[idx+len(needle):]
		if rest != "" && !strings.HasPrefix(rest, "/") {
			continue
		}
		var doc struct {
			Rules []any `yaml:"rules"`
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			continue
		}
		n += len(doc.Rules)
	}
	return n
}

func countRulesInRoot(files []string, packRoot, prefix string) int {
	prefix = strings.Trim(filepath.ToSlash(prefix), "/")
	n := 0
	for _, f := range files {
		rel, err := filepath.Rel(packRoot, f)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if rel != prefix && !strings.HasPrefix(rel, prefix+"/") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var doc struct {
			Rules []any `yaml:"rules"`
		}
		if err := yaml.Unmarshal(raw, &doc); err == nil {
			n += len(doc.Rules)
		}
	}
	return n
}

// BundleHash reproduces the vendor script's bundle digest: sha256 over the
// sorted `sha256sum` lines of every file under dir, with `./`-relative paths.
func BundleHash(dir string) (string, error) {
	var names []string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		names = append(names, "./"+filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(names)
	var listing strings.Builder
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return "", err
		}
		fh := sha256.Sum256(raw)
		fmt.Fprintf(&listing, "%s  %s\n", hex.EncodeToString(fh[:]), n)
	}
	sum := sha256.Sum256([]byte(listing.String()))
	return hex.EncodeToString(sum[:]), nil
}

// testExtensions are sibling annotated-test extensions (autofix fixtures
// *.fixed.* are intentionally excluded: sdt never applies fixes).
var testExtensions = []string{
	".py", ".js", ".ts", ".go", ".java", ".kt", ".dart", ".rb", ".php",
	".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".scala", ".rs",
	// Generic-language rules (secrets, IaC, CI) are tested with
	// plain-text fixtures in these formats.
	".txt", ".tf", ".yaml", ".yml", ".json", ".toml", ".xml",
}

// RuleIDs parses the rule ids declared in a rule file.
func RuleIDs(ruleFile string) []string {
	raw, err := os.ReadFile(ruleFile)
	if err != nil {
		return nil
	}
	var doc struct {
		Rules []struct {
			ID string `yaml:"id"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	var out []string
	for _, r := range doc.Rules {
		if r.ID != "" {
			out = append(out, r.ID)
		}
	}
	return out
}

// annotationRe matches `# ruleid: <id>` / `# ok: <id>` (and // variants).
var annotationRe = regexp.MustCompile(`(?:#|//)\s*(?:ruleid|ok)\s*:\s*([A-Za-z0-9][\w\-.]+)`)

// IndexAnnotations maps rule id -> test files mentioning it via ruleid:/ok:
// markers. Only candidate test files are scanned (non-yaml code fixtures
// plus *.test.yaml), keeping the index cheap.
func IndexAnnotations(roots []string) map[string][]string {
	index := map[string][]string{}
	add := func(id, file string) {
		for _, f := range index[id] {
			if f == file {
				return
			}
		}
		index[id] = append(index[id], file)
	}
	for _, root := range roots {
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			base := filepath.Base(p)
			isTestYaml := (strings.HasSuffix(base, ".test.yaml") || strings.HasSuffix(base, ".test.yml"))
			isCode := false
			for _, ext := range testExtensions {
				if strings.HasSuffix(base, ext) && !strings.HasSuffix(base, ".test"+ext) {
					// plain <stem>.<ext> fixtures (upstream convention)
					isCode = true
					break
				}
			}
			// Exclude rule files themselves and autofix fixtures.
			if strings.Contains(base, ".fixed.") {
				return nil
			}
			if !isTestYaml && !isCode {
				// Ours <stem>.test.<ext> fixtures.
				isOurs := strings.Contains(base, ".test.")
				if !isOurs {
					return nil
				}
			}
			if (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) && !isTestYaml {
				return nil // a rule file, not a test
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			for _, line := range strings.Split(string(raw), "\n") {
				m := annotationRe.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				add(m[1], p)
			}
			return nil
		})
	}
	return index
}

// FindTests returns colocated annotated-test siblings for a rule file.
// Two conventions: upstream `<stem>.<ext>` (vendored, colocated by
// necessity) and ours `<stem>.test.<ext>` (excluded from scan targets).
// The rule file itself is never returned, even for yaml-ish extensions.
func FindTests(ruleFile string) []string {
	var out []string
	stem := strings.TrimSuffix(strings.TrimSuffix(ruleFile, ".yaml"), ".yml")
	seen := map[string]bool{ruleFile: true}
	for _, ext := range testExtensions {
		for _, cand := range []string{stem + ".test" + ext, stem + ext} {
			if seen[cand] {
				continue
			}
			seen[cand] = true
			if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
				out = append(out, cand)
			}
		}
	}
	sort.Strings(out)
	return out
}

// EnforceManifest checks expected counts, per-file hashes, and bundle hashes.
// It returns human-readable problems (empty = clean).
// repoRoot anchors both the pack dir and any relative file paths, so callers
// may pass CWD-relative discovery results (the `sdt rules verify` default)
// or absolute paths (tests, tooling) — both resolve identically.
func EnforceManifest(repoRoot string, files []string, m *Manifest) []string {
	var problems []string
	packRoot := RulePackDir()
	if !filepath.IsAbs(packRoot) {
		packRoot = filepath.Join(repoRoot, packRoot)
	}
	absFiles := make([]string, 0, len(files))
	for _, f := range files {
		if !filepath.IsAbs(f) {
			f = filepath.Join(repoRoot, f)
		}
		absFiles = append(absFiles, f)
	}
	files = absFiles
	for _, s := range m.Sources {
		// Count across all prefixes of this source.
		total := 0
		for _, prefix := range s.PathPrefixes {
			total += countRulesInRoot(files, packRoot, prefix)
		}
		if s.ExpectedRuleCount != 0 && total != s.ExpectedRuleCount {
			problems = append(problems, fmt.Sprintf("source %q: want %d rules, found %d", s.ID, s.ExpectedRuleCount, total))
		}
		for rel, want := range s.Hashes {
			raw, err := os.ReadFile(filepath.Join(packRoot, filepath.FromSlash(rel)))
			if err != nil {
				problems = append(problems, fmt.Sprintf("source %q: missing hashed file %s", s.ID, rel))
				continue
			}
			sum := sha256.Sum256(raw)
			if hex.EncodeToString(sum[:]) != want {
				problems = append(problems, fmt.Sprintf("source %q: hash mismatch %s", s.ID, rel))
			}
		}
		if s.BundleSHA256 != "" {
			// Bundle root = longest common tree of the source prefixes.
			// Prefixes share one top dir in practice (vendor/semgrep/<lang>).
			root := bundleRoot(packRoot, s.PathPrefixes)
			got, err := BundleHash(root)
			if err != nil {
				problems = append(problems, fmt.Sprintf("source %q: bundle unreadable: %v", s.ID, err))
			} else if got != s.BundleSHA256 {
				problems = append(problems, fmt.Sprintf("source %q: bundle hash mismatch (want %s, got %s)", s.ID, s.BundleSHA256, got))
			}
		}
	}
	return problems
}

func bundleRoot(packRoot string, prefixes []string) string {
	if len(prefixes) == 1 {
		return filepath.Join(packRoot, filepath.FromSlash(prefixes[0]))
	}
	// Longest common slash-prefix.
	parts := [][]string{}
	for _, p := range prefixes {
		parts = append(parts, strings.Split(p, "/"))
	}
	common := parts[0]
	for _, q := range parts[1:] {
		i := 0
		for i < len(common) && i < len(q) && common[i] == q[i] {
			i++
		}
		common = common[:i]
	}
	return filepath.Join(append([]string{packRoot}, common...)...)
}

// Validate runs `opengrep validate` over rule files. Files are named one by
// one so the title overlay, which sits beside the vendored rules but is not a
// rule file, is never offered to the engine.
func Validate(binary string, files []string, timeoutSecs int) error {
	args := append([]string{"validate"}, files...)
	return runEngine(binary, args, timeoutSecs)
}

// TestRule runs `opengrep test --config <rule> <tests...>` for one rule.
func TestRule(binary, ruleFile string, testFiles []string, intrafile bool, timeoutSecs int) error {
	args := []string{"test"}
	if intrafile {
		args = append(args, "--taint-intrafile")
	}
	args = append(args, "--config", ruleFile)
	args = append(args, testFiles...)
	return runEngine(binary, args, timeoutSecs)
}

func runEngine(binary string, args []string, timeoutSecs int) error {
	if timeoutSecs <= 0 {
		timeoutSecs = 300
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &bytes.Buffer{}
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[:2000]
		}
		return fmt.Errorf("%s %s: %v\n%s", binary, strings.Join(args, " "), err, msg)
	}
	return nil
}
