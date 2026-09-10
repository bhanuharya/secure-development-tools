package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// relToRoot normalizes a tool-reported path to a repo-relative slash path so
// fingerprints hold across machines. Paths outside root are kept as-is.
func relToRoot(root, p string) string {
	if p == "" {
		return ""
	}
	rel := p
	if filepath.IsAbs(p) && root != "" {
		if r, err := filepath.Rel(root, p); err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			rel = r
		}
	}
	return filepath.ToSlash(rel)
}

// checksumFiles returns sorted per-file content digests so rule-content
// changes alter the plan digest (determinism over contents, not just paths).
func checksumFiles(files []string) []string {
	sorted := append([]string{}, files...)
	sort.Strings(sorted)
	var out []string
	for _, f := range sorted {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(raw)
		out = append(out, "sha256:"+hex.EncodeToString(sum[:]))
	}
	return out
}

// isRuleFile reports whether a basename is a loadable rule file.
// Annotated test fixtures (*.test.*) and autofix fixtures (*.fixed.*) are
// never rules: passing a multi-doc test target as --config fails the whole
// engine run (exit 7), so discovery must exclude them.
func isRuleFile(base string) bool {
	if strings.Contains(base, ".test.") || strings.Contains(base, ".fixed.") {
		return false
	}
	return strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")
}

// opengrepExcludes keeps scanner output out of caches, VCS metadata, and
// vendored/bundled third-party trees. Pinned vendor content is verified by
// hash (sdt rules verify), never scanned as first-party code — this also
// keeps colocated upstream rule-test fixtures out of scan targets.
func opengrepExcludes() []string {
	base := []string{".git/*", ".cache/*", "reports/*", "node_modules/*", ".venv/*", "venv/*", "__pycache__/*", "*.min.js", "rules/opengrep-rules/vendor/**", "rules/**/*.test.*"}
	if extra := os.Getenv("SDT_OPENGREP_EXCLUDE"); extra != "" {
		base = append(base, strings.Split(extra, ",")...)
	}
	return base
}

// nativeReportPath returns a deterministic machine-output path under the
// scan cache root so identical inputs produce identical plans (NFR-001).
func nativeReportPath(cacheRoot, name string) (string, error) {
	if cacheRoot == "" {
		cacheRoot = ".cache/sdt"
	}
	native := filepath.Join(cacheRoot, "native")
	if err := os.MkdirAll(native, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(native, name), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// cleanRuleID normalizes an engine rule id to a machine-independent key.
//
// Opengrep prefixes vendored rules with the absolute install path (leaking
// the operator's home directory into reports and breaking fingerprint
// stability across machines). Anything through "opengrep-rules." is cut,
// keeping the pack-relative id (e.g.
// "vendor.semgrep.java.lang.security.java-pattern-from-string-parameter").
// First-party ids ("scp.common...") are kept from "scp." onward. Anything
// else is returned trimmed as-is.
func cleanRuleID(checkID string) string {
	id := strings.TrimSpace(checkID)
	if i := strings.LastIndex(id, "opengrep-rules."); i >= 0 {
		id = id[i+len("opengrep-rules."):]
	} else if i := strings.Index(id, "scp."); i >= 0 {
		id = id[i:]
	}
	return id
}

// fingerprintCtx builds the semantic-context component of a finding
// fingerprint: rule-specific content when the tool provides it, plus the
// start line as a last-resort disambiguator. The line is never the primary
// identity component (PRD FIND-003) — content dominates, the line only
// separates true duplicates (identical rule+content in one file) so two
// distinct issues in one file never share identity.
func fingerprintCtx(content string, startLine *int) string {
	ctx := normalizeCtx(content)
	if startLine != nil {
		ctx += fmt.Sprintf("\x00line:%d", *startLine)
	}
	return ctx
}

func linePtr(n int) *int { return &n }

func normalizeCtx(s string) string {
	// Collapse whitespace; bound length so huge blobs don't dominate.
	joined := strings.Join(strings.Fields(s), " ")
	if len(joined) > 512 {
		joined = joined[:512]
	}
	return joined
}

func toStringList(v any, cweNormalize bool) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return nil
		}
		if cweNormalize {
			s := strings.ToUpper(strings.TrimSpace(t))
			if !strings.HasPrefix(s, "CWE-") {
				s = "CWE-" + s
			}
			return []string{s}
		}
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case []string:
		return t
	default:
		return []string{fmt.Sprint(v)}
	}
}

// detectLanguages is a lightweight filename-based detector.
func detectLanguages(root string) []string {
	exts := map[string]string{
		".py": "python", ".js": "javascript", ".ts": "typescript",
		".go": "go", ".java": "java", ".kt": "kotlin", ".yaml": "yaml", ".yml": "yaml",
	}
	found := map[string]bool{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(p)
			if base == ".git" || base == "node_modules" || base == "vendor" || base == ".venv" || base == "venv" {
				return filepath.SkipDir
			}
			return nil
		}
		if lang, ok := exts[strings.ToLower(filepath.Ext(p))]; ok {
			found[lang] = true
		}
		return nil
	})
	var out []string
	for l := range found {
		out = append(out, l)
	}
	return out
}
