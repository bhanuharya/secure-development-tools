// Package reachability answers one question per dependency finding: is the
// vulnerable package actually imported by first-party source?
//
// Soundness contract (load-bearing):
//   - "unreachable" requires positive proof of absence: a resolvable
//     ecosystem with a complete first-party source walk and no import.
//   - Anything doubtful — dynamic imports, missing manifests, unsupported
//     ecosystems, unreadable trees — resolves to "unknown", which policy
//     treats as matching neither reachable nor unreachable. Unknown can
//     never silently demote a finding.
//   - Test-only use still counts as imported: reachability is about code
//     reference, not deployment topology.
package reachability

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// States.
const (
	Reachable   = "reachable"
	Unreachable = "unreachable"
	Unknown     = "unknown"
)

// Info is attached to dependency/image vulnerability findings.
type Info struct {
	State    string `json:"state"`
	Reason   string `json:"reason"`
	Evidence string `json:"evidence,omitempty"`
}

// Annotate sets Reachability on dependency/image vulnerability findings.
// All other categories are untouched.
func Annotate(root string, findings []*finding.Finding) {
	inv := newInventory(root)
	for _, f := range findings {
		if f.Category != finding.CatDepVuln && f.Category != finding.CatImgVuln {
			continue
		}
		if f.Artifact == nil || f.Artifact.Package == "" {
			f.Reachability = &finding.Reachability{State: Unknown, Reason: "no package identity in finding"}
			continue
		}
		f.Reachability = inv.resolve(f.Artifact.Package, ecosystemOf(f.Artifact.Target))
	}
}

// inventory is a lazily-built view of first-party imports per ecosystem.
type inventory struct {
	root    string
	files   map[string][]string // ext -> absolute paths (first-party only)
	goFiles []string
	pyFiles []string
	jsFiles []string
	pyDyn   bool // dynamic-import constructs seen in python sources
	jsDyn   bool // dynamic import() with non-literal seen in js sources
	goMod   bool
	pkgJSON bool
	scanned bool
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, "__pycache__": true, ".venv": true, "venv": true,
	"target": true, ".cache": true, "reports": true, ".tox": true,
}

func newInventory(root string) *inventory {
	return &inventory{root: root, files: map[string][]string{}}
}

func (inv *inventory) scan() {
	if inv.scanned {
		return
	}
	inv.scanned = true
	_ = filepath.Walk(inv.root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".go":
			inv.goFiles = append(inv.goFiles, p)
		case ".py":
			inv.pyFiles = append(inv.pyFiles, p)
		case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
			inv.jsFiles = append(inv.jsFiles, p)
		case "":
			if info.Name() == "go.mod" {
				inv.goMod = true
			}
			if info.Name() == "package.json" {
				inv.pkgJSON = true
			}
		}
		return nil
	})
}

func ecosystemOf(target string) string {
	base := strings.ToLower(filepath.Base(target))
	switch base {
	case "go.mod", "go.sum":
		return "go"
	case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
		return "js"
	case "requirements.txt", "pipfile", "pipfile.lock", "poetry.lock", "setup.py", "setup.cfg", "pyproject.toml":
		return "python"
	case "pom.xml", "build.gradle", "build.gradle.kts":
		return "jvm"
	case "cargo.lock", "cargo.toml":
		return "rust"
	case "gemfile.lock", "gemfile":
		return "ruby"
	}
	return ""
}

func (inv *inventory) resolve(pkg, eco string) *finding.Reachability {
	inv.scan()
	switch eco {
	case "go":
		return inv.resolveGo(pkg)
	case "python":
		return inv.resolvePython(pkg)
	case "js":
		return inv.resolveJS(pkg)
	default:
		return &finding.Reachability{State: Unknown, Reason: "unsupported ecosystem for reachability"}
	}
}

// --- Go ---

var (
	goImportBlock = regexp.MustCompile(`(?m)^\s*(?:[\w.]+\s+)?"([^"]+)"`)
	goImportOne   = regexp.MustCompile(`(?m)^\s*import\s+(?:[\w.]+\s+)?"([^"]+)"`)
)

func (inv *inventory) resolveGo(pkg string) *finding.Reachability {
	if len(inv.goFiles) == 0 {
		if !inv.goMod {
			return &finding.Reachability{State: Unknown, Reason: "no go sources or go.mod under root"}
		}
		return &finding.Reachability{State: Unknown, Reason: "go.mod present but no go sources walked"}
	}
	// Module path may carry a /vN suffix; match import prefix sans version.
	bare := regexp.MustCompile(`/v\d+$`).ReplaceAllString(pkg, "")
	for _, f := range inv.goFiles {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, re := range []*regexp.Regexp{goImportOne, goImportBlock} {
			for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
				imp := m[1]
				if imp == pkg || imp == bare || strings.HasPrefix(imp, pkg+"/") || strings.HasPrefix(imp, bare+"/") {
					rel, _ := filepath.Rel(inv.root, f)
					dyn := ""
					if strings.HasPrefix(m[0], ". ") || strings.Contains(m[0], "_ ") {
						dyn = " (blank/dot import: conservative reachable)"
					}
					return &finding.Reachability{State: Reachable, Reason: "package imported by first-party source" + dyn, Evidence: filepath.ToSlash(rel)}
				}
			}
		}
	}
	return &finding.Reachability{State: Unreachable, Reason: "package not imported by any walked go source"}
}

// --- Python ---

var (
	pyImport    = regexp.MustCompile(`(?m)^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w., ]+))`)
	pyDynamic   = regexp.MustCompile(`__import__\s*\(|importlib\s*\.\s*(import_module|__import__)|exec\s*\(.*import|eval\s*\(.*import`)
	pyTopModule = regexp.MustCompile(`^[A-Za-z0-9_]+`)
)

// pyAliases maps distribution names to import names where they differ.
var pyAliases = map[string]string{
	"pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4",
	"scikit-learn": "sklearn", "python-dateutil": "dateutil",
	"pyopenssl": "OpenSSL", "pymysql": "pymysql", "psycopg2": "psycopg2",
	"psycopg2-binary": "psycopg2", "pillow-simd": "PIL",
}

func importNames(dist string) []string {
	norm := strings.ToLower(strings.ReplaceAll(dist, "-", "_"))
	names := []string{norm}
	if top := pyTopModule.FindString(norm); top != "" && top != norm {
		names = append(names, top)
	}
	if alias, ok := pyAliases[strings.ToLower(strings.ReplaceAll(dist, "_", "-"))]; ok {
		names = append(names, strings.ToLower(alias))
	}
	if alias, ok := pyAliases[norm]; ok {
		names = append(names, strings.ToLower(alias))
	}
	return names
}

func (inv *inventory) resolvePython(pkg string) *finding.Reachability {
	if len(inv.pyFiles) == 0 {
		return &finding.Reachability{State: Unknown, Reason: "no python sources under root"}
	}
	candidates := importNames(pkg)
	dynSeen := false
	for _, f := range inv.pyFiles {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		src := string(raw)
		if pyDynamic.MatchString(src) {
			dynSeen = true
		}
		for _, m := range pyImport.FindAllStringSubmatch(src, -1) {
			var tops []string
			if m[1] != "" {
				// "from X import ...": X is the module.
				tops = append(tops, strings.ToLower(strings.Split(strings.TrimSpace(m[1]), ".")[0]))
			} else {
				// "import a [, b as c]": each part's head, minus aliases.
				for _, part := range strings.Split(m[2], ",") {
					part = strings.TrimSpace(part)
					if i := strings.Index(part, " as "); i >= 0 {
						part = strings.TrimSpace(part[:i])
					}
					part = strings.Trim(part, "()")
					if part == "" {
						continue
					}
					tops = append(tops, strings.ToLower(strings.Split(part, ".")[0]))
				}
			}
			for _, top := range tops {
				for _, cand := range candidates {
					if top != "" && top == cand {
						rel, _ := filepath.Rel(inv.root, f)
						return &finding.Reachability{State: Reachable, Reason: "package imported by first-party source", Evidence: filepath.ToSlash(rel)}
					}
				}
			}
		}
	}
	if dynSeen {
		return &finding.Reachability{State: Unknown, Reason: "dynamic import constructs present; cannot prove absence"}
	}
	return &finding.Reachability{State: Unreachable, Reason: "package not imported by any walked python source"}
}

// --- JavaScript/npm ---

var (
	jsStaticImport  = regexp.MustCompile(`(?m)^\s*import\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]`)
	jsRequire       = regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	jsDynImportLit  = regexp.MustCompile(`import\s*\(\s*['"]([^'"]+)['"]`)
	jsDynImportExpr = regexp.MustCompile(`import\s*\(\s*[^'")\s]`)
	jsExportFrom    = regexp.MustCompile(`(?m)^\s*export\s[^;'"]*?from\s*['"]([^'"]+)['"]`)
)

func jsPkgName(spec string) string {
	if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
		return ""
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") && len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func (inv *inventory) resolveJS(pkg string) *finding.Reachability {
	if len(inv.jsFiles) == 0 {
		return &finding.Reachability{State: Unknown, Reason: "no javascript sources under root"}
	}
	dynSeen := false
	for _, f := range inv.jsFiles {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		src := string(raw)
		if jsDynImportExpr.MatchString(src) {
			dynSeen = true
		}
		specs := []string{}
		for _, m := range jsStaticImport.FindAllStringSubmatch(src, -1) {
			specs = append(specs, m[1])
		}
		for _, m := range jsRequire.FindAllStringSubmatch(src, -1) {
			specs = append(specs, m[1])
		}
		for _, m := range jsDynImportLit.FindAllStringSubmatch(src, -1) {
			specs = append(specs, m[1])
		}
		for _, m := range jsExportFrom.FindAllStringSubmatch(src, -1) {
			specs = append(specs, m[1])
		}
		for _, s := range specs {
			if jsPkgName(s) == pkg {
				rel, _ := filepath.Rel(inv.root, f)
				return &finding.Reachability{State: Reachable, Reason: "package imported by first-party source", Evidence: filepath.ToSlash(rel)}
			}
		}
	}
	if dynSeen {
		return &finding.Reachability{State: Unknown, Reason: "dynamic import() with non-literal present; cannot prove absence"}
	}
	return &finding.Reachability{State: Unreachable, Reason: "package not imported by any walked javascript source"}
}
