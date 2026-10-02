// Package reachability answers one question per dependency finding: is the
// vulnerable package actually imported by first-party source, directly or
// through a dependency that is?
//
// Soundness contract (load-bearing):
//   - "unreachable" requires positive proof of absence: a resolvable
//     ecosystem with a complete first-party source walk and no import.
//   - A transitive dependency is never imported by name, so a missing import
//     proves nothing about it. It is "unreachable" only when the lock file's
//     dependency graph shows that no imported package depends on it; without
//     such a graph it is "unknown".
//   - Anything doubtful — dynamic imports, missing manifests, unsupported
//     ecosystems, unreadable trees — resolves to "unknown", which policy
//     treats as matching neither reachable nor unreachable. Unknown can
//     never silently demote a finding.
//   - Test-only use still counts as imported: reachability is about code
//     reference, not deployment topology.
package reachability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
		f.Reachability = inv.resolve(f.Artifact.Package, f.Artifact.Target)
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

	pkgJSONs  []string             // first-party package.json files
	jsConfigs []string             // small JSON files that may name a package (tool configuration)
	jsImports map[string]string    // imported package -> first importing file (relative)
	jsNamed   map[string]string    // package named in a string literal -> first file (relative)
	jsScripts map[string]bool      // words used in package.json scripts
	jsRead    bool                 // jsImports/jsDyn computed
	npmLocks  map[string]*npmGraph // lock file target -> dependency graph (nil: none usable)
	goMods    map[string]map[string]bool
}

// maxConfigBytes bounds the JSON files read for package names: tool
// configuration is small, data files are not.
const maxConfigBytes = 256 << 10

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
		case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro":
			inv.jsFiles = append(inv.jsFiles, p)
		case ".json":
			switch info.Name() {
			case "package.json":
				inv.pkgJSON = true
				inv.pkgJSONs = append(inv.pkgJSONs, p)
			case "package-lock.json", "npm-shrinkwrap.json":
			default:
				if info.Size() <= maxConfigBytes {
					inv.jsConfigs = append(inv.jsConfigs, p)
				}
			}
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

func (inv *inventory) resolve(pkg, target string) *finding.Reachability {
	inv.scan()
	switch ecosystemOf(target) {
	case "go":
		return inv.resolveGo(pkg, target)
	case "python":
		return inv.resolvePython(pkg, target)
	case "js":
		return inv.resolveJS(pkg, target)
	default:
		return &finding.Reachability{State: Unknown, Reason: "unsupported ecosystem for reachability"}
	}
}

// --- Go ---

var (
	goImportBlock = regexp.MustCompile(`(?m)^\s*(?:[\w.]+\s+)?"([^"]+)"`)
	goImportOne   = regexp.MustCompile(`(?m)^\s*import\s+(?:[\w.]+\s+)?"([^"]+)"`)
)

func (inv *inventory) resolveGo(pkg, target string) *finding.Reachability {
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
	// Not imported by name. Only a direct requirement can be ruled out that
	// way; an indirect one is used through another module.
	direct, listed := inv.goRequires(target)[pkg]
	switch {
	case !listed:
		return &finding.Reachability{State: Unknown, Reason: "module not listed in go.mod; cannot tell a direct from an indirect dependency"}
	case !direct:
		return &finding.Reachability{State: Unknown, Reason: "indirect dependency, used through another module; go.mod does not record which"}
	}
	return &finding.Reachability{State: Unreachable, Reason: "package not imported by any walked go source"}
}

var goRequireLine = regexp.MustCompile(`^([^\s()]+)\s+v\S+(\s*//\s*indirect\b)?`)

// goRequires reads the go.mod next to target: module path -> is it a direct
// requirement. Modules absent from the map are not listed at all.
func (inv *inventory) goRequires(target string) map[string]bool {
	modPath := filepath.Join(inv.root, filepath.Dir(filepath.FromSlash(target)), "go.mod")
	if reqs, ok := inv.goMods[modPath]; ok {
		return reqs
	}
	reqs := map[string]bool{}
	if inv.goMods == nil {
		inv.goMods = map[string]map[string]bool{}
	}
	inv.goMods[modPath] = reqs
	raw, err := os.ReadFile(modPath)
	if err != nil {
		return reqs
	}
	inBlock := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "require (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		case !inBlock:
			continue
		}
		if m := goRequireLine.FindStringSubmatch(line); m != nil {
			reqs[m[1]] = m[2] == ""
		}
	}
	return reqs
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

func (inv *inventory) resolvePython(pkg, target string) *finding.Reachability {
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
	// A pinned requirements or lock file also lists transitive packages, which
	// are never imported by name. Only a declared direct dependency can be
	// ruled out by a missing import.
	if !inv.pyDeclaredDirect(pkg, target) {
		return &finding.Reachability{State: Unknown, Reason: "not imported, and not declared as a direct dependency; cannot rule out use through another package"}
	}
	return &finding.Reachability{State: Unreachable, Reason: "package not imported by any walked python source"}
}

// pyDirectManifests are the files where a project declares the packages it
// depends on directly, as opposed to a resolved or frozen list.
var pyDirectManifests = []string{"pyproject.toml", "setup.cfg", "setup.py", "Pipfile", "requirements.in"}

var pyNameSeparators = regexp.MustCompile(`[-_.]+`)

// pyDeclaredDirect reports whether a manifest next to target names pkg as a
// dependency (names compared the way PyPI normalizes them).
func (inv *inventory) pyDeclaredDirect(pkg, target string) bool {
	name := regexp.QuoteMeta(pyNameSeparators.ReplaceAllString(strings.ToLower(pkg), "-"))
	name = strings.ReplaceAll(name, "-", `[-_.]+`)
	decl := regexp.MustCompile(`(?im)(?:^|[\s"'\[,])` + name + `(?:$|[\s"'\]\[=<>~!;,])`)
	dir := filepath.Join(inv.root, filepath.Dir(filepath.FromSlash(target)))
	for _, manifest := range pyDirectManifests {
		if raw, err := os.ReadFile(filepath.Join(dir, manifest)); err == nil && decl.Match(raw) {
			return true
		}
	}
	return false
}

// --- JavaScript/npm ---

var (
	jsStaticImport  = regexp.MustCompile(`(?m)^\s*import\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]`)
	jsRequire       = regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	jsDynImportLit  = regexp.MustCompile(`import\s*\(\s*['"]([^'"]+)['"]`)
	jsDynImportExpr = regexp.MustCompile(`import\s*\(\s*[^'")\s]`)
	// A quoted package specifier anywhere: modules, plugins and presets are
	// named as strings in configuration rather than imported.
	jsStringLiteral = regexp.MustCompile("[`'\"](@?[A-Za-z0-9][\\w.-]*(?:/[\\w.-]+)*)[`'\"]")
	jsScriptWord    = regexp.MustCompile(`[@\w][\w@./-]*`)
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

// readJSImports walks the first-party JavaScript once and records every
// imported package.
func (inv *inventory) readJSImports() {
	if inv.jsRead {
		return
	}
	inv.jsRead = true
	inv.jsImports = map[string]string{}
	inv.jsNamed = map[string]string{}
	inv.jsScripts = map[string]bool{}
	named := func(f, src string) {
		for _, m := range jsStringLiteral.FindAllStringSubmatch(src, -1) {
			name := jsPkgName(m[1])
			if _, seen := inv.jsNamed[name]; name != "" && !seen {
				rel, _ := filepath.Rel(inv.root, f)
				inv.jsNamed[name] = filepath.ToSlash(rel)
			}
		}
	}
	for _, f := range inv.jsConfigs {
		if raw, err := os.ReadFile(f); err == nil {
			named(f, string(raw))
		}
	}
	for _, f := range inv.pkgJSONs {
		var manifest struct {
			Scripts map[string]string `json:"scripts"`
		}
		if raw, err := os.ReadFile(f); err == nil && json.Unmarshal(raw, &manifest) == nil {
			for _, script := range manifest.Scripts {
				for _, word := range jsScriptWord.FindAllString(script, -1) {
					inv.jsScripts[word] = true
				}
			}
		}
	}
	for _, f := range inv.jsFiles {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		src := string(raw)
		if jsDynImportExpr.MatchString(src) {
			inv.jsDyn = true
		}
		named(f, src)
		for _, re := range []*regexp.Regexp{jsStaticImport, jsRequire, jsDynImportLit, jsExportFrom} {
			for _, m := range re.FindAllStringSubmatch(src, -1) {
				name := jsPkgName(m[1])
				if _, seen := inv.jsImports[name]; name != "" && !seen {
					rel, _ := filepath.Rel(inv.root, f)
					inv.jsImports[name] = filepath.ToSlash(rel)
				}
			}
		}
	}
}

// jsUse reports how first-party code uses a package without importing it: a
// framework or tool started from a package.json script, or a module, plugin or
// preset named in configuration. Either one runs the package.
func (inv *inventory) jsUse(pkg string, graph *npmGraph) (reason, evidence string, ok bool) {
	if graph != nil {
		for _, bin := range graph.bins[pkg] {
			if inv.jsScripts[bin] {
				return "run by a package.json script (" + bin + ")", "package.json", true
			}
		}
	}
	if inv.jsScripts[pkg] {
		return "run by a package.json script (" + pkg + ")", "package.json", true
	}
	if file, named := inv.jsNamed[pkg]; named {
		return "named in first-party source or configuration", file, true
	}
	return "", "", false
}

func (inv *inventory) resolveJS(pkg, target string) *finding.Reachability {
	if len(inv.jsFiles) == 0 {
		return &finding.Reachability{State: Unknown, Reason: "no javascript sources under root"}
	}
	inv.readJSImports()
	if file, ok := inv.jsImports[pkg]; ok {
		return &finding.Reachability{State: Reachable, Reason: "package imported by first-party source", Evidence: file}
	}
	graph := inv.npmGraph(target)
	if reason, file, ok := inv.jsUse(pkg, graph); ok {
		return &finding.Reachability{State: Reachable, Reason: "package " + reason, Evidence: file}
	}
	if graph == nil {
		// No dependency graph (yarn, pnpm, old npm lock files, or none): only
		// a missing lock file keeps the plain import check.
		if _, err := os.Stat(filepath.Join(inv.root, filepath.FromSlash(target))); err == nil {
			return &finding.Reachability{State: Unknown, Reason: "not imported, but this lock file has no readable dependency graph; cannot rule out use through another package"}
		}
	} else {
		roots := graph.roots[pkg]
		if len(roots) == 0 {
			return &finding.Reachability{State: Unknown, Reason: "package not found in the lock file's dependency graph"}
		}
		for _, root := range roots {
			if root == pkg {
				continue
			}
			if file, ok := inv.jsImports[root]; ok {
				return &finding.Reachability{State: Reachable, Reason: "transitive dependency of imported package " + root, Evidence: file}
			}
			if reason, file, ok := inv.jsUse(root, graph); ok {
				return &finding.Reachability{State: Reachable, Reason: "transitive dependency of " + root + ", which is " + reason, Evidence: file}
			}
		}
		if !inv.jsDyn && !(len(roots) == 1 && roots[0] == pkg) {
			return &finding.Reachability{State: Unreachable, Reason: "transitive dependency; no package that depends on it is imported, run by a script or named in configuration (" + summarize(roots, 3) + ")"}
		}
	}
	if inv.jsDyn {
		return &finding.Reachability{State: Unknown, Reason: "dynamic import() with non-literal present; cannot prove absence"}
	}
	return &finding.Reachability{State: Unreachable, Reason: "package not imported by any walked javascript source"}
}

func summarize(names []string, max int) string {
	if len(names) <= max {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:max], ", ") + ", …"
}

// npmGraph maps every package in an npm lock file (lockfileVersion 2 or 3) to
// the direct dependencies of first-party packages that pull it in.
type npmGraph struct {
	roots map[string][]string // package name -> sorted direct dependency names
	bins  map[string][]string // package name -> commands it installs
}

type npmLockEntry struct {
	Link                 bool              `json:"link"`
	Bin                  map[string]string `json:"bin"`
	Resolved             string            `json:"resolved"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

func (inv *inventory) npmGraph(target string) *npmGraph {
	if g, ok := inv.npmLocks[target]; ok {
		return g
	}
	if inv.npmLocks == nil {
		inv.npmLocks = map[string]*npmGraph{}
	}
	inv.npmLocks[target] = nil
	if strings.ToLower(filepath.Base(target)) != "package-lock.json" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(inv.root, filepath.FromSlash(target)))
	if err != nil {
		return nil
	}
	var lock struct {
		Packages map[string]npmLockEntry `json:"packages"`
	}
	if json.Unmarshal(raw, &lock) != nil || len(lock.Packages) == 0 {
		return nil
	}
	g := buildNpmGraph(lock.Packages)
	inv.npmLocks[target] = g
	return g
}

func buildNpmGraph(packages map[string]npmLockEntry) *npmGraph {
	// locate follows Node's lookup: the nearest node_modules, walking up.
	locate := func(from, name string) (string, bool) {
		for dir := from; ; {
			key := "node_modules/" + name
			if dir != "" {
				key = dir + "/" + key
			}
			if e, ok := packages[key]; ok {
				if e.Link && e.Resolved != "" {
					return e.Resolved, true
				}
				return key, true
			}
			if dir == "" {
				return "", false
			}
			if i := strings.LastIndex(dir, "/node_modules/"); i >= 0 {
				dir = dir[:i]
			} else {
				dir = ""
			}
		}
	}
	nameOf := func(key string) string {
		if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
			return key[i+len("node_modules/"):]
		}
		return ""
	}
	reach := map[string]map[string]bool{}
	for key, entry := range packages {
		if strings.Contains(key, "node_modules/") {
			continue // third-party; only first-party packages declare direct dependencies
		}
		for _, deps := range []map[string]string{entry.Dependencies, entry.DevDependencies, entry.OptionalDependencies, entry.PeerDependencies} {
			for direct := range deps {
				start, ok := locate(key, direct)
				if !ok {
					continue
				}
				seen := map[string]bool{start: true}
				for queue := []string{start}; len(queue) > 0; queue = queue[1:] {
					cur := queue[0]
					if name := nameOf(cur); name != "" {
						if reach[name] == nil {
							reach[name] = map[string]bool{}
						}
						reach[name][direct] = true
					}
					e := packages[cur]
					for _, next := range []map[string]string{e.Dependencies, e.OptionalDependencies, e.PeerDependencies} {
						for dep := range next {
							if k, ok := locate(cur, dep); ok && !seen[k] {
								seen[k] = true
								queue = append(queue, k)
							}
						}
					}
				}
			}
		}
	}
	g := &npmGraph{roots: map[string][]string{}, bins: map[string][]string{}}
	for key, entry := range packages {
		if name := nameOf(key); name != "" {
			for bin := range entry.Bin {
				g.bins[name] = append(g.bins[name], bin)
			}
			sort.Strings(g.bins[name])
		}
	}
	for name, directs := range reach {
		for d := range directs {
			g.roots[name] = append(g.roots[name], d)
		}
		sort.Strings(g.roots[name])
	}
	return g
}
