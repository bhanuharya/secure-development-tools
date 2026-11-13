package endpoints

import (
	"bufio"
	"fmt"
	"go/ast"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Go services usually build the engine in one file and register routes in
// another: main.go calls routes.Register(app.Group("/api")), or server.go calls
// Route(app) declared next to it in the same package. A router parameter is
// resolved from every call that passes it: in the same file, from the other
// files of the package, and, for an exported function, from packages that
// import it. Imports are mapped to directories through the module path in
// go.mod; packages outside the repository are not followed.

// goCallSite is a call made in fr.
type goCallSite struct {
	fr   *fileResolver
	call callSite
}

type goProject struct {
	root     string
	gates    *gateMatcher
	byFile   map[string]*fileResolver
	files    []*fileResolver // every Go file of the tree, once loaded
	loaded   bool
	modules  map[string]goModule // directory -> enclosing module
	callers  map[string][]goCallSite
	methods  map[string]int // method name -> declarations with a router parameter
	pkgNames map[string]string
	// While statesOf enumerates callers: the caller chosen for each parameter
	// (by key) and the parameters whose callers were found to differ.
	forced  map[string]int
	pending map[string]int
}

type goModule struct {
	dir, path string // dir relative to root ("." for the root); path from the module line
}

func newGoProject(root string, gates *gateMatcher) *goProject {
	return &goProject{root: root, gates: gates, byFile: map[string]*fileResolver{},
		modules: map[string]goModule{}, callers: map[string][]goCallSite{}, pkgNames: map[string]string{}}
}

func (p *goProject) add(fr *fileResolver) {
	fr.project = p
	p.byFile[fr.file] = fr
}

// goSkipDirs are never part of a service's own routing.
var goSkipDirs = map[string]bool{"vendor": true, "node_modules": true, "testdata": true, ".git": true}

// all returns a resolver for every Go file of the tree. Files without facts
// matter too: a package that only forwards a group (backoffice.Register(grp))
// is a link in the chain.
func (p *goProject) all() []*fileResolver {
	if p.loaded {
		return p.files
	}
	p.loaded = true
	_ = filepath.WalkDir(p.root, func(full string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if full != p.root && (goSkipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(p.root, full)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if _, ok := p.byFile[rel]; !ok {
			p.add(newFileResolver(rel, nil, p.root, p.gates))
		}
		return nil
	})
	files := make([]string, 0, len(p.byFile))
	for file := range p.byFile {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		p.files = append(p.files, p.byFile[file])
	}
	p.methods = map[string]int{}
	for _, fr := range p.files {
		for _, fn := range fr.funcs {
			if fn.method && hasRouterParam(fn) {
				p.methods[fn.name]++
			}
		}
	}
	return p.files
}

func hasRouterParam(fn funcScope) bool {
	for _, param := range fn.params {
		if routerParamRe.MatchString(param.typ) {
			return true
		}
	}
	return false
}

// callersOf lists the calls that can reach fn: plain calls from its package,
// pkg.Fn calls from packages importing it (exported functions only), and
// x.Method calls from its package, or from anywhere when no other method with
// a router parameter has that name.
func (fr *fileResolver) callersOf(fn *funcScope) []goCallSite {
	key := fmt.Sprintf("%s:%d", fr.file, fn.start)
	if fr.project != nil {
		if sites, ok := fr.project.callers[key]; ok {
			return sites
		}
	}
	var out []goCallSite
	for _, c := range fr.calls {
		if fr.reaches(fn, fr, c, true) {
			out = append(out, goCallSite{fr: fr, call: c})
		}
	}
	if fr.project == nil {
		return out
	}
	dir := path.Dir(fr.file)
	for _, other := range fr.project.all() {
		if other == fr {
			continue
		}
		samePkg := path.Dir(other.file) == dir && other.pkg == fr.pkg
		for _, c := range other.calls {
			if fr.reaches(fn, other, c, samePkg) {
				out = append(out, goCallSite{fr: other, call: c})
			}
		}
	}
	fr.project.callers[key] = out
	return out
}

// reaches reports whether call c, made in caller, calls fn declared in fr.
func (fr *fileResolver) reaches(fn *funcScope, caller *fileResolver, c callSite, samePkg bool) bool {
	if c.fn != fn.name {
		return false
	}
	if fn.method {
		if c.qual == "" {
			return false
		}
		if _, isImport := caller.importDir(c.qual); isImport {
			return false
		}
		return samePkg || (fr.project != nil && fr.project.methods[fn.name] == 1)
	}
	if c.qual == "" {
		return samePkg
	}
	if samePkg || !ast.IsExported(fn.name) || fr.project == nil {
		return false
	}
	target, isImport := caller.importDir(c.qual)
	return isImport && target == path.Dir(fr.file)
}

// importDir maps a qualifier to the directory of the package it imports. The
// second result is false when qual names no import (a variable).
func (fr *fileResolver) importDir(qual string) (string, bool) {
	for importPath, alias := range fr.imports {
		dir := ""
		if fr.project != nil {
			dir = fr.project.importDir(fr.file, importPath)
		}
		name := alias
		if name == "" && dir != "" && fr.project != nil {
			name = fr.project.pkgName(dir)
		}
		if name == "" {
			name = goDefaultPkgName(importPath)
		}
		if name == qual {
			return dir, true
		}
	}
	return "", false
}

// goDefaultPkgName guesses a package name from its path: the last element,
// skipping a /vN major-version suffix.
func goDefaultPkgName(importPath string) string {
	base := path.Base(importPath)
	if len(base) > 1 && base[0] == 'v' && strings.Trim(base[1:], "0123456789") == "" {
		base = path.Base(path.Dir(importPath))
	}
	return strings.ReplaceAll(base, "-", "_")
}

// importDir returns the directory of importPath relative to root when it is a
// package of the module enclosing from, or "" when it is not.
func (p *goProject) importDir(from, importPath string) string {
	mod, ok := p.moduleOf(path.Dir(from))
	if !ok {
		return ""
	}
	switch {
	case importPath == mod.path:
		return mod.dir
	case strings.HasPrefix(importPath, mod.path+"/"):
		return path.Join(mod.dir, strings.TrimPrefix(importPath, mod.path+"/"))
	}
	return ""
}

// moduleOf finds the go.mod at or above dir, inside root.
func (p *goProject) moduleOf(dir string) (goModule, bool) {
	if mod, ok := p.modules[dir]; ok {
		return mod, mod.path != ""
	}
	mod := goModule{}
	if modPath := readModulePath(filepath.Join(p.root, filepath.FromSlash(dir), "go.mod")); modPath != "" {
		mod = goModule{dir: dir, path: modPath}
	} else if dir != "." && dir != "" && dir != "/" {
		mod, _ = p.moduleOf(path.Dir(dir))
	}
	p.modules[dir] = mod
	return mod, mod.path != ""
}

func readModulePath(file string) string {
	f, err := os.Open(file)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "module" {
			return strings.Trim(fields[1], `"`)
		}
	}
	return ""
}

// pkgName is the package clause of the Go files in dir.
func (p *goProject) pkgName(dir string) string {
	if name, ok := p.pkgNames[dir]; ok {
		return name
	}
	name := ""
	for _, fr := range p.all() {
		if path.Dir(fr.file) == dir && fr.pkg != "" {
			name = fr.pkg
			break
		}
	}
	p.pkgNames[dir] = name
	return name
}
