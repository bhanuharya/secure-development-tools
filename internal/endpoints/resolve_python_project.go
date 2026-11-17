package endpoints

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// FastAPI and Flask services usually define a router or blueprint in one
// module and mount it in another: main.py does
// `from app.routers.users import router as users_router` and
// `app.include_router(users_router, prefix="/users")`. Each file's imports are
// read so a mount's target can be linked to the definition it names. Absolute
// imports are looked up from every folder between the importing file and the
// repository root (a src/ layout or a service subfolder); relative imports
// (from .users import router) from the importing file's package.

var (
	pyFromImportRe = regexp.MustCompile(`(?m)^[ \t]*from[ \t]+(\.*[\w.]*)[ \t]+import[ \t]+(\([^)]*\)|[^\n#]+)`)
	pyImportRe     = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+([\w.]+)(?:[ \t]+as[ \t]+(\w+))?[ \t]*(?:#.*)?$`)
	pyIdentRe      = regexp.MustCompile(`^[A-Za-z_]\w*$`)
)

// pyImport binds a local name to a definition in another file, or to the
// module itself when name is "".
type pyImport struct {
	file string
	name string
}

// pyExtMount is a mount made in another file (by res) of a definition here.
type pyExtMount struct {
	res   *pyResolver
	mount pyMount
}

type pyProject struct {
	root      string
	resolvers map[string]*pyResolver
	imports   map[string]map[string]pyImport
	external  map[string][]pyExtMount // "file|name" of the definition -> mounts
}

func newPyProject(root string) *pyProject {
	return &pyProject{root: root, resolvers: map[string]*pyResolver{},
		imports: map[string]map[string]pyImport{}, external: map[string][]pyExtMount{}}
}

// link records every mount whose target is a definition of another file.
func (p *pyProject) link(files []string) {
	for _, file := range files {
		res := p.resolvers[file]
		for _, m := range res.mounts {
			if res.defs[m.target] != nil {
				continue // a same-file mount, matched by name
			}
			target, name := p.resolveTarget(file, m.target)
			if target == "" {
				continue
			}
			def := p.resolvers[target]
			if def == nil || def.defs[name] == nil {
				continue
			}
			key := target + "|" + name
			p.external[key] = append(p.external[key], pyExtMount{res: res, mount: m})
		}
	}
}

// resolveTarget maps a mount argument (users_router, users.router) to the file
// and name of the definition it refers to.
func (p *pyProject) resolveTarget(file, expr string) (string, string) {
	imports := p.importsOf(file)
	expr = strings.TrimSpace(expr)
	if pyIdentRe.MatchString(expr) {
		if imp, ok := imports[expr]; ok && imp.name != "" {
			return imp.file, imp.name
		}
		return "", ""
	}
	dot := strings.LastIndexByte(expr, '.')
	if dot <= 0 {
		return "", ""
	}
	head, member := expr[:dot], expr[dot+1:]
	if !pyIdentRe.MatchString(member) {
		return "", ""
	}
	if imp, ok := imports[head]; ok && imp.name == "" {
		return imp.file, member
	}
	return "", ""
}

func (p *pyProject) importsOf(file string) map[string]pyImport {
	if imports, ok := p.imports[file]; ok {
		return imports
	}
	imports := map[string]pyImport{}
	p.imports[file] = imports
	raw, err := os.ReadFile(filepath.Join(p.root, file))
	if err != nil {
		return imports
	}
	src := string(raw)
	for _, m := range pyFromImportRe.FindAllStringSubmatch(src, -1) {
		module := m[1]
		names := strings.Trim(strings.TrimSpace(m[2]), "()")
		for _, part := range strings.Split(names, ",") {
			part = strings.TrimSpace(strings.SplitN(part, "#", 2)[0])
			name, local := part, part
			if i := strings.Index(part, " as "); i >= 0 {
				name, local = strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+4:])
			}
			if !pyIdentRe.MatchString(name) || !pyIdentRe.MatchString(local) {
				continue
			}
			// from pkg import users: users may be a submodule, used as users.router.
			if sub := p.moduleFile(file, joinModule(module, name)); sub != "" {
				imports[local] = pyImport{file: sub}
				continue
			}
			if target := p.moduleFile(file, module); target != "" {
				imports[local] = pyImport{file: target, name: name}
			}
		}
	}
	for _, m := range pyImportRe.FindAllStringSubmatch(src, -1) {
		if m[2] == "" {
			continue // import a.b.c binds a, not the module; not followed
		}
		if target := p.moduleFile(file, m[1]); target != "" {
			imports[m[2]] = pyImport{file: target}
		}
	}
	return imports
}

func joinModule(module, name string) string {
	if module == "" || strings.HasSuffix(module, ".") {
		return module + name
	}
	return module + "." + name
}

// moduleFile finds the file of a dotted module, relative (leading dots) or
// absolute, as name.py or name/__init__.py.
func (p *pyProject) moduleFile(from, module string) string {
	if module == "" {
		return ""
	}
	var bases []string
	if strings.HasPrefix(module, ".") {
		dots := len(module) - len(strings.TrimLeft(module, "."))
		base := path.Dir(filepath.ToSlash(from))
		for i := 1; i < dots; i++ {
			base = path.Dir(base)
		}
		bases = []string{base}
		module = module[dots:]
	} else {
		for dir := path.Dir(filepath.ToSlash(from)); ; dir = path.Dir(dir) {
			bases = append(bases, dir)
			if dir == "." || dir == "/" || dir == "" {
				break
			}
		}
	}
	rel := strings.ReplaceAll(module, ".", "/")
	for _, base := range bases {
		for _, candidate := range []string{path.Join(base, rel) + ".py", path.Join(base, rel, "__init__.py")} {
			if strings.HasPrefix(candidate, "../") {
				continue
			}
			if info, err := os.Stat(filepath.Join(p.root, filepath.FromSlash(candidate))); err == nil && info.Mode().IsRegular() {
				return candidate
			}
		}
	}
	return ""
}
