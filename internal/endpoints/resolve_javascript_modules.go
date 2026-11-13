package endpoints

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Express services usually split routing over files: app.js mounts
// require('./routes'), and routes/index.js mounts one router per module, often
// built by a factory (createUserRouter(deps)). This file reads what each file
// imports and exports, and the body of every function, so a mount whose last
// argument comes from another file can be linked to the router it adds. Only
// relative imports inside the repository are followed; package imports and
// path aliases are not.

const jsIdent = `[A-Za-z_$][\w$]*`

var (
	jsRequireRe     = regexp.MustCompile(`\b(?:const|let|var)\s+(` + jsIdent + `)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)(?:\s*\.\s*(` + jsIdent + `))?`)
	jsRequireObjRe  = regexp.MustCompile(`\b(?:const|let|var)\s*\{([^{}]*)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)`)
	jsImportRe      = regexp.MustCompile(`(?m)^[ \t]*import\s+(?:type\s+)?([^'";]*?)\s*from\s*['"]([^'"]+)['"]`)
	jsImportEqRe    = regexp.MustCompile(`\bimport\s+(` + jsIdent + `)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)`)
	jsExportDeclRe  = regexp.MustCompile(`\bexport\s+(?:async\s+)?(?:function\s*\*?|const|let|var|class)\s*(` + jsIdent + `)`)
	jsExportDefRe   = regexp.MustCompile(`\bexport\s+default\s+(?:(?:async\s+)?function\s*\*?\s*|class\s+)?(` + jsIdent + `)`)
	jsExportListRe  = regexp.MustCompile(`\bexport\s*\{([^{}]*)\}(?:\s*from\s*['"]([^'"]+)['"])?`)
	jsModExportRe   = regexp.MustCompile(`\bmodule\.exports\s*=\s*(` + jsIdent + `)\s*;?[ \t]*(?:\r?\n|$)`)
	jsModExportReq  = regexp.MustCompile(`\bmodule\.exports\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)`)
	jsModExportObj  = regexp.MustCompile(`\bmodule\.exports\s*=\s*\{([^{}]*)\}`)
	jsExportsPropRe = regexp.MustCompile(`\b(?:module\.)?exports\.(` + jsIdent + `)\s*=\s*(` + jsIdent + `)\s*;?[ \t]*(?:\r?\n|$)`)
	jsExportsReqRe  = regexp.MustCompile(`\b(?:module\.)?exports\.(` + jsIdent + `)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)`)
	// A function expression that is exported directly: module.exports = (deps) => {...},
	// exports.createRouter = function (deps) {...}, export default (deps) => {...}.
	jsExportFnRe = regexp.MustCompile(`\b(?:module\.exports|(?:module\.)?exports\.(` + jsIdent + `)|export\s+default)\s*=?\s*(?:async\s+)?(?:function\b\s*\*?\s*(?:` + jsIdent + `)?\s*)?(?:<[^>()]*>)?\s*\(`)
	jsFuncDeclRe = regexp.MustCompile(`\bfunction\s*\*?\s*(` + jsIdent + `)\s*(?:<[^>()]*>)?\s*\(`)
	jsFuncVarRe  = regexp.MustCompile(`\b(?:const|let|var)\s+(` + jsIdent + `)\s*(?::[^=;\n]+)?=\s*(?:async\s+)?(?:function\b\s*\*?\s*(?:` + jsIdent + `)?\s*)?(?:<[^>()]*>)?\s*\(`)
	jsArrow1Re   = regexp.MustCompile(`\b(?:const|let|var)\s+(` + jsIdent + `)\s*=\s*(?:async\s+)?` + jsIdent + `\s*=>\s*\{`)
	jsReturnRe   = regexp.MustCompile(`\breturn\s+(` + jsIdent + `)\s*;?[ \t]*(?:\r?\n|\}|$)`)
	jsIdentOnly  = regexp.MustCompile(`^` + jsIdent + `$`)
)

// jsDefaultFn names a function expression exported as the module itself.
const jsDefaultFn = "<default>"

// jsImport is a local name bound to another file's export. name is "default"
// for a default import or a whole CommonJS module, "*" for a namespace import.
type jsImport struct {
	file string
	name string
}

// jsFunc is a function body: the lines it spans and its text, for return statements.
type jsFunc struct {
	start, end int
	body       string
}

type jsModule struct {
	imports   map[string]jsImport // local name -> import
	exports   map[string]string   // exported name -> local name in this file
	reexports map[string]jsImport // exported name -> another file's export
	funcs     map[string]jsFunc   // function name (or jsDefaultFn) -> body
}

// readJSModule parses the import, export and function shapes listed above.
func readJSModule(root, file string) *jsModule {
	m := &jsModule{imports: map[string]jsImport{}, exports: map[string]string{},
		reexports: map[string]jsImport{}, funcs: map[string]jsFunc{}}
	raw, err := os.ReadFile(filepath.Join(root, file))
	if err != nil {
		return m
	}
	src := jsBlankComments(raw)
	text := string(src)
	target := func(spec string) string { return jsResolveModule(root, file, spec) }

	for _, g := range jsRequireRe.FindAllStringSubmatch(text, -1) {
		if t := target(g[2]); t != "" {
			name := "default"
			if g[3] != "" {
				name = g[3]
			}
			m.imports[g[1]] = jsImport{file: t, name: name}
		}
	}
	for _, g := range jsImportEqRe.FindAllStringSubmatch(text, -1) {
		if t := target(g[2]); t != "" {
			m.imports[g[1]] = jsImport{file: t, name: "default"}
		}
	}
	for _, g := range jsRequireObjRe.FindAllStringSubmatch(text, -1) {
		if t := target(g[2]); t != "" {
			for exported, local := range jsBindingList(g[1], ":") {
				m.imports[local] = jsImport{file: t, name: exported}
			}
		}
	}
	for _, g := range jsImportRe.FindAllStringSubmatch(text, -1) {
		if t := target(g[2]); t != "" {
			jsImportClause(g[1], t, m.imports)
		}
	}

	for _, g := range jsExportDeclRe.FindAllStringSubmatch(text, -1) {
		m.exports[g[1]] = g[1]
	}
	for _, g := range jsExportDefRe.FindAllStringSubmatch(text, -1) {
		if g[1] != "function" && g[1] != "class" && g[1] != "async" {
			m.exports["default"] = g[1]
		}
	}
	for _, g := range jsExportListRe.FindAllStringSubmatch(text, -1) {
		for inner, outer := range jsBindingList(g[1], " as ") { // export { inner as outer }
			if g[2] == "" {
				m.exports[outer] = inner
				continue
			}
			if t := target(g[2]); t != "" {
				m.reexports[outer] = jsImport{file: t, name: inner}
			}
		}
	}
	for _, g := range jsModExportRe.FindAllStringSubmatch(text, -1) {
		m.exports["default"] = g[1]
	}
	for _, g := range jsModExportReq.FindAllStringSubmatch(text, -1) {
		if t := target(g[1]); t != "" {
			m.reexports["default"] = jsImport{file: t, name: "default"}
		}
	}
	for _, g := range jsModExportObj.FindAllStringSubmatch(text, -1) {
		for exported, local := range jsBindingList(g[1], ":") {
			m.exports[exported] = local
		}
	}
	for _, g := range jsExportsPropRe.FindAllStringSubmatch(text, -1) {
		m.exports[g[1]] = g[2]
	}
	for _, g := range jsExportsReqRe.FindAllStringSubmatch(text, -1) {
		if t := target(g[2]); t != "" {
			m.reexports[g[1]] = jsImport{file: t, name: "default"}
		}
	}

	lines := jsLineStarts(src)
	addFunc := func(name string, open int) bool {
		if _, seen := m.funcs[name]; seen {
			return true
		}
		start, end, ok := jsFuncBody(src, open)
		if !ok {
			return false
		}
		m.funcs[name] = jsFunc{start: jsLineAt(lines, start), end: jsLineAt(lines, end-1), body: string(src[start:end])}
		return true
	}
	for _, idx := range jsExportFnRe.FindAllSubmatchIndex(src, -1) {
		name, exported := jsDefaultFn, "default"
		if idx[2] >= 0 {
			name = string(src[idx[2]:idx[3]])
			exported = name
		}
		if addFunc(name, idx[1]-1) {
			m.exports[exported] = name
		}
	}
	for _, re := range []*regexp.Regexp{jsFuncDeclRe, jsFuncVarRe} {
		for _, idx := range re.FindAllSubmatchIndex(src, -1) {
			addFunc(string(src[idx[2]:idx[3]]), idx[1]-1)
		}
	}
	for _, idx := range jsArrow1Re.FindAllSubmatchIndex(src, -1) {
		name := string(src[idx[2]:idx[3]])
		if _, seen := m.funcs[name]; seen {
			continue
		}
		open := idx[1] - 1
		if end := scanBraceEnd(src, open+1); end > 0 {
			m.funcs[name] = jsFunc{start: jsLineAt(lines, open), end: jsLineAt(lines, end-1), body: string(src[open:end])}
		}
	}
	return m
}

// jsBindingList reads `a, b: c` (sep ":") or `a, b as c` (sep " as ") into
// exported -> local, or for export lists local -> exported. Defaults
// (`a = x`), rest elements and nested patterns are skipped.
func jsBindingList(list, sep string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), "type "))
		if part == "" || strings.HasPrefix(part, "...") {
			continue
		}
		if i := strings.Index(part, "="); i >= 0 {
			part = strings.TrimSpace(part[:i])
		}
		left, right := part, part
		if i := strings.Index(part, sep); i >= 0 {
			left, right = strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+len(sep):])
		}
		if jsIdentOnly.MatchString(left) && jsIdentOnly.MatchString(right) {
			out[left] = right
		}
	}
	return out
}

// jsImportClause reads `X`, `X, { a, b as c }`, `{ a }` and `* as ns`.
func jsImportClause(clause, file string, imports map[string]jsImport) {
	clause = strings.TrimSpace(clause)
	if open := strings.Index(clause, "{"); open >= 0 {
		if close := strings.Index(clause[open:], "}"); close > 0 {
			for exported, local := range jsBindingList(clause[open+1:open+close], " as ") {
				imports[local] = jsImport{file: file, name: exported}
			}
		}
		clause = strings.TrimSpace(clause[:open])
	}
	for _, part := range strings.Split(clause, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "*"):
			if i := strings.Index(part, " as "); i >= 0 {
				if ns := strings.TrimSpace(part[i+4:]); jsIdentOnly.MatchString(ns) {
					imports[ns] = jsImport{file: file, name: "*"}
				}
			}
		case jsIdentOnly.MatchString(part):
			imports[part] = jsImport{file: file, name: "default"}
		}
	}
}

// jsResolveModule maps a relative specifier to a file under root, trying the
// extensions and index files Node and TypeScript try. "" means not followed.
func jsResolveModule(root, from, spec string) string {
	if !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") && spec != "." && spec != ".." {
		return ""
	}
	base := path.Join(path.Dir(filepath.ToSlash(from)), spec)
	if base == ".." || strings.HasPrefix(base, "../") {
		return ""
	}
	exts := []string{".js", ".ts", ".mjs", ".cjs"}
	candidates := []string{base}
	for _, ext := range exts {
		candidates = append(candidates, base+ext)
	}
	if ext := path.Ext(base); ext == ".js" || ext == ".mjs" || ext == ".cjs" {
		candidates = append(candidates, strings.TrimSuffix(base, ext)+".ts") // ESM TypeScript imports name the output
	}
	for _, ext := range exts {
		candidates = append(candidates, base+"/index"+ext)
	}
	for _, c := range candidates {
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(c))); err == nil && info.Mode().IsRegular() {
			return c
		}
	}
	return ""
}

// jsFuncBody returns the offsets of the `{` and just past the `}` of the body
// of the function whose parameter list opens at open. A TypeScript return type
// between the parameters and the body is skipped; an arrow with an expression
// body has no block and is not a factory this file follows.
func jsFuncBody(src []byte, open int) (int, int, bool) {
	if open < 0 || open >= len(src) || src[open] != '(' {
		return 0, 0, false
	}
	close := jsMatchParen(src, open)
	if close < 0 {
		return 0, 0, false
	}
	i := skipJSSpace(src, close+1)
	if i < len(src) && src[i] == ':' {
		depth := 0
		for i++; i < len(src); i++ {
			c := src[i]
			if c == '(' || c == '[' || c == '<' {
				depth++
			} else if c == ')' || c == ']' || (c == '>' && src[i-1] != '=') {
				depth--
			} else if depth == 0 && (c == '{' || c == ';' || (c == '=' && i+1 < len(src) && src[i+1] == '>')) {
				break
			} else if c == '{' {
				if end := scanBraceEnd(src, i+1); end > 0 {
					i = end - 1
				}
			}
		}
	}
	if i+1 < len(src) && src[i] == '=' && src[i+1] == '>' {
		i = skipJSSpace(src, i+2)
	}
	if i >= len(src) || src[i] != '{' {
		return 0, 0, false
	}
	end := scanBraceEnd(src, i+1)
	if end < 0 {
		return 0, 0, false
	}
	return i, end, true
}

// jsMatchParen returns the index of the `)` matching the `(` at open.
func jsMatchParen(src []byte, open int) int {
	depth := 0
	for i := open; i < len(src); i++ {
		switch c := src[i]; c {
		case '\'', '"':
			i = skipJSString(src, i, c)
		case '`':
			end := scanTemplateEnd(src, i)
			if end < 0 {
				return -1
			}
			i = end - 1
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// jsBlankComments replaces comments with spaces, keeping newlines, so the
// regular expressions above never read commented-out code.
func jsBlankComments(src []byte) []byte {
	out := append([]byte{}, src...)
	for i := 0; i < len(out); i++ {
		switch c := out[i]; {
		case c == '\'' || c == '"':
			i = skipJSString(out, i, c)
		case c == '`':
			if end := scanTemplateEnd(out, i); end > 0 {
				i = end - 1
			}
		case c == '/' && i+1 < len(out) && (out[i+1] == '/' || out[i+1] == '*'):
			end, _ := skipComment(out, i)
			for j := i; j < end && j < len(out); j++ {
				if out[j] != '\n' {
					out[j] = ' '
				}
			}
			i = end - 1
		}
	}
	return out
}

func jsLineStarts(src []byte) []int {
	starts := []int{0}
	for i, c := range src {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// jsLineAt is the 1-based line of offset.
func jsLineAt(starts []int, offset int) int {
	return sort.Search(len(starts), func(i int) bool { return starts[i] > offset })
}

// jsTarget is the router a mount adds: a declaration in some file's resolver.
type jsTarget struct {
	res     *jsResolver
	binding *jsBinding
}

// jsProject links the Express files of one inventory. Mounts holds, for each
// router declaration, the mounts in any file that add it.
type jsProject struct {
	root      string
	resolvers map[string]*jsResolver
	modules   map[string]*jsModule
	mounts    map[*jsBinding][]jsMount
}

func newJSProject(root string) *jsProject {
	return &jsProject{root: root, resolvers: map[string]*jsResolver{},
		modules: map[string]*jsModule{}, mounts: map[*jsBinding][]jsMount{}}
}

func (p *jsProject) module(file string) *jsModule {
	if m, ok := p.modules[file]; ok {
		return m
	}
	m := readJSModule(p.root, file)
	p.modules[file] = m
	return m
}

// link resolves every use() whose last argument is not a router declared in
// the same file: an imported router, an imported or local factory call, or
// require('./x'). A resolved target turns the call into a mount.
func (p *jsProject) link(files []string) {
	for _, file := range files {
		js := p.resolvers[file]
		if js == nil || js.nest {
			continue
		}
		for i, u := range js.uses {
			if len(u.args) == 0 || !js.serverReceiver(u.receiver) {
				continue
			}
			last := strings.TrimSpace(u.args[len(u.args)-1])
			if js.routers[last] || js.engines[last] {
				continue // a same-file mount, matched by name in mountsFor
			}
			t := p.routerExpr(js, last, u.line, 0)
			if t == nil {
				continue
			}
			js.uses[i].target = t
			m := js.mountOf(js.uses[i])
			m.from = js
			p.mounts[t.binding] = append(p.mounts[t.binding], m)
		}
	}
}

// routerExpr resolves an expression used as the router of a mount.
func (p *jsProject) routerExpr(js *jsResolver, expr string, line, depth int) *jsTarget {
	if depth > 8 || expr == "" {
		return nil
	}
	mod := p.module(js.file)
	if strings.HasPrefix(expr, "require(") {
		closeIdx := strings.Index(expr, ")")
		if closeIdx < 0 {
			return nil
		}
		file := jsResolveModule(p.root, js.file, unquote(strings.TrimSpace(expr[len("require("):closeIdx])))
		rest := strings.TrimSpace(expr[closeIdx+1:])
		switch {
		case file == "":
			return nil
		case rest == "":
			return p.exportTarget(file, "default", false, depth+1)
		case strings.HasPrefix(rest, ".") && jsIdentOnly.MatchString(rest[1:]):
			return p.exportTarget(file, rest[1:], false, depth+1)
		case strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")"):
			return p.exportTarget(file, "default", true, depth+1)
		}
		return nil
	}
	call := false
	name := expr
	if strings.HasSuffix(expr, ")") {
		name = callableName(expr)
		if name == expr || name == "" {
			return nil
		}
		call = true
	}
	if jsIdentOnly.MatchString(name) {
		if call {
			if _, ok := mod.funcs[name]; ok {
				return p.factoryTarget(js.file, name)
			}
		} else if b := js.bindingAt(name, line); b != nil && (b.router || b.engine) {
			return &jsTarget{res: js, binding: b}
		}
		if imp, ok := mod.imports[name]; ok && imp.name != "*" {
			return p.exportTarget(imp.file, imp.name, call, depth+1)
		}
		return nil
	}
	// ns.userRouter or routes.createUserRouter(...): a member of an imported module.
	dot := strings.LastIndex(name, ".")
	if dot <= 0 {
		return nil
	}
	head, member := strings.TrimSpace(name[:dot]), strings.TrimSpace(name[dot+1:])
	imp, ok := mod.imports[head]
	if !ok || !jsIdentOnly.MatchString(member) || (imp.name != "*" && imp.name != "default") {
		return nil
	}
	return p.exportTarget(imp.file, member, call, depth+1)
}

// exportTarget follows an export to the router it names: a router declared at
// the top of the file, or, for a call, the router a factory function returns.
func (p *jsProject) exportTarget(file, name string, call bool, depth int) *jsTarget {
	if depth > 8 {
		return nil
	}
	mod := p.module(file)
	if re, ok := mod.reexports[name]; ok {
		return p.exportTarget(re.file, re.name, call, depth+1)
	}
	local, ok := mod.exports[name]
	if !ok {
		return nil
	}
	if imp, ok := mod.imports[local]; ok && imp.name != "*" {
		return p.exportTarget(imp.file, imp.name, call, depth+1)
	}
	if call {
		return p.factoryTarget(file, local)
	}
	js := p.resolvers[file]
	if js == nil || js.nest {
		return nil
	}
	for i := range js.bindings {
		b := &js.bindings[i]
		if b.name == local && b.end == jsTopLevelEnd && (b.router || b.engine) {
			return &jsTarget{res: js, binding: b}
		}
	}
	return nil
}

// factoryTarget is the router a function creates and returns: the only
// router declared in its body, or the one its return statement names.
func (p *jsProject) factoryTarget(file, fn string) *jsTarget {
	js := p.resolvers[file]
	if js == nil || js.nest {
		return nil
	}
	body, ok := p.module(file).funcs[fn]
	if !ok {
		return nil
	}
	var inside []*jsBinding
	for i := range js.bindings {
		b := &js.bindings[i]
		if (b.router || b.engine) && b.line >= body.start && b.line <= body.end {
			inside = append(inside, b)
		}
	}
	if len(inside) == 1 {
		return &jsTarget{res: js, binding: inside[0]}
	}
	returned := map[string]bool{}
	for _, g := range jsReturnRe.FindAllStringSubmatch(body.body, -1) {
		returned[g[1]] = true
	}
	var match *jsBinding
	for _, b := range inside {
		if returned[b.name] {
			if match != nil {
				return nil
			}
			match = b
		}
	}
	if match == nil {
		return nil
	}
	return &jsTarget{res: js, binding: match}
}
