package endpoints

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// This file resolves Flask and FastAPI facts into routes (SPEC §5, Python
// bullet). Every route decorator is its own registration; only gate decorators
// below it on the same def wrap the registered function. Router prefixes and
// dependencies are joined across files through imports
// (resolve_python_project.go); a router no mount reaches stays unknown.

var (
	pyQuotedRe = regexp.MustCompile(`["']([^"']+)["']`)
	// Python gate names put the role in the function name (require_admin),
	// unlike the Go/JS middleware list where "admin" alone is not a role word.
	// Permission, RBAC and authorize names are role gates too (T29).
	pyRoleRe = regexp.MustCompile(`(?i)(role|authority|admin|superuser|permission|rbac|acl|authorize)`)
)

// pyGate is one thing that can protect a route: a decorator, a FastAPI
// parameter dependency, or a router/include dependency list.
type pyGate struct {
	expr     string // as written, matched against the shared gate regexes
	evidence string // "file:line what decided it"
	line     int
	defLine  int // the def the gate belongs to; gates from another same-name function do not apply
}

// pyDef is an application, router or blueprint created in the file.
type pyDef struct {
	kind   string // engine, router, blueprint
	prefix string
	deps   []string // raw dependency lists from APIRouter(...)
	line   int
}

// pyMount is an include_router or register_blueprint call.
type pyMount struct {
	owner, target string
	call          string // include_router, register_blueprint
	prefix        string
	hasPrefix     bool // the keyword was written, even when its value is ""
	deps          []string
	line          int
}

// pyState is what a route receiver carries at its registration: prefixes from
// the mount chain (outermost first) and gates from the router chain.
type pyState struct {
	prefixes []string
	deps     []pyGate
	unknown  bool
	reason   string
}

type pyResolver struct {
	file, root string
	framework  string
	matcher    *gateMatcher
	defs       map[string]*pyDef
	mounts     []pyMount
	routes     []Fact
	routeLines []Fact              // one fact per route decorator line, including stacked ones
	routeDeps  map[int][]pyGate    // route decorator line -> dependencies=[...] on that decorator
	gates      map[string][]pyGate // handler -> decorators and parameter gates
	unresolved []string
	project    *pyProject
}

// resolvePython sends each Python file to the Flask/FastAPI resolver.
func resolvePython(facts []Fact, root string, gates *gateMatcher) ([]Route, []string) {
	byFile := map[string][]Fact{}
	var files []string
	for _, f := range facts {
		if !strings.HasSuffix(f.File, ".py") {
			continue
		}
		if _, ok := byFile[f.File]; !ok {
			files = append(files, f.File)
		}
		byFile[f.File] = append(byFile[f.File], f)
	}
	sort.Strings(files)

	// Every file is read before any route is resolved: a router may be
	// mounted in a module that sorts after it.
	project := newPyProject(root)
	for _, file := range files {
		py := newPyResolver(file, byFile[file], root, gates)
		py.project = project
		project.resolvers[file] = py
	}
	project.link(files)

	var routes []Route
	var unresolved []string
	for _, file := range files {
		py := project.resolvers[file]
		fileRoutes, fileUnresolved := py.resolve()
		routes = append(routes, fileRoutes...)
		unresolved = append(unresolved, fileUnresolved...)
	}
	return routes, unresolved
}

func newPyResolver(file string, facts []Fact, root string, gates *gateMatcher) *pyResolver {
	py := &pyResolver{file: file, root: root, framework: "flask", matcher: gates, defs: map[string]*pyDef{}, gates: map[string][]pyGate{}, routeDeps: map[int][]pyGate{}}
	mounts := map[string]*pyMount{}
	for _, f := range facts {
		name := f.Metavars["$R"]
		switch f.Kind {
		case "flask_app":
			py.defs[name] = &pyDef{kind: "engine", line: f.Line}
		case "fastapi_app":
			py.framework = "fastapi"
			py.appDef(name, f.Line)
		case "fastapi_app_deps":
			py.framework = "fastapi"
			def := py.appDef(name, f.Line)
			if deps := f.Metavars["$DEPS"]; deps != "" {
				def.deps = append(def.deps, deps)
			}
		case "router":
			py.framework = "fastapi"
			py.defs[name] = &pyDef{kind: "router", prefix: f.Metavars["$PREFIX"], deps: pyDepList(f), line: f.Line}
		case "blueprint":
			py.defs[name] = &pyDef{kind: "blueprint", prefix: f.Metavars["$PREFIX"], line: f.Line}
		case "include_router", "register_blueprint":
			py.addMount(mounts, f)
		case "route":
			py.routes = append(py.routes, f)
			py.addRouteDeps(f)
		case "route_decorator":
			py.routeLines = append(py.routeLines, f)
		case "decorator":
			py.addDecorator(f)
		case "param_gate":
			py.addParamGate(f)
		}
	}
	py.routeLines = pyDropQuotedRouteDecorators(py.root, py.file, py.routeLines)
	py.routeLines = append(py.routeLines, pySourceRoutes(py.root, py.file)...)
	py.addStackedRoutes()
	for _, m := range mounts {
		py.mounts = append(py.mounts, *m)
	}
	sort.Slice(py.mounts, func(i, j int) bool { return py.mounts[i].line < py.mounts[j].line })
	sort.Slice(py.routes, func(i, j int) bool { return pyRouteLine(py.routes[i]) < pyRouteLine(py.routes[j]) })
	for _, gates := range py.gates {
		sort.SliceStable(gates, func(i, j int) bool { return gates[i].line < gates[j].line })
	}
	return py
}

// appDef returns the FastAPI application definition, keeping dependencies
// whichever order the constructor and its dependency fact arrive in.
func (py *pyResolver) appDef(name string, line int) *pyDef {
	def := py.defs[name]
	if def == nil {
		def = &pyDef{kind: "engine"}
		py.defs[name] = def
	}
	def.line = line
	return def
}

// addStackedRoutes fills in the route decorators a structural pattern cannot
// see. routeLines holds the engine's facts and the source scan; one
// registration sits on every route decorator line, and the handler is the def
// below that stack.
func (py *pyResolver) addStackedRoutes() {
	seen := map[int]bool{}
	for _, f := range py.routes {
		seen[pyRouteLine(f)] = true
	}
	for _, f := range py.routeLines {
		if seen[f.Line] {
			continue
		}
		route, ok := py.routeFromDecorator(f)
		if !ok {
			continue
		}
		seen[f.Line] = true
		py.routes = append(py.routes, route)
		py.addRouteDeps(route)
	}
}

func (py *pyResolver) routeFromDecorator(f Fact) (Fact, bool) {
	args := f.Metavars["$ARGS"]
	path := pyFirstString(args)
	handler := f.Metavars["$H"]
	if path == "" || handler == "" {
		return Fact{}, false
	}
	metavars := map[string]string{"$X": f.Metavars["$X"], "$H": handler, "$PATH": path}
	if verb := strings.ToLower(f.Metavars["$VERB"]); verb != "" && verb != "route" {
		metavars["$VERB"] = verb
	}
	if methods := pyKeywordValue(args, "methods"); methods != "" {
		metavars["$METHODS"] = methods
	}
	if deps := pyKeywordValue(args, "dependencies"); deps != "" {
		metavars["$DEPS"] = deps
	}
	lines := map[string]int{}
	for name, line := range f.MetavarLines {
		lines[name] = line
	}
	return Fact{Kind: "route", File: f.File, Line: f.Line, Column: f.Column, Metavars: metavars, MetavarLines: lines}, true
}

// pyFirstString reads the first quoted path argument of a decorator.
func pyFirstString(s string) string {
	if m := pyQuotedRe.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}

// pyKeywordValue reads a keyword argument, keeping a bracketed list intact so
// the quoted-string parser and gate matcher see the same expression as before.
func pyKeywordValue(args, key string) string {
	i := strings.Index(args, key+"=")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(args[i+len(key)+1:])
	if rest == "" {
		return ""
	}
	if rest[0] == '[' || rest[0] == '(' || rest[0] == '{' {
		closer := map[byte]byte{'[': ']', '(': ')', '{': '}'}[rest[0]]
		depth := 0
		for j := 0; j < len(rest); j++ {
			if rest[j] == rest[0] {
				depth++
			} else if rest[j] == closer {
				depth--
				if depth == 0 {
					return rest[:j+1]
				}
			}
		}
		return rest
	}
	if j := strings.IndexByte(rest, ','); j >= 0 {
		return strings.TrimSpace(rest[:j])
	}
	return rest
}

// pyRouteLine is the decorator line of a registration. Opengrep reports a
// match span that may start at a decorator above the route, so the path
// metavariable's line is the one that names the registration.
func pyRouteLine(f Fact) int {
	if line := f.MetavarLines["$PATH"]; line > 0 {
		return line
	}
	return f.Line
}

// pyDefLine is the def a fact belongs to. Two functions may share a name; the
// def line keeps their decorators and parameters apart.
func pyDefLine(f Fact) int {
	return f.MetavarLines["$H"]
}

func pyDepList(f Fact) []string {
	if deps := f.Metavars["$DEPS"]; deps != "" {
		return []string{deps}
	}
	return nil
}

// addMount merges the prefix and dependency facts of one include/register call
// (opengrep reports one result per matching argument pattern).
func (py *pyResolver) addMount(mounts map[string]*pyMount, f Fact) {
	owner, target := f.Metavars["$A"], f.Metavars["$R"]
	if owner == "" || target == "" {
		return
	}
	key := fmt.Sprintf("%s|%s|%d", owner, target, f.Line)
	m := mounts[key]
	if m == nil {
		m = &pyMount{owner: owner, target: target, line: f.Line}
		mounts[key] = m
	}
	m.call = f.Kind
	if prefix, ok := f.Metavars["$PREFIX"]; ok {
		// Presence matters: url_prefix="" is an explicit override (T31),
		// distinct from a mount without the keyword.
		m.prefix, m.hasPrefix = prefix, true
	}
	if deps := f.Metavars["$DEPS"]; deps != "" {
		m.deps = append(m.deps, deps)
	}
}

func (py *pyResolver) addRouteDeps(f Fact) {
	handler, deps := f.Metavars["$H"], f.Metavars["$DEPS"]
	if handler == "" || deps == "" {
		return
	}
	line := pyRouteLine(f)
	evidence := fmt.Sprintf("%s:%d route dependencies %s on %s", py.file, line, omitCallArguments(deps), handler)
	py.routeDeps[line] = append(py.routeDeps[line], pyGate{expr: deps, evidence: evidence, line: line})
}

func (py *pyResolver) addDecorator(f Fact) {
	handler := f.Metavars["$H"]
	if handler == "" {
		return
	}
	expr := f.Metavars["$DEC"]
	if a1 := f.Metavars["$A1"]; a1 != "" {
		expr += "(" + a1
		if a2 := f.Metavars["$A2"]; a2 != "" {
			expr += ", " + a2
		}
		expr += ")"
	}
	line := f.Line
	if decLine := f.MetavarLines["$DEC"]; decLine > 0 {
		line = decLine
	}
	evidence := fmt.Sprintf("%s:%d decorator @%s on %s", py.file, line, omitCallArguments(expr), handler)
	py.gates[handler] = append(py.gates[handler], pyGate{expr: expr, evidence: evidence, line: line, defLine: pyDefLine(f)})
}

func (py *pyResolver) addParamGate(f Fact) {
	handler, param, dep := f.Metavars["$H"], f.Metavars["$P"], f.Metavars["$F"]
	kind := f.Metavars["$K"]
	if handler == "" || dep == "" {
		return
	}
	expr := kind + "(" + dep + ")"
	evidence := fmt.Sprintf("%s:%d parameter %s=%s on %s", py.file, f.Line, param, omitCallArguments(expr), handler)
	line := f.Line
	if paramLine := f.MetavarLines["$P"]; paramLine > 0 {
		line = paramLine
	}
	py.gates[handler] = append(py.gates[handler], pyGate{expr: expr, evidence: evidence, line: line, defLine: pyDefLine(f)})
}

func (py *pyResolver) resolve() ([]Route, []string) {
	var routes []Route
	for _, f := range py.routes {
		fileRoutes, err := py.routesFromFact(f)
		if err != nil {
			py.unresolved = append(py.unresolved, fmt.Sprintf("%s:%d %v", py.file, f.Line, err))
			continue
		}
		routes = append(routes, fileRoutes...)
	}
	return routes, py.unresolved
}

func (py *pyResolver) routesFromFact(f Fact) ([]Route, error) {
	rawPath := f.Metavars["$PATH"]
	receiver, handler := f.Metavars["$X"], f.Metavars["$H"]
	if rawPath == "" || receiver == "" || handler == "" {
		return nil, fmt.Errorf("route path, receiver or handler could not be resolved")
	}
	line, defLine := pyRouteLine(f), pyDefLine(f)
	state := py.stateOf(receiver, 0)
	protection, roles, evidence := py.decide(line, defLine, handler, state)
	confidence := "high"
	if protection == ProtUnknown {
		confidence = "low"
		py.addUnknown(state, receiver)
	}
	fullPath := joinPaths(state.prefixes, rawPath)
	var routes []Route
	for _, method := range pyMethods(f) {
		routes = append(routes, Route{
			Service:    serviceOf(py.root, py.file),
			Framework:  py.framework,
			Method:     method,
			Path:       fullPath,
			Handler:    handler,
			File:       py.file,
			Line:       line,
			Protection: protection,
			Roles:      roles,
			Evidence:   evidence,
			Confidence: confidence,
		})
	}
	return routes, nil
}

// pyMethods reads the method of a verb decorator, the methods=[...] list of a
// Flask route, or the Flask default GET (task T07).
func pyMethods(f Fact) []string {
	if verb := f.Metavars["$VERB"]; verb != "" {
		return []string{strings.ToUpper(verb)}
	}
	if list := f.Metavars["$METHODS"]; list != "" {
		var methods []string
		for _, m := range pyQuotedRe.FindAllStringSubmatch(list, -1) {
			methods = append(methods, strings.ToUpper(m[1]))
		}
		if len(methods) > 0 {
			return dedupe(methods)
		}
	}
	return []string{"GET"}
}

// stateOf resolves a route receiver through its own prefix/dependencies and
// every same-file mount that reaches it.
func (py *pyResolver) stateOf(name string, depth int) *pyState {
	name = strings.TrimSpace(name)
	if depth > 8 {
		return &pyState{unknown: true, reason: name}
	}
	def := py.defs[name]
	if def == nil {
		return &pyState{unknown: true, reason: name}
	}
	if def.kind == "engine" {
		return &pyState{deps: py.defGates(name, def)}
	}
	own := py.defGates(name, def)
	var mounts []pyExtMount
	for _, m := range py.mountsFor(name) {
		mounts = append(mounts, pyExtMount{res: py, mount: m})
	}
	if py.project != nil {
		mounts = append(mounts, py.project.external[py.file+"|"+name]...)
	}
	if len(mounts) == 0 {
		return &pyState{unknown: true, reason: name}
	}
	var merged *pyState
	for _, em := range mounts {
		m := em.mount
		owner := em.res.stateOf(m.owner, depth+1)
		if owner.unknown {
			return &pyState{unknown: true, reason: name}
		}
		next := &pyState{}
		next.prefixes = append(append([]string{}, owner.prefixes...), py.mountPrefixes(m, def)...)
		next.deps = append(append([]pyGate{}, own...), em.res.mountGates(m)...)
		next.deps = append(next.deps, owner.deps...)
		if merged == nil {
			merged = next
		} else if !samePyState(merged, next) {
			return &pyState{unknown: true, reason: name}
		}
	}
	return merged
}

// mountPrefixes applies the framework's prefix rule: Flask's register_blueprint
// url_prefix replaces the blueprint's own prefix, while FastAPI's
// include_router prefix adds to the router's prefix. An explicit empty
// url_prefix is still an override and removes the blueprint prefix.
func (py *pyResolver) mountPrefixes(m pyMount, def *pyDef) []string {
	if m.call == "register_blueprint" {
		if m.hasPrefix {
			return []string{m.prefix}
		}
		return []string{def.prefix}
	}
	return []string{m.prefix, def.prefix}
}

func (py *pyResolver) defGates(name string, def *pyDef) []pyGate {
	var gates []pyGate
	for _, deps := range def.deps {
		evidence := fmt.Sprintf("%s:%d APIRouter dependencies %s on router %s", py.file, def.line, omitCallArguments(deps), name)
		if def.kind == "engine" {
			evidence = fmt.Sprintf("%s:%d FastAPI application dependencies %s on app", py.file, def.line, omitCallArguments(deps))
		}
		gates = append(gates, pyGate{expr: deps, evidence: evidence, line: def.line})
	}
	return gates
}

func (py *pyResolver) mountGates(m pyMount) []pyGate {
	var gates []pyGate
	label := m.prefix
	if label == "" {
		label = "/"
	}
	for _, deps := range m.deps {
		evidence := fmt.Sprintf("%s:%d %s dependencies %s on mount %s", py.file, m.line, m.call, omitCallArguments(deps), label)
		gates = append(gates, pyGate{expr: deps, evidence: evidence, line: m.line})
	}
	return gates
}

func (py *pyResolver) mountsFor(name string) []pyMount {
	var out []pyMount
	for _, m := range py.mounts {
		if m.target == name {
			out = append(out, m)
		}
	}
	return out
}

func samePyState(a, b *pyState) bool {
	if a.unknown != b.unknown || strings.Join(a.prefixes, "|") != strings.Join(b.prefixes, "|") || len(a.deps) != len(b.deps) {
		return false
	}
	for i := range a.deps {
		if a.deps[i].expr != b.deps[i].expr || a.deps[i].evidence != b.deps[i].evidence {
			return false
		}
	}
	return true
}

// decide evaluates the gates below this route decorator on the same function,
// then the router/app chain. A decorator above the route decorator wraps the
// registered function from the outside and does not protect the route.
func (py *pyResolver) decide(line, defLine int, handler string, state *pyState) (Protection, []string, []string) {
	chain := append([]pyGate{}, py.routeDeps[line]...)
	for _, gate := range py.gates[handler] {
		if gate.defLine != defLine || gate.line <= line {
			continue
		}
		chain = append(chain, gate)
	}
	chain = append(chain, state.deps...)
	var evidence, roles []string
	authenticated, role := false, false
	for _, gate := range chain {
		if !py.matcher.re.MatchString(gate.expr) {
			continue
		}
		authenticated = true
		evidence = append(evidence, gate.evidence)
		if pyRoleRe.MatchString(gate.expr) {
			role = true
			roles = append(roles, roleNames(gate.expr)...)
		}
	}
	if role {
		return ProtRole, dedupe(roles), evidence
	}
	if authenticated {
		return ProtAuthenticated, nil, evidence
	}
	if state.unknown {
		evidence = append(evidence, fmt.Sprintf("%s:%d router %s is not mounted in any file this scan follows", py.file, line, state.reason))
		return ProtUnknown, nil, evidence
	}
	evidence = append(evidence, fmt.Sprintf("%s:%d no gate decorator or dependency on the route", py.file, line))
	for _, gate := range chain {
		if !py.matcher.re.MatchString(gate.expr) {
			evidence = append(evidence, gate.evidence+" (does not match the gate list)")
		}
	}
	return ProtPublic, nil, evidence
}

func (py *pyResolver) addUnknown(state *pyState, receiver string) {
	name := state.reason
	if name == "" {
		name = receiver
	}
	sentence := fmt.Sprintf("%s router %s: no include_router or register_blueprint of it was found; protection unknown", py.file, name)
	for _, s := range py.unresolved {
		if s == sentence {
			return
		}
	}
	py.unresolved = append(py.unresolved, sentence)
}
