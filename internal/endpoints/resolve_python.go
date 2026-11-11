package endpoints

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// This file resolves Flask and FastAPI facts into routes (SPEC §5, Python
// bullet). A route decorator, the gate decorators stacked under it and FastAPI
// parameter gates are joined by the handler name. Router prefixes and
// dependencies are joined inside one file only: an APIRouter or Blueprint
// created or mounted elsewhere stays unknown.

var (
	pyQuotedRe = regexp.MustCompile(`["']([^"']+)["']`)
	// Python gate names put the role in the function name (require_admin),
	// unlike the Go/JS middleware list where "admin" alone is not a role word.
	pyRoleRe = regexp.MustCompile(`(?i)(role|authority|admin|superuser)`)
)

// pyGate is one thing that can protect a route: a decorator, a FastAPI
// parameter dependency, or a router/include dependency list.
type pyGate struct {
	expr     string // as written, matched against the shared gate regexes
	evidence string // "file:line what decided it"
	line     int
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
	routeDeps  map[string][]pyGate // handler -> dependencies=[...] on the route decorator
	gates      map[string][]pyGate // handler -> decorators and parameter gates
	unresolved []string
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

	var routes []Route
	var unresolved []string
	for _, file := range files {
		py := newPyResolver(file, byFile[file], root, gates)
		fileRoutes, fileUnresolved := py.resolve()
		routes = append(routes, fileRoutes...)
		unresolved = append(unresolved, fileUnresolved...)
	}
	return routes, unresolved
}

func newPyResolver(file string, facts []Fact, root string, gates *gateMatcher) *pyResolver {
	py := &pyResolver{file: file, root: root, framework: "flask", matcher: gates, defs: map[string]*pyDef{}, gates: map[string][]pyGate{}, routeDeps: map[string][]pyGate{}}
	mounts := map[string]*pyMount{}
	for _, f := range facts {
		name := f.Metavars["$R"]
		switch f.Kind {
		case "flask_app":
			py.defs[name] = &pyDef{kind: "engine", line: f.Line}
		case "fastapi_app":
			py.framework = "fastapi"
			py.defs[name] = &pyDef{kind: "engine", line: f.Line}
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
		case "decorator":
			py.addDecorator(f)
		case "param_gate":
			py.addParamGate(f)
		}
	}
	for _, m := range mounts {
		py.mounts = append(py.mounts, *m)
	}
	sort.Slice(py.mounts, func(i, j int) bool { return py.mounts[i].line < py.mounts[j].line })
	sort.Slice(py.routes, func(i, j int) bool { return py.routes[i].Line < py.routes[j].Line })
	for _, gates := range py.gates {
		sort.SliceStable(gates, func(i, j int) bool { return gates[i].line < gates[j].line })
	}
	return py
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
	if prefix := f.Metavars["$PREFIX"]; prefix != "" {
		m.prefix = prefix
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
	evidence := fmt.Sprintf("%s:%d route dependencies %s on %s", py.file, f.Line, deps, handler)
	py.routeDeps[handler] = append(py.routeDeps[handler], pyGate{expr: deps, evidence: evidence, line: f.Line})
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
	evidence := fmt.Sprintf("%s:%d decorator @%s on %s", py.file, f.Line, expr, handler)
	py.gates[handler] = append(py.gates[handler], pyGate{expr: expr, evidence: evidence, line: f.Line})
}

func (py *pyResolver) addParamGate(f Fact) {
	handler, param, dep := f.Metavars["$H"], f.Metavars["$P"], f.Metavars["$F"]
	kind := f.Metavars["$K"]
	if handler == "" || dep == "" {
		return
	}
	expr := kind + "(" + dep + ")"
	evidence := fmt.Sprintf("%s:%d parameter %s=%s on %s", py.file, f.Line, param, expr, handler)
	py.gates[handler] = append(py.gates[handler], pyGate{expr: expr, evidence: evidence, line: f.Line})
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
	state := py.stateOf(receiver, 0)
	protection, roles, evidence := py.decide(f, handler, state)
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
			Line:       f.Line,
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
		return &pyState{}
	}
	own := py.defGates(name, def)
	mounts := py.mountsFor(name)
	if len(mounts) == 0 {
		return &pyState{unknown: true, reason: name}
	}
	var merged *pyState
	for _, m := range mounts {
		owner := py.stateOf(m.owner, depth+1)
		if owner.unknown {
			return &pyState{unknown: true, reason: name}
		}
		next := &pyState{}
		next.prefixes = append(append([]string{}, owner.prefixes...), m.prefix, def.prefix)
		next.deps = append(append([]pyGate{}, own...), py.mountGates(m)...)
		next.deps = append(next.deps, owner.deps...)
		if merged == nil {
			merged = next
		} else if !samePyState(merged, next) {
			return &pyState{unknown: true, reason: name}
		}
	}
	return merged
}

func (py *pyResolver) defGates(name string, def *pyDef) []pyGate {
	var gates []pyGate
	for _, deps := range def.deps {
		evidence := fmt.Sprintf("%s:%d APIRouter dependencies %s on router %s", py.file, def.line, deps, name)
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
		evidence := fmt.Sprintf("%s:%d %s dependencies %s on mount %s", py.file, m.line, m.call, deps, label)
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

// decide evaluates route gates first, then the router chain. The router chain
// only exists when the receiver was created and mounted in this file.
func (py *pyResolver) decide(f Fact, handler string, state *pyState) (Protection, []string, []string) {
	chain := append([]pyGate{}, py.routeDeps[handler]...)
	chain = append(chain, py.gates[handler]...)
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
		evidence = append(evidence, fmt.Sprintf("%s:%d router %s is not created or mounted in this file", py.file, f.Line, state.reason))
		return ProtUnknown, nil, evidence
	}
	evidence = append(evidence, fmt.Sprintf("%s:%d no gate decorator or dependency on the route", py.file, f.Line))
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
	sentence := fmt.Sprintf("%s router %s is created or mounted in another file; protection unknown", py.file, name)
	for _, s := range py.unresolved {
		if s == sentence {
			return
		}
	}
	py.unresolved = append(py.unresolved, sentence)
}
