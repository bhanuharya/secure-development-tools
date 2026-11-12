package endpoints

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// This file resolves Express and NestJS facts into routes (SPEC §5, JS
// bullet). Express mounts and router.use lines are same-file only; a router
// exported for another file stays unknown. NestJS guards are local to the
// class/method, and a service-wide APP_GUARD/useGlobalGuards makes an
// unguarded controller unknown instead of public.

// resolveJS sends each JavaScript/TypeScript file to the matching resolver.
// NestJS and Express never share a file: the controller fact decides.
// Frontend, test and asset files register calls too, but they are not a
// service's server routes (T15, SPEC §5).
func resolveJS(facts []Fact, root string, gates *gateMatcher) ([]Route, []string) {
	byFile := map[string][]Fact{}
	var files []string
	for _, f := range facts {
		if !isJSFile(f.File) {
			continue
		}
		if _, ok := byFile[f.File]; !ok {
			files = append(files, f.File)
		}
		byFile[f.File] = append(byFile[f.File], f)
	}
	sort.Strings(files)
	global := nestGlobalGuards(facts, root)

	var routes []Route
	var unresolved []string
	for _, file := range files {
		fileFacts := byFile[file]
		if jsFileExcluded(file) || hasFact(fileFacts, "frontend_import") {
			continue
		}
		js := newJSResolver(file, fileFacts, root, gates)
		fileRoutes, fileUnresolved := js.resolve(global)
		routes = append(routes, fileRoutes...)
		unresolved = append(unresolved, fileUnresolved...)
	}
	return routes, unresolved
}

// jsFileExcluded is the path half of the frontend/test skip; the fact rules
// see the imports. The engine also excludes these paths (factExcludes), so
// this keeps facts supplied by another caller honest.
func jsFileExcluded(file string) bool {
	if strings.HasSuffix(file, ".jsx") || strings.HasSuffix(file, ".tsx") {
		return true
	}
	slash := "/" + strings.TrimPrefix(file, "/")
	for _, dir := range []string{"/src/main/webapp/", "/public/", "/static/", "/test/", "/tests/", "/__tests__/"} {
		if strings.Contains(slash, dir) {
			return true
		}
	}
	base := slash[strings.LastIndex(slash, "/")+1:]
	return strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
}

func hasFact(facts []Fact, kind string) bool {
	for _, f := range facts {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func isJSFile(file string) bool {
	for _, ext := range []string{".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"} {
		if strings.HasSuffix(file, ext) {
			return true
		}
	}
	return false
}

// nestGlobalGuards marks the services that register a global guard anywhere,
// because those guards affect every controller of the service (SPEC §5).
func nestGlobalGuards(facts []Fact, root string) map[string]bool {
	global := map[string]bool{}
	for _, f := range facts {
		if f.Kind == "app_guard" && isJSFile(f.File) {
			global[serviceOf(root, f.File)] = true
		}
	}
	return global
}

// jsFactValue is a decorator or middleware registration: its line and the
// expressions it names (guard classes, role names, middleware arguments).
type jsFactValue struct {
	line   int
	values []string
}

type jsUse struct {
	receiver string
	args     []string
	line     int
}

// jsMount is app.use("/prefix", mw..., router): the prefix and middleware an
// application adds to a router created in the same file.
type jsMount struct {
	receiver string
	prefix   string
	mws      []string
	line     int
}

// jsState is what a router variable carries at a line: prefixes from its
// mounts and the middleware registered before the line.
type jsState struct {
	prefixes []string
	mws      []mwRef
	unknown  bool
	reason   string
	exported bool // a known router variable, so the sentence can say "exported"
}

type jsResolver struct {
	file, root  string
	matcher     *gateMatcher
	engines     map[string]bool
	routers     map[string]bool
	routerCalls map[string]bool
	uses        []jsUse
	routes      []Fact
	nest        bool

	expressImport bool

	controllers  map[string]string
	classGates   map[string][]jsFactValue
	methodGates  map[string][]jsFactValue
	classRoles   map[string][]jsFactValue
	methodRoles  map[string][]jsFactValue
	classPublic  map[string]int
	methodPublic map[string]int

	unresolved []string
}

func newJSResolver(file string, facts []Fact, root string, gates *gateMatcher) *jsResolver {
	js := &jsResolver{
		file: file, root: root, matcher: gates,
		engines: map[string]bool{}, routers: map[string]bool{}, routerCalls: map[string]bool{},
		controllers:  map[string]string{},
		classGates:   map[string][]jsFactValue{},
		methodGates:  map[string][]jsFactValue{},
		classRoles:   map[string][]jsFactValue{},
		methodRoles:  map[string][]jsFactValue{},
		classPublic:  map[string]int{},
		methodPublic: map[string]int{},
	}
	for _, f := range facts {
		switch f.Kind {
		case "express_import":
			js.expressImport = true
		case "engine":
			js.engines[f.Metavars["$R"]] = true
		case "router":
			js.routers[f.Metavars["$R"]] = true
		case "router_fn":
			js.routerCalls[f.Metavars["$R"]] = true
		case "use":
			js.uses = append(js.uses, jsUse{receiver: f.Metavars["$R"], args: factArgs(f), line: f.Line})
		case "route":
			js.routes = append(js.routes, f)
		case "controller":
			js.nest = true
			js.controllers[f.Metavars["$C"]] = f.Metavars["$PREFIX"]
		case "class_guard":
			js.nest = true
			js.classGates[f.Metavars["$C"]] = append(js.classGates[f.Metavars["$C"]], jsFactValue{line: f.Line, values: factList(f, "$G")})
		case "method_guard":
			js.nest = true
			key := jsMethodKey(f)
			js.methodGates[key] = append(js.methodGates[key], jsFactValue{line: f.Line, values: factList(f, "$G")})
		case "class_roles":
			js.nest = true
			js.classRoles[f.Metavars["$C"]] = append(js.classRoles[f.Metavars["$C"]], jsFactValue{line: f.Line, values: factList(f, "$R")})
		case "method_roles":
			js.nest = true
			key := jsMethodKey(f)
			js.methodRoles[key] = append(js.methodRoles[key], jsFactValue{line: f.Line, values: factList(f, "$R")})
		case "class_public":
			js.nest = true
			js.classPublic[f.Metavars["$C"]] = f.Line
		case "method_public":
			js.nest = true
			js.methodPublic[jsMethodKey(f)] = f.Line
		}
	}
	if js.expressImport {
		for name := range js.routerCalls {
			js.routers[name] = true
		}
	}
	sort.Slice(js.routes, func(i, j int) bool { return js.routes[i].Line < js.routes[j].Line })
	return js
}

func jsMethodKey(f Fact) string {
	return f.Metavars["$C"] + "." + f.Metavars["$M"]
}

// factList reads $PREFIX1..$PREFIX5 in order; guards and roles use two slots.
func factList(f Fact, prefix string) []string {
	var out []string
	for i := 1; i <= 5; i++ {
		v := f.Metavars[fmt.Sprintf("%s%d", prefix, i)]
		if v == "" {
			break
		}
		out = append(out, v)
	}
	return out
}

func (js *jsResolver) resolve(global map[string]bool) ([]Route, []string) {
	if js.nest {
		return js.resolveNest(global[serviceOf(js.root, js.file)])
	}
	return js.resolveExpress()
}

// resolveExpress turns every route fact of a server receiver into a route. A
// router that is not created or mounted in this file yields unknown plus an
// Unresolved sentence. Client calls in the same file are dropped silently.
func (js *jsResolver) resolveExpress() ([]Route, []string) {
	var routes []Route
	for _, f := range js.routes {
		if !js.serverReceiver(f.Metavars["$R"]) {
			continue
		}
		route, err := js.expressRoute(f)
		if err != nil {
			js.unresolved = append(js.unresolved, fmt.Sprintf("%s:%d %v", js.file, f.Line, err))
			continue
		}
		routes = append(routes, route)
	}
	return routes, js.unresolved
}

// jsClientReceivers are HTTP clients, not servers: their .get/.post calls
// look exactly like Express routes to a single-file rule.
var jsClientReceivers = map[string]bool{
	"axios": true, "http": true, "https": true, "request": true,
	"supertest": true, "superagent": true, "got": true, "fetch": true,
	"ky": true, "needle": true, "$fetch": true,
}

// serverReceiver keeps a route only when the receiver looks like an Express
// application or router: created here, imported here, a conventional name, or
// ending in Router. Everything else (axios, http, request(app), ...) is a
// client and is dropped, not reported unknown.
func (js *jsResolver) serverReceiver(receiver string) bool {
	base := jsReceiverBase(receiver)
	if jsClientReceivers[strings.ToLower(base)] {
		return false
	}
	if js.engines[receiver] || js.routers[receiver] {
		return true
	}
	if js.expressImport {
		return true
	}
	switch base {
	case "app", "router", "routes", "api", "server":
		return true
	}
	return strings.HasSuffix(base, "Router")
}

// jsReceiverBase reduces `this.router`, `request(app)` or `express.Router()`
// to the name a developer would call the variable.
func jsReceiverBase(receiver string) string {
	base := strings.TrimSpace(receiver)
	if i := strings.Index(base, "("); i >= 0 {
		base = base[:i]
	}
	if i := strings.LastIndex(base, "."); i >= 0 {
		base = base[i+1:]
	}
	return strings.TrimSpace(base)
}

func (js *jsResolver) expressRoute(f Fact) (Route, error) {
	rawPath, err := js.routePath(f)
	if err != nil {
		return Route{}, err
	}
	receiver := f.Metavars["$R"]
	args := routeArgs(f, js.root, 1)
	if len(args) == 0 {
		return Route{}, fmt.Errorf("route handler could not be resolved")
	}
	handler := args[len(args)-1]
	state := js.stateOf(receiver, f.Line, 0)
	routeMW := make([]mwRef, 0, len(args)-1)
	for _, expr := range args[:len(args)-1] {
		routeMW = append(routeMW, mwRef{file: js.file, line: f.Line, expr: expr})
	}
	protection, roles, evidence := js.decide(f.Line, routeMW, state)
	confidence := "high"
	if protection == ProtUnknown {
		confidence = "low"
		js.addUnknown(state)
	}
	return Route{
		Service:    serviceOf(js.root, js.file),
		Framework:  "express",
		Method:     methodOf(f),
		Path:       joinPaths(state.prefixes, rawPath),
		Handler:    handler,
		File:       js.file,
		Line:       f.Line,
		Protection: protection,
		Roles:      roles,
		Evidence:   evidence,
		Confidence: confidence,
	}, nil
}

// stateOf resolves a router variable at a line: the mounts that reach it, then
// its own use() calls registered before the line.
func (js *jsResolver) stateOf(name string, line, depth int) *jsState {
	name = strings.TrimSpace(name)
	if depth > 8 {
		return &jsState{unknown: true, reason: receiverName(name)}
	}
	mounts := js.mountsFor(name)
	if len(mounts) == 0 && !js.engines[name] {
		return &jsState{unknown: true, reason: receiverName(name), exported: js.routers[name]}
	}
	state, ok := js.mountState(mounts, depth)
	if !ok {
		return &jsState{unknown: true, reason: receiverName(name)}
	}
	place := "on router"
	if js.engines[name] {
		place = "on app"
	}
	for _, u := range js.uses {
		if u.receiver != name || u.line >= line || js.classifyUse(u) != "middleware" {
			continue
		}
		for _, expr := range u.args {
			state.mws = append(state.mws, mwRef{file: js.file, line: u.line, expr: expr, place: place})
		}
	}
	return state
}

// mountsFor returns the mount calls that target the router: the router being
// mounted is the last argument, not the receiver.
func (js *jsResolver) mountsFor(name string) []jsMount {
	var out []jsMount
	for _, u := range js.uses {
		if js.classifyUse(u) != "mount" || u.args[len(u.args)-1] != name {
			continue
		}
		out = append(out, js.mountOf(u))
	}
	return out
}

// mountState combines every mount that reaches the router. More than one mount
// with the same chain (the usual case) is fine; differing chains are unknown.
func (js *jsResolver) mountState(mounts []jsMount, depth int) (*jsState, bool) {
	var merged *jsState
	for _, m := range mounts {
		base := js.stateOf(m.receiver, m.line, depth+1)
		if base.unknown {
			return nil, false
		}
		next := &jsState{prefixes: append([]string{}, base.prefixes...), mws: append([]mwRef{}, base.mws...)}
		if m.prefix != "" {
			next.prefixes = append(next.prefixes, m.prefix)
		}
		place := "on mount " + m.prefix
		if m.prefix == "" {
			place = "on mount"
		}
		for _, expr := range m.mws {
			next.mws = append(next.mws, mwRef{file: js.file, line: m.line, expr: expr, place: place})
		}
		if merged == nil {
			merged = next
		} else if !sameJSState(merged, next) {
			return nil, false
		}
	}
	if merged == nil {
		merged = &jsState{}
	}
	return merged, true
}

func sameJSState(a, b *jsState) bool {
	if strings.Join(a.prefixes, "|") != strings.Join(b.prefixes, "|") || len(a.mws) != len(b.mws) {
		return false
	}
	for i := range a.mws {
		if a.mws[i].expr != b.mws[i].expr || a.mws[i].line != b.mws[i].line {
			return false
		}
	}
	return true
}

// classifyUse tells the three .use() forms apart: a same-file router mount (the
// last argument is a known router, with or without a path), a global/router
// middleware registration, or a prefixed middleware we do not model.
func (js *jsResolver) classifyUse(u jsUse) string {
	if len(u.args) == 0 {
		return ""
	}
	last := u.args[len(u.args)-1]
	if js.routers[last] || js.engines[last] {
		return "mount"
	}
	if isPathExpr(u.args[0]) {
		return "prefixed"
	}
	return "middleware"
}

func (js *jsResolver) mountOf(u jsUse) jsMount {
	m := jsMount{receiver: u.receiver, line: u.line}
	if len(u.args) < 2 {
		return m
	}
	first := 0
	if isPathExpr(u.args[0]) {
		m.prefix = unquote(u.args[0])
		first = 1
	}
	m.mws = u.args[first : len(u.args)-1]
	return m
}

func isPathExpr(expr string) bool {
	return strings.HasPrefix(unquote(expr), "/")
}

// decide evaluates route middleware, then the router/mount chain innermost
// first, exactly like the Go resolver reads a group chain.
func (js *jsResolver) decide(line int, routeMW []mwRef, state *jsState) (Protection, []string, []string) {
	chain := append([]mwRef{}, routeMW...)
	for i := len(state.mws) - 1; i >= 0; i-- {
		chain = append(chain, state.mws[i])
	}
	var evidence, roles []string
	authenticated, role := false, false
	for _, mw := range chain {
		name := callableName(mw.expr)
		if !js.matcher.re.MatchString(name) {
			continue
		}
		authenticated = true
		evidence = append(evidence, evidenceLine(mw))
		if roleRe.MatchString(name) {
			role = true
			roles = append(roles, roleNames(mw.expr)...)
		}
	}
	if role {
		return ProtRole, dedupe(roles), evidence
	}
	if authenticated {
		return ProtAuthenticated, nil, evidence
	}
	if state.unknown {
		evidence = append(evidence, fmt.Sprintf("%s:%d router %s is not mounted in this file", js.file, line, state.reason))
		return ProtUnknown, nil, evidence
	}
	evidence = append(evidence, fmt.Sprintf("%s:%d no gate middleware on the route", js.file, line))
	for _, mw := range chain {
		if !js.matcher.re.MatchString(callableName(mw.expr)) {
			evidence = append(evidence, evidenceLine(mw)+" (does not match the gate list)")
		}
	}
	return ProtPublic, nil, evidence
}

func (js *jsResolver) addUnknown(state *jsState) {
	name := state.reason
	if name == "" {
		name = "router"
	}
	sentence := fmt.Sprintf("%s router %s is created or mounted in another file; protection unknown", js.file, name)
	if state.exported {
		sentence = fmt.Sprintf("%s router %s is exported and mounted in another file; protection unknown", js.file, name)
	}
	for _, s := range js.unresolved {
		if s == sentence {
			return
		}
	}
	js.unresolved = append(js.unresolved, sentence)
}

// resolveNest builds one route per controller method decorator.
func (js *jsResolver) resolveNest(global bool) ([]Route, []string) {
	var routes []Route
	for _, f := range js.routes {
		route, sentence, err := js.nestRoute(f, global)
		if err != nil {
			js.unresolved = append(js.unresolved, fmt.Sprintf("%s:%d %v", js.file, f.Line, err))
			continue
		}
		routes = append(routes, route)
		if sentence != "" {
			js.unresolved = append(js.unresolved, sentence)
		}
	}
	return routes, js.unresolved
}

func (js *jsResolver) nestRoute(f Fact, global bool) (Route, string, error) {
	class, method := f.Metavars["$C"], f.Metavars["$M"]
	if class == "" || method == "" {
		return Route{}, "", fmt.Errorf("controller class or method could not be resolved")
	}
	protection, roles, evidence, sentence := js.nestProtection(class, method, f.Line, global)
	return Route{
		Service:    serviceOf(js.root, js.file),
		Framework:  "nestjs",
		Method:     methodOf(f),
		Path:       joinPaths([]string{js.controllers[class]}, f.Metavars["$PATH"]),
		Handler:    class + "." + method,
		File:       js.file,
		Line:       f.Line,
		Protection: protection,
		Roles:      roles,
		Evidence:   evidence,
		Confidence: nestConfidence(protection),
	}, sentence, nil
}

func nestConfidence(protection Protection) string {
	if protection == ProtUnknown {
		return "low"
	}
	return "high"
}

// nestProtection applies a method guard first, then the class guard, then the
// service-wide global guard. @Public on either level wins: it exists to open a
// route under a global guard.
func (js *jsResolver) nestProtection(class, method string, line int, global bool) (Protection, []string, []string, string) {
	key := class + "." + method
	if publicLine, ok := js.methodPublic[key]; ok {
		return ProtPublic, nil, []string{fmt.Sprintf("%s:%d @Public() on method %s", js.file, publicLine, method)}, ""
	}
	if publicLine, ok := js.classPublic[class]; ok {
		return ProtPublic, nil, []string{fmt.Sprintf("%s:%d @Public() on class %s", js.file, publicLine, class)}, ""
	}
	gates, scope, owner := js.methodGates[key], "method", method
	if len(gates) == 0 {
		gates, scope, owner = js.classGates[class], "class", class
	}
	if len(gates) > 0 {
		roles, roleEvidence := js.rolesFor(class, key)
		evidence := guardEvidence(js.file, gates, scope, owner)
		evidence = append(evidence, roleEvidence...)
		if len(roles) > 0 {
			return ProtRole, roles, evidence, ""
		}
		return ProtAuthenticated, nil, evidence, ""
	}
	if global {
		evidence := fmt.Sprintf("%s:%d no local guard; the service registers a global guard", js.file, line)
		sentence := fmt.Sprintf("%s:%d %s: only a global guard could protect this route; protection unknown", js.file, line, key)
		return ProtUnknown, nil, []string{evidence}, sentence
	}
	evidence := fmt.Sprintf("%s:%d no guard on the controller and no global guard in the service", js.file, line)
	return ProtPublic, nil, []string{evidence}, ""
}

// rolesFor prefers method roles over class roles, like the guards do.
func (js *jsResolver) rolesFor(class, key string) ([]string, []string) {
	roles, scope, owner := js.methodRoles[key], "method", key[strings.LastIndex(key, ".")+1:]
	if len(roles) == 0 {
		roles, scope, owner = js.classRoles[class], "class", class
	}
	var names, evidence []string
	for _, r := range roles {
		names = append(names, r.values...)
		evidence = append(evidence, fmt.Sprintf("%s:%d @Roles(%s) on %s %s", js.file, r.line, quoteList(r.values), scope, owner))
	}
	return dedupe(names), evidence
}

func guardEvidence(file string, gates []jsFactValue, scope, owner string) []string {
	var out []string
	for _, g := range gates {
		out = append(out, fmt.Sprintf("%s:%d @UseGuards(%s) on %s %s", file, g.line, strings.Join(g.values, ", "), scope, owner))
	}
	return out
}

func quoteList(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = strconv.Quote(v)
	}
	return strings.Join(quoted, ", ")
}
