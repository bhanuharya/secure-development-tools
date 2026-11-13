package endpoints

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Role list from SPEC §5; the gate list lives in gates.go.
var (
	// A gate whose callable name says it checks a role or a permission is a
	// role gate; the arguments need not be readable (T29).
	roleRe   = regexp.MustCompile(`(?i)(role|authority|adminonly|admin_only|admin-only|permission|rbac|acl|authorize)`)
	quotedRe = regexp.MustCompile(`"([^"]+)"`)
	colonRe  = regexp.MustCompile(`(^|/):([A-Za-z_][A-Za-z0-9_]*)`)
	angleRe  = regexp.MustCompile(`<[^>]*>`)
	slashRe  = regexp.MustCompile(`/{2,}`)
)

// resolveFacts sends each fact file to the resolver for its language. Facts
// are always resolved per file, so one dispatcher keeps both families apart.
func resolveFacts(facts []Fact, root string, gates *gateMatcher) ([]Route, []string) {
	goRoutes, goUnresolved := resolveGo(facts, root, gates)
	springRoutes, springUnresolved := resolveSpring(facts, root)
	jsRoutes, jsUnresolved := resolveJS(facts, root, gates)
	pyRoutes, pyUnresolved := resolvePython(facts, root, gates)
	routes := append(append(append(goRoutes, springRoutes...), jsRoutes...), pyRoutes...)
	return routes, append(append(append(goUnresolved, springUnresolved...), jsUnresolved...), pyUnresolved...)
}

// resolveGo turns Go route facts into routes. Groups, Use and the same-file
// scope model live in resolve_go_scope.go; this file interprets each
// framework's argument order and decides protection.
func resolveGo(facts []Fact, root string, gates *gateMatcher) ([]Route, []string) {
	byFile := map[string][]Fact{}
	for _, f := range facts {
		if !strings.HasSuffix(f.File, ".go") {
			continue // Java and Python facts belong to their own resolvers
		}
		byFile[f.File] = append(byFile[f.File], f)
	}
	files := make([]string, 0, len(byFile))
	for file := range byFile {
		files = append(files, file)
	}
	sort.Strings(files)

	// Every fact file is indexed before any route is resolved: a router
	// parameter's caller may be in a file that sorts after it.
	project := newGoProject(root, gates)
	resolvers := make([]*fileResolver, 0, len(files))
	for _, file := range files {
		fr := newFileResolver(file, byFile[file], root, gates)
		project.add(fr)
		resolvers = append(resolvers, fr)
	}
	var routes []Route
	var unresolved []string
	for _, fr := range resolvers {
		routes = append(routes, fr.resolveRoutes()...)
		unresolved = append(unresolved, fr.unknown...)
	}
	return routes, unresolved
}

// resolveRoutes resolves every route fact of one file.
func (fr *fileResolver) resolveRoutes() []Route {
	var out []Route
	for _, f := range fr.routes {
		routes, err := fr.routeFromFact(f)
		if err != nil {
			fr.unknown = append(fr.unknown, fmt.Sprintf("%s:%d %v", fr.file, f.Line, err))
			continue
		}
		out = append(out, routes...)
	}
	return out
}

// routeFromFact resolves one registration. A function called from several
// places with different routers registers its routes once per caller, so one
// fact can give several routes, one per distinct prefix.
func (fr *fileResolver) routeFromFact(f Fact) ([]Route, error) {
	rawPath := f.Metavars["$PATH"]
	if !strings.HasPrefix(rawPath, "/") {
		return nil, fmt.Errorf("route path %q could not be resolved", rawPath)
	}
	receiver := f.Metavars["$R"]
	if receiver == "" {
		return nil, fmt.Errorf("route receiver could not be resolved")
	}
	lead := 1
	if f.Metavars["$VERB"] != "" {
		lead = 2 // Handle(verb, path, handler...)
	}
	args := routeArgs(f, fr.root, lead)
	if len(args) == 0 {
		if h := f.Metavars["$H"]; h != "" {
			args = []string{h}
		}
	}
	handler, middleware := splitHandlers(fr.framework, args)
	if handler == "" {
		return nil, fmt.Errorf("route handler could not be resolved")
	}
	routeMW := make([]mwRef, 0, len(middleware)+1)
	for _, expr := range middleware {
		routeMW = append(routeMW, mwRef{file: fr.file, line: f.Line, expr: fr.mwExpr(expr, f.Line)})
	}
	// net/http handlers are often wrapped: mux.Handle("/x", authWrap(h)).
	if wrapped := handlerWrapper(handler); wrapped != "" {
		routeMW = append(routeMW, mwRef{file: fr.file, line: f.Line, expr: wrapped, place: "wraps the handler"})
	}
	var routes []Route
	for _, state := range fr.statesOf(receiver, f.Line, rawPath) {
		path := joinPaths(state.prefixes, rawPath)
		protection, roles, evidence := decide(fr, f.Line, path, routeMW, state)
		confidence := "high"
		if protection == ProtUnknown {
			confidence = "low"
			fr.addUnknown(state)
		}
		routes = append(routes, Route{
			Service:    serviceOf(fr.root, fr.file),
			Framework:  fr.framework,
			Method:     methodOf(f),
			Path:       path,
			Handler:    handler,
			File:       fr.file,
			Line:       f.Line,
			Protection: protection,
			Roles:      roles,
			Evidence:   evidence,
			Confidence: confidence,
		})
	}
	return routes, nil
}

// maxCallerStates bounds the routes one registration can give; past it the
// route stays unknown rather than multiply.
const maxCallerStates = 16

// statesOf resolves a receiver once per combination of callers that pass
// different routers into the functions on its way. Without such a function it
// is stateOfExpr. Combinations that end on the same path with different
// middleware give one unknown state for that path.
func (fr *fileResolver) statesOf(receiver string, line int, rawPath string) []*routeState {
	p := fr.project
	if p == nil {
		return []*routeState{fr.stateOfExpr(receiver, line, 0)}
	}
	var found []*routeState
	var first *routeState
	overflow := false
	var walk func(forced map[string]int)
	walk = func(forced map[string]int) {
		if overflow {
			return
		}
		p.forced, p.pending = forced, map[string]int{}
		state := fr.stateOfExpr(receiver, line, 0)
		pending := p.pending
		if first == nil {
			first = state
		}
		var keys []string
		for key := range pending {
			if _, done := forced[key]; !done {
				keys = append(keys, key)
			}
		}
		if len(keys) == 0 {
			if len(found) >= maxCallerStates {
				overflow = true
				return
			}
			found = append(found, state)
			return
		}
		sort.Strings(keys)
		for i := 0; i < pending[keys[0]]; i++ {
			next := map[string]int{keys[0]: i}
			for k, v := range forced {
				next[k] = v
			}
			walk(next)
		}
	}
	walk(map[string]int{})
	p.forced, p.pending = nil, nil
	if overflow || len(found) == 0 {
		return []*routeState{first}
	}
	// One state per path: the same path reached with different middleware
	// cannot be decided.
	var out []*routeState
	byPath := map[string]int{}
	for _, state := range found {
		path := joinPaths(state.prefixes, rawPath)
		i, seen := byPath[path]
		if !seen {
			byPath[path] = len(out)
			out = append(out, state)
			continue
		}
		if !out[i].unknown && !sameState(out[i], state) {
			out[i] = &routeState{unknown: true, reason: first.reason, why: first.why, fn: first.fn, prefixes: state.prefixes}
		}
	}
	return out
}

// splitHandlers reads the argument order of the framework. gin, fiber, chi and
// net/http put the handler last; echo puts it first and middleware after it.
func splitHandlers(framework string, args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	if framework == "echo" {
		return args[0], args[1:]
	}
	return args[len(args)-1], args[:len(args)-1]
}

func methodOf(f Fact) string {
	if verb := f.Metavars["$VERB"]; verb != "" {
		return normalizeMethod(unquote(verb))
	}
	if method := f.Metavars["$METHOD"]; method != "" {
		return normalizeMethod(method)
	}
	return "ANY" // Handle(path, h) / HandleFunc(path, h) accept every method
}

func normalizeMethod(method string) string {
	name := strings.TrimSpace(method)
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:] // http.MethodGet and friends
	}
	name = strings.TrimPrefix(strings.ToLower(name), "method")
	switch name {
	case "get":
		return "GET"
	case "post":
		return "POST"
	case "put":
		return "PUT"
	case "patch":
		return "PATCH"
	case "delete":
		return "DELETE"
	case "any", "all":
		return "ANY"
	default:
		return strings.ToUpper(strings.TrimSpace(method))
	}
}

// decide evaluates the middleware chain. Route-level middleware comes first,
// then the nearest group, then the engine (most specific first, as evidence).
// A path-scoped Use entry applies only to routes under its prefix.
func decide(fr *fileResolver, line int, routePath string, routeMW []mwRef, state *routeState) (Protection, []string, []string) {
	chain := append([]mwRef{}, routeMW...)
	for i := len(state.mws) - 1; i >= 0; i-- {
		chain = append(chain, state.mws[i])
	}
	var evidence, roles []string
	authenticated, role := false, false
	for _, mw := range chain {
		if !prefixApplies(mw.prefix, routePath) {
			continue
		}
		name := callableName(mw.expr)
		if !fr.matcher.re.MatchString(name) {
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
		evidence = append(evidence, fmt.Sprintf("%s:%d %s", fr.file, line, state.unknownEvidence()))
		return ProtUnknown, nil, evidence
	}
	evidence = append(evidence, fmt.Sprintf("%s:%d no gate middleware on the route", fr.file, line))
	for _, mw := range chain {
		if !prefixApplies(mw.prefix, routePath) {
			continue
		}
		if !fr.matcher.re.MatchString(callableName(mw.expr)) {
			evidence = append(evidence, evidenceLine(mw)+" (does not match the gate list)")
		}
	}
	return ProtPublic, nil, evidence
}

// unknownEvidence says why a router's protection is unknown.
func (s *routeState) unknownEvidence() string {
	switch s.why {
	case goNoCaller:
		return fmt.Sprintf("router %s is a parameter of %s, and no call to %s was found", s.reason, s.fn, s.fn)
	case goCallersDiffer:
		return fmt.Sprintf("router %s: the calls to %s pass routers with different prefixes or middleware", s.reason, s.fn)
	case goNoField:
		return fmt.Sprintf("router field %s is never assigned in its package", s.reason)
	case goFieldsDiffer:
		return fmt.Sprintf("router field %s is assigned routers with different prefixes or middleware", s.reason)
	}
	return fmt.Sprintf("router %s is not created where this scan can follow it", s.reason)
}

func evidenceLine(mw mwRef) string {
	if mw.place == wrapsRouter {
		return fmt.Sprintf("%s:%d router built by %s wraps the group", mw.file, mw.line, omitCallArguments(mw.expr))
	}
	if mw.place == "wraps the handler" {
		return fmt.Sprintf("%s:%d handler %s wraps the route handler", mw.file, mw.line, omitCallArguments(mw.expr))
	}
	if mw.place != "" {
		return fmt.Sprintf("%s:%d middleware %s %s", mw.file, mw.line, omitCallArguments(displayMW(mw.expr)), mw.place)
	}
	return fmt.Sprintf("%s:%d middleware %s", mw.file, mw.line, omitCallArguments(displayMW(mw.expr)))
}

// displayMW drops the parentheses of zero-argument middleware so evidence
// reads like the call a developer wrote (AuthMiddleware, not AuthMiddleware()).
func displayMW(expr string) string {
	expr = strings.TrimSpace(expr)
	if inlineFunction(expr) {
		return "inline function"
	}
	if strings.HasSuffix(expr, "()") && !strings.Contains(expr[:len(expr)-2], "(") {
		return strings.TrimSuffix(expr, "()")
	}
	return expr
}

// inlineFunctionRe matches a function literal written in place of a named
// middleware: (req, res, next) => {...}, req => ..., function (req) {...},
// async (...) => ..., func(c *gin.Context) {...}. Its body is code, not a name.
var inlineFunctionRe = regexp.MustCompile(`^(?:async\s+)?(?:function\b|func\s*\(|\([^()]*\)\s*(?::[^=]*)?=>|[A-Za-z_$][\w$]*\s*=>)`)

func inlineFunction(expr string) bool {
	return inlineFunctionRe.MatchString(expr)
}

func roleNames(expr string) []string {
	var roles []string
	for _, m := range quotedRe.FindAllStringSubmatch(expr, -1) {
		roles = append(roles, m[1])
	}
	if len(roles) == 0 && strings.Contains(strings.ToLower(expr), "admin") {
		roles = append(roles, "admin")
	}
	return roles
}

// handlerWrapper returns a plain call expression used as the handler, so its
// name can be checked against the gate list.
func handlerWrapper(handler string) string {
	handler = strings.TrimSpace(handler)
	open := strings.Index(handler, "(")
	if open <= 0 || !strings.HasSuffix(handler, ")") {
		return ""
	}
	for _, r := range handler[:open] {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return ""
		}
	}
	return handler
}

// joinPaths joins group prefixes and the route path with exactly one slash.
func joinPaths(prefixes []string, routePath string) string {
	out := ""
	parts := append(append([]string{}, prefixes...), routePath)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "/" {
			continue
		}
		out = strings.TrimRight(out, "/") + "/" + strings.Trim(part, "/")
	}
	if out == "" {
		out = "/"
	}
	return normalizePath(out)
}

// normalizePath applies SPEC §4: one slash between parts; `:id`, `{id}` and
// `<int:id>` all become `{id}`; no trailing slash except for "/".
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = colonRe.ReplaceAllString(p, "$1{$2}")
	p = angleRe.ReplaceAllStringFunc(p, func(m string) string {
		name := strings.Trim(m, "<>")
		if i := strings.LastIndex(name, ":"); i >= 0 {
			name = name[i+1:]
		}
		return "{" + name + "}"
	})
	p = slashRe.ReplaceAllString(p, "/")
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// serviceOf returns the directory of the nearest module file at or above the
// file, relative to the scanned root ("." for the root service).
func serviceOf(root, file string) string {
	markers := []string{"go.mod", "package.json", "pom.xml", "build.gradle", "build.gradle.kts", "pyproject.toml"}
	dir := filepath.Dir(file)
	for {
		for _, marker := range markers {
			if _, err := os.Stat(filepath.Join(root, dir, marker)); err == nil {
				dir = filepath.ToSlash(filepath.Clean(dir))
				if dir == "" {
					return "."
				}
				return dir
			}
		}
		if dir == "." || dir == "" || dir == string(filepath.Separator) {
			return "."
		}
		dir = filepath.Dir(dir)
	}
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
