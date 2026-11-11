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
	roleRe   = regexp.MustCompile(`(?i)(role|authority|adminonly|admin_only|admin-only)`)
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

	var routes []Route
	var unresolved []string
	for _, file := range files {
		fr := newFileResolver(file, byFile[file], root, gates)
		routes = append(routes, fr.resolveRoutes()...)
		unresolved = append(unresolved, fr.unknown...)
	}
	return routes, unresolved
}

// resolveRoutes resolves every route fact of one file.
func (fr *fileResolver) resolveRoutes() []Route {
	var out []Route
	for _, f := range fr.routes {
		route, err := fr.routeFromFact(f)
		if err != nil {
			fr.unknown = append(fr.unknown, fmt.Sprintf("%s:%d %v", fr.file, f.Line, err))
			continue
		}
		out = append(out, route)
	}
	return out
}

func (fr *fileResolver) routeFromFact(f Fact) (Route, error) {
	rawPath := f.Metavars["$PATH"]
	if !strings.HasPrefix(rawPath, "/") {
		return Route{}, fmt.Errorf("route path %q could not be resolved", rawPath)
	}
	receiver := f.Metavars["$R"]
	if receiver == "" {
		return Route{}, fmt.Errorf("route receiver could not be resolved")
	}
	state := fr.stateOfExpr(receiver, f.Line, 0)
	args := factArgs(f)
	if len(args) == 0 {
		if h := f.Metavars["$H"]; h != "" {
			args = []string{h}
		}
	}
	handler, middleware := splitHandlers(fr.framework, args)
	if handler == "" {
		return Route{}, fmt.Errorf("route handler could not be resolved")
	}
	routeMW := make([]mwRef, 0, len(middleware)+1)
	for _, expr := range middleware {
		routeMW = append(routeMW, mwRef{file: fr.file, line: f.Line, expr: expr})
	}
	// net/http handlers are often wrapped: mux.Handle("/x", authWrap(h)).
	if wrapped := handlerWrapper(handler); wrapped != "" {
		routeMW = append(routeMW, mwRef{file: fr.file, line: f.Line, expr: wrapped, place: "wraps the handler"})
	}
	protection, roles, evidence := decide(fr, f.Line, routeMW, state)
	confidence := "high"
	if protection == ProtUnknown {
		confidence = "low"
		fr.addUnknown(state.reason)
	}
	return Route{
		Service:    serviceOf(fr.root, fr.file),
		Framework:  fr.framework,
		Method:     methodOf(f),
		Path:       joinPaths(state.prefixes, rawPath),
		Handler:    handler,
		File:       fr.file,
		Line:       f.Line,
		Protection: protection,
		Roles:      roles,
		Evidence:   evidence,
		Confidence: confidence,
	}, nil
}

// splitHandlers reads the argument order of the framework. gin, chi and
// net/http put the handler last; echo and fiber put middleware after it.
func splitHandlers(framework string, args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	if framework == "echo" || framework == "fiber" {
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
func decide(fr *fileResolver, line int, routeMW []mwRef, state *routeState) (Protection, []string, []string) {
	chain := append([]mwRef{}, routeMW...)
	for i := len(state.mws) - 1; i >= 0; i-- {
		chain = append(chain, state.mws[i])
	}
	var evidence, roles []string
	authenticated, role := false, false
	for _, mw := range chain {
		if !fr.matcher.re.MatchString(mw.expr) {
			continue
		}
		authenticated = true
		evidence = append(evidence, evidenceLine(mw))
		if roleRe.MatchString(mw.expr) {
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
		evidence = append(evidence, fmt.Sprintf("%s:%d router %s is not created or mounted in this file", fr.file, line, state.reason))
		return ProtUnknown, nil, evidence
	}
	evidence = append(evidence, fmt.Sprintf("%s:%d no gate middleware on the route", fr.file, line))
	for _, mw := range chain {
		if !fr.matcher.re.MatchString(mw.expr) {
			evidence = append(evidence, evidenceLine(mw)+" (does not match the gate list)")
		}
	}
	return ProtPublic, nil, evidence
}

func evidenceLine(mw mwRef) string {
	if mw.place == "wraps the handler" {
		return fmt.Sprintf("%s:%d handler %s wraps the route handler", mw.file, mw.line, mw.expr)
	}
	if mw.place != "" {
		return fmt.Sprintf("%s:%d middleware %s %s", mw.file, mw.line, displayMW(mw.expr), mw.place)
	}
	return fmt.Sprintf("%s:%d middleware %s", mw.file, mw.line, displayMW(mw.expr))
}

// displayMW drops the parentheses of zero-argument middleware so evidence
// reads like the call a developer wrote (AuthMiddleware, not AuthMiddleware()).
func displayMW(expr string) string {
	expr = strings.TrimSpace(expr)
	if strings.HasSuffix(expr, "()") && !strings.Contains(expr[:len(expr)-2], "(") {
		return strings.TrimSuffix(expr, "()")
	}
	return expr
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
