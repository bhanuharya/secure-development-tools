package endpoints

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// This file is the scope model behind resolve_go.go. Facts say what is
// registered where; this model says which group/router a receiver refers to at
// that line. A router parameter is followed to its callers, in the same file
// or elsewhere in the service (resolve_go_project.go); a router no caller
// reaches stays unknown.

// mwRef is one middleware expression on a route's chain. prefix is set for a
// Fiber Use("/x", mw): the entry only applies under that path.
type mwRef struct {
	file   string
	line   int
	expr   string
	place  string // "", "on router", "on group /api", "wraps the handler"
	prefix string // "" means global
}

// routeState is a resolved group/router: the prefixes it adds and the
// middleware inherited from its creation up to a given line.
type routeState struct {
	prefixes []string
	mws      []mwRef
	unknown  bool
	reason   string // the receiver name, for the Unresolved sentence
	why      string // goNoCaller or goCallersDiffer for a parameter; "" otherwise
	fn       string // the function whose parameter it is
}

const (
	goNoCaller      = "no caller"
	goCallersDiffer = "callers differ"
	// wrapsRouter marks a wrapper constructor (x := NewRoleRouter(group, ...)).
	wrapsRouter = "wraps the router"
)

// groupNode is a group assignment. It is evaluated lazily because its base may
// itself be a group whose Use calls are only known once the whole file is read.
type groupNode struct {
	baseName string
	baseLine int
	prefix   string
	mws      []mwRef
}

// binding binds a name to a group for a line range. Group variables live to
// the end of the file; chi.Route closure parameters live inside the closure.
type binding struct {
	name  string
	start int
	end   int // math.MaxInt for file-wide bindings
	node  *groupNode
	chi   *Fact // a chi.Route/Group closure parameter, resolved when first needed
	// resolving is set while the closure's base is read: the parameter
	// usually shadows the router it comes from (r.Route("/x", func(r chi.Router)).
	resolving bool
}

type paramRef struct {
	name string
	typ  string
}

type funcScope struct {
	name   string
	start  int
	end    int
	params []paramRef
	method bool // declared with a receiver: called as x.name(...)
	// recvName and recvType name a method's receiver (a, RestAPI for
	// func (a *RestAPI) ...). delegates are the receiver's fields the body
	// calls a method on: a.Router.Get(path, h) delegates to Router.
	recvName  string
	recvType  string
	delegates []string
}

// goFieldSet stores a router in a struct field: a.Router = app inside a method
// of the type (recvVar a), or T{Router: app} (typ T).
type goFieldSet struct {
	typ     string
	recvVar string
	field   string
	expr    string
	line    int
}

// callSite is a call to fn, qualified by qual for pkg.Fn(...) or x.Method(...).
type callSite struct {
	fn   string
	qual string
	args []string
	line int
}

// goWrapper is `name := callee(base, ...)` or `var name = callee(base, ...)`:
// a value built from another expression, such as a router type that wraps a
// group and adds its own checks.
type goWrapper struct {
	name   string
	line   int
	callee string
	base   string // first argument; "" for a call without arguments
	value  string // the whole call
}

// goSyntax is what the Go parser reads from one file beyond the facts.
type goSyntax struct {
	pkg      string
	imports  map[string]string // local name ("" for none) -> import path
	funcs    []funcScope
	calls    []callSite
	scopes   []lineScope
	wrappers []goWrapper
	fields   []goFieldSet
}

// lineScope is the source range of a lexical block: a function body, a closure
// or a plain { ... } block. Bindings made inside one are not visible to
// another (T23 lexical scope, T31 block scope).
type lineScope struct {
	start int
	end   int
}

type fileResolver struct {
	file      string
	root      string
	framework string
	matcher   *gateMatcher
	engines   []Fact
	groups    []Fact
	chis      []Fact
	uses      []Fact
	routes    []Fact
	bindings  []binding
	funcs     []funcScope
	calls     []callSite
	scopes    []lineScope
	unknown   []string
	pkg       string
	imports   map[string]string
	wrappers  []goWrapper
	fields    []goFieldSet
	project   *goProject
}

var routerParamRe = regexp.MustCompile(`(?i)(gin\.(RouterGroup|Engine|IRouter|IRoutes)|echo\.(Group|Echo)|fiber\.(Router|App)|chi\.(Router|Mux)|http\.ServeMux)`)

// newFileResolver indexes one file's facts and its Go syntax (functions and
// calls) for same-file scope resolution.
func newFileResolver(file string, facts []Fact, root string, gates *gateMatcher) *fileResolver {
	fr := &fileResolver{file: file, root: root, matcher: gates}
	var imports []string
	for _, f := range facts {
		switch f.Kind {
		case "import":
			imports = append(imports, f.Metavars["$IMPORT"])
		case "engine":
			fr.engines = append(fr.engines, f)
		case "group":
			fr.groups = append(fr.groups, f)
		case "chi_route":
			fr.chis = append(fr.chis, f)
		case "use":
			fr.uses = append(fr.uses, f)
		case "route":
			fr.routes = append(fr.routes, f)
		}
	}
	fr.framework = frameworkFor(imports)
	syn := parseGoScope(filepath.Join(root, file))
	fr.funcs, fr.calls, fr.scopes = syn.funcs, syn.calls, syn.scopes
	fr.pkg, fr.imports, fr.wrappers = syn.pkg, syn.imports, syn.wrappers
	fr.fields = typedFieldSets(syn.fields, syn.funcs)
	fr.addEngineBindings()
	fr.addGroupBindings()
	fr.addChiBindings()
	return fr
}

// addEngineBindings binds each router constructor to the function or closure
// that declares it, so two functions with their own `r := gin.New()` never
// share Use calls.
func (fr *fileResolver) addEngineBindings() {
	seen := map[string]bool{}
	for _, f := range fr.engines {
		name := f.Metavars["$R"]
		key := fmt.Sprintf("%s:%d", name, f.Line)
		if name == "" || seen[key] {
			continue
		}
		seen[key] = true
		start, end := fr.declRange(f.Line)
		fr.bindings = append(fr.bindings, binding{name: name, start: start, end: end})
	}
}

// declRange is the visibility range of a variable declared at line: from its
// declaration to the end of the innermost block (function, closure or { ... }).
// Package-level declarations are visible throughout the file.
func (fr *fileResolver) declRange(line int) (int, int) {
	if scope, ok := innermostScope(fr.scopes, line); ok {
		return line, scope.end
	}
	return 0, math.MaxInt
}

func innermostScope(scopes []lineScope, line int) (lineScope, bool) {
	var best lineScope
	found := false
	for _, scope := range scopes {
		if line < scope.start || line > scope.end {
			continue
		}
		if !found || scope.end-scope.start < best.end-best.start {
			best, found = scope, true
		}
	}
	return best, found
}

func (fr *fileResolver) addGroupBindings() {
	seen := map[string]bool{}
	sort.Slice(fr.groups, func(i, j int) bool { return fr.groups[i].Line < fr.groups[j].Line })
	for _, f := range fr.groups {
		name := f.Metavars["$G"]
		key := fmt.Sprintf("%s:%d", name, f.Line)
		if name == "" || seen[key] {
			continue
		}
		seen[key] = true
		start, end := fr.declRange(f.Line)
		fr.bindings = append(fr.bindings, binding{
			name:  name,
			start: start,
			end:   end,
			node: &groupNode{
				baseName: f.Metavars["$BASE"],
				baseLine: f.Line,
				prefix:   f.Metavars["$PREFIX"],
				mws:      fr.resolveMWs(factMWs(fr.file, f)),
			},
		})
	}
}

// addChiBindings turns each chi.Route/Group closure into a scoped binding. Its
// state is read when a route needs it, so a closure inside a function whose
// router comes from another file still finds its callers.
func (fr *fileResolver) addChiBindings() {
	sort.Slice(fr.chis, func(i, j int) bool { return fr.chis[i].Line < fr.chis[j].Line })
	for _, f := range fr.chis {
		name := f.Metavars["$P"]
		if name == "" {
			continue
		}
		fact := f
		fr.bindings = append(fr.bindings, binding{name: name, start: f.Line, end: f.EndLine, chi: &fact})
	}
}

// bindingAt returns the innermost binding of name visible at line.
func (fr *fileResolver) bindingAt(name string, line int) *binding {
	var best *binding
	for i := range fr.bindings {
		b := &fr.bindings[i]
		if b.name != name || line < b.start || line > b.end || b.resolving {
			continue
		}
		if best == nil || b.start > best.start || (b.start == best.start && b.end < best.end) {
			best = b
		}
	}
	return best
}

// stateOfExpr resolves a route receiver: a variable, or an inline chain such
// as r.Group("/api", auth) / r.With(auth) (chi).
func (fr *fileResolver) stateOfExpr(expr string, line, depth int) *routeState {
	expr = strings.TrimSpace(expr)
	if depth > 8 {
		return &routeState{unknown: true, reason: receiverName(expr)}
	}
	if isEngineConstructor(expr) || expr == "http.DefaultServeMux" {
		return &routeState{}
	}
	base, method, args, ok := receiverCall(expr)
	if !ok {
		return fr.stateOfVar(expr, line, depth)
	}
	state := fr.stateOfExpr(base, line, depth+1)
	switch method {
	case "Group", "Route":
		if len(args) > 0 {
			if prefix := unquote(args[0]); strings.HasPrefix(prefix, "/") {
				state.prefixes = append(state.prefixes, prefix)
			}
		}
		if method == "Group" {
			for _, arg := range args[1:] {
				state.mws = append(state.mws, mwRef{file: fr.file, line: line, expr: fr.mwExpr(arg, line), place: groupPlace(state)})
			}
		}
	case "With":
		for _, arg := range args {
			state.mws = append(state.mws, mwRef{file: fr.file, line: line, expr: fr.mwExpr(arg, line), place: groupPlace(state)})
		}
	default:
		return &routeState{unknown: true, reason: receiverName(expr)}
	}
	return state
}

func (fr *fileResolver) stateOfVar(name string, line, depth int) *routeState {
	name = strings.TrimSpace(name)
	if depth > 8 {
		return &routeState{unknown: true, reason: receiverName(name)}
	}
	b := fr.bindingAt(name, line)
	var state *routeState
	var scope *funcScope
	if b != nil {
		switch {
		case b.chi != nil:
			b.resolving = true
			state = fr.stateOfExpr(b.chi.Metavars["$R"], b.chi.Line, depth+1)
			b.resolving = false
			if prefix := b.chi.Metavars["$PREFIX"]; prefix != "" {
				state.prefixes = append(state.prefixes, prefix)
			}
		case b.node != nil:
			state = fr.stateOfNode(b.node, depth)
		default:
			state = &routeState{}
		}
	} else if fn, idx := fr.paramAt(name, line); fn != nil {
		scope = fn
		state = fr.paramState(fn, idx, depth)
	} else if w := fr.wrapperAt(name, line); w != nil {
		state = fr.wrapperState(w, depth)
	} else if fs, ok := fr.receiverFieldState(name, line, depth); ok {
		state = fs
	} else if name == "http" {
		state = &routeState{}
	} else {
		state = &routeState{unknown: true, reason: name}
	}
	state.mws = append(state.mws, fr.usesBefore(name, line, b, scope, state)...)
	return state
}

func (fr *fileResolver) stateOfNode(node *groupNode, depth int) *routeState {
	state := fr.stateOfVar(node.baseName, node.baseLine, depth+1)
	if node.prefix != "" {
		state.prefixes = append(state.prefixes, node.prefix)
	}
	state.mws = append(state.mws, node.mws...)
	return state
}

// usesBefore returns the Use calls on name that are visible to a registration
// at line: same binding (scope), registered earlier. Fiber's path form
// Use("/x", mw) only applies to routes under that prefix.
func (fr *fileResolver) usesBefore(name string, line int, b *binding, scope *funcScope, state *routeState) []mwRef {
	inScope := func(l int) bool {
		if scope != nil {
			return l >= scope.start && l <= scope.end
		}
		return fr.bindingAt(name, l) == b // otherwise a shadowing group or router
	}
	var out []mwRef
	for _, u := range fr.uses {
		if u.Metavars["$R"] != name || u.Line >= line || !inScope(u.Line) {
			continue
		}
		out = append(out, fr.useMWs(u, state)...)
	}
	return append(out, fr.helperUses(name, line, inScope, state)...)
}

// useMWs turns one Use fact into middleware. Fiber's path form Use("/x", mw)
// only applies to routes under that prefix.
func (fr *fileResolver) useMWs(u Fact, state *routeState) []mwRef {
	args := factArgs(u)
	prefix := ""
	if fr.framework == "fiber" && len(args) > 0 {
		if p := unquote(args[0]); strings.HasPrefix(p, "/") {
			prefix = joinPaths(state.prefixes, p)
			args = args[1:]
		}
	}
	var out []mwRef
	for _, expr := range args {
		out = append(out, mwRef{file: fr.file, line: u.Line, expr: fr.mwExpr(expr, u.Line), place: groupPlace(state), prefix: prefix})
	}
	return out
}

// prefixApplies reports whether a path-scoped middleware applies to routePath.
// Fiber matches prefixes on segment boundaries: "/admin" covers "/admin" and
// "/admin/users", not "/administrators".
func prefixApplies(prefix, routePath string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	prefix = strings.TrimSuffix(prefix, "/")
	return routePath == prefix || strings.HasPrefix(routePath, prefix+"/")
}

// paramState resolves a router function parameter from its call sites: in
// this file, in the other files of the package, and in packages that import
// it. No call site, or callers that pass routers with different prefixes or
// middleware, leave it unknown.
func (fr *fileResolver) paramState(fn *funcScope, idx, depth int) *routeState {
	var sites []goCallSite
	for _, site := range fr.callersOf(fn) {
		if idx < len(site.call.args) {
			sites = append(sites, site)
		}
	}
	param := fn.params[idx].name
	if len(sites) == 0 {
		return &routeState{unknown: true, reason: param, why: goNoCaller, fn: fn.name}
	}
	resolve := func(site goCallSite) *routeState {
		return site.fr.stateOfExpr(site.call.args[idx], site.call.line, depth+1)
	}
	key := fmt.Sprintf("%s:%d:%d", fr.file, fn.start, idx)
	if p := fr.project; p != nil && p.forced != nil {
		if i, ok := p.forced[key]; ok && i < len(sites) {
			return resolve(sites[i]) // statesOf chose this caller
		}
	}
	state := resolve(sites[0])
	for _, site := range sites[1:] {
		if !sameState(state, resolve(site)) {
			if p := fr.project; p != nil && p.pending != nil {
				p.pending[key] = len(sites)
			}
			return &routeState{unknown: true, reason: param, why: goCallersDiffer, fn: fn.name}
		}
	}
	return state
}

// mwExpr resolves a middleware held in a variable (mw := auth.Jwt(key);
// grp.Use(mw)) to the call that built it, so the gate list sees the call.
func (fr *fileResolver) mwExpr(expr string, line int) string {
	expr = strings.TrimSpace(expr)
	if !goIdentRe.MatchString(expr) {
		return expr
	}
	if w := fr.wrapperAt(expr, line); w != nil {
		return w.value
	}
	return expr
}

func (fr *fileResolver) resolveMWs(mws []mwRef) []mwRef {
	for i := range mws {
		mws[i].expr = fr.mwExpr(mws[i].expr, mws[i].line)
	}
	return mws
}

var goIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// wrapperAt returns the latest wrapper assignment to name that is visible at line.
func (fr *fileResolver) wrapperAt(name string, line int) *goWrapper {
	var best *goWrapper
	for i := range fr.wrappers {
		w := &fr.wrappers[i]
		if w.name != name || w.line >= line {
			continue
		}
		if start, end := fr.declRange(w.line); line < start || line > end {
			continue
		}
		if best == nil || w.line > best.line {
			best = w
		}
	}
	return best
}

// wrapperState is the state of the router a wrapper is built from, plus the
// wrapper itself: its constructor may check something on every route.
func (fr *fileResolver) wrapperState(w *goWrapper, depth int) *routeState {
	if w.base == "" {
		return &routeState{unknown: true, reason: w.name}
	}
	base := fr.stateOfExpr(w.base, w.line, depth+1)
	if base.unknown {
		return &routeState{unknown: true, reason: w.name}
	}
	base.mws = append(base.mws, mwRef{file: fr.file, line: w.line, expr: w.callee, place: wrapsRouter})
	return base
}

func (fr *fileResolver) paramAt(name string, line int) (*funcScope, int) {
	var best *funcScope
	idx := -1
	for i := range fr.funcs {
		fn := &fr.funcs[i]
		if line < fn.start || line > fn.end {
			continue
		}
		if best != nil && fn.start <= best.start {
			continue
		}
		for j, p := range fn.params {
			if p.name == name && routerParamRe.MatchString(p.typ) {
				best, idx = fn, j
				break
			}
		}
	}
	return best, idx
}

func (fr *fileResolver) addUnknown(state *routeState) {
	name := receiverName(state.reason)
	if name == "" {
		name = "router"
	}
	var sentence string
	switch state.why {
	case goNoCaller:
		sentence = fmt.Sprintf("%s router %s is a parameter of %s, and no call to %s was found; protection unknown", fr.file, name, state.fn, state.fn)
	case goCallersDiffer:
		sentence = fmt.Sprintf("%s router %s: the calls to %s pass routers with different prefixes or middleware; protection unknown", fr.file, name, state.fn)
	case goNoField, goFieldsDiffer:
		sentence = fmt.Sprintf("%s %s; protection unknown", fr.file, state.unknownEvidence())
	default:
		sentence = fmt.Sprintf("%s router %s is created where this scan cannot follow it; protection unknown", fr.file, name)
	}
	for _, s := range fr.unknown {
		if s == sentence {
			return
		}
	}
	fr.unknown = append(fr.unknown, sentence)
}

func cloneState(s *routeState) *routeState {
	if s == nil {
		return &routeState{}
	}
	out := &routeState{unknown: s.unknown, reason: s.reason, why: s.why, fn: s.fn}
	out.prefixes = append(out.prefixes, s.prefixes...)
	out.mws = append(out.mws, s.mws...)
	return out
}

func sameState(a, b *routeState) bool {
	if a.unknown != b.unknown || strings.Join(a.prefixes, "|") != strings.Join(b.prefixes, "|") || len(a.mws) != len(b.mws) {
		return false
	}
	for i := range a.mws {
		if a.mws[i].expr != b.mws[i].expr {
			return false
		}
	}
	return true
}

func groupPlace(state *routeState) string {
	if len(state.prefixes) > 0 {
		return "on group " + state.prefixes[len(state.prefixes)-1]
	}
	return "on router"
}

// factMWs reads $A1..$A5 from a group/use fact.
func factMWs(file string, f Fact) []mwRef {
	var out []mwRef
	prefix := f.Metavars["$PREFIX"]
	place := "on a group"
	if prefix != "" {
		place = "on group " + prefix
	}
	for _, expr := range factArgs(f) {
		out = append(out, mwRef{file: file, line: f.Line, expr: expr, place: place})
	}
	return out
}

func factArgs(f Fact) []string {
	var out []string
	for i := 1; i <= 5; i++ {
		v, ok := f.Metavars[fmt.Sprintf("$A%d", i)]
		if !ok {
			break
		}
		out = append(out, v)
	}
	return out
}

func frameworkFor(imports []string) string {
	joined := strings.Join(imports, " ")
	switch {
	case strings.Contains(joined, "gin-gonic/gin"):
		return "gin"
	case strings.Contains(joined, "labstack/echo"):
		return "echo"
	case strings.Contains(joined, "gofiber/fiber"):
		return "fiber"
	case strings.Contains(joined, "go-chi/chi"):
		return "chi"
	case strings.Contains(joined, "net/http"):
		return "nethttp"
	default:
		return "gin"
	}
}

func isEngineConstructor(expr string) bool {
	for _, p := range []string{"gin.New(", "gin.Default(", "echo.New(", "fiber.New(", "chi.NewRouter(", "http.NewServeMux("} {
		if strings.HasPrefix(expr, p) {
			return true
		}
	}
	return false
}

// receiverCall splits an inline receiver such as r.Group("/x", mw) into its
// base, method and top-level arguments.
func receiverCall(expr string) (string, string, []string, bool) {
	expr = strings.TrimSpace(expr)
	if !strings.HasSuffix(expr, ")") {
		return "", "", nil, false
	}
	depth := 0
	open := -1
	for i := len(expr) - 1; i >= 0; i-- {
		switch expr[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				open = i
			}
		}
		if open >= 0 {
			break
		}
	}
	if open <= 0 {
		return "", "", nil, false
	}
	j := open - 1
	for j >= 0 && expr[j] == ' ' {
		j--
	}
	end := j + 1
	for j >= 0 && (expr[j] == '_' || expr[j] >= 'a' && expr[j] <= 'z' || expr[j] >= 'A' && expr[j] <= 'Z' || expr[j] >= '0' && expr[j] <= '9') {
		j--
	}
	if j < 0 || expr[j] != '.' {
		return "", "", nil, false
	}
	return strings.TrimSpace(expr[:j]), expr[j+1 : end], splitArgs(expr[open+1 : len(expr)-1]), true
}

// splitArgs splits on top-level commas only, so RequireRole("a,b") stays one
// argument. Comments are blanked first: a commented-out middleware call is not
// an argument, and its commas must not split the list (T31).
func splitArgs(src string) []string {
	src = stripComments(src)
	var out []string
	depth := 0
	start := 0
	quote := byte(0)
	for i := 0; i < len(src); i++ {
		c := src[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(src[start:i]))
				start = i + 1
			}
		}
	}
	if last := strings.TrimSpace(src[start:]); last != "" {
		out = append(out, last)
	}
	return out
}

// stripComments replaces // and /* */ comment text with spaces, keeping line
// breaks so argument text either side stays apart. Quotes win over comment
// markers, so a URL in a string literal is left alone.
func stripComments(src string) string {
	out := []byte(src)
	quote := byte(0)
	for i := 0; i < len(out); i++ {
		c := out[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '/':
			if i+1 >= len(out) {
				continue
			}
			switch out[i+1] {
			case '/':
				for i < len(out) && out[i] != '\n' {
					out[i] = ' '
					i++
				}
			case '*':
				out[i], out[i+1] = ' ', ' '
				i += 2
				for i < len(out) {
					if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
						out[i], out[i+1] = ' ', ' '
						i++
						break
					}
					if out[i] != '\n' {
						out[i] = ' '
					}
					i++
				}
			}
		}
	}
	return string(out)
}

func receiverName(expr string) string {
	expr = strings.TrimSpace(expr)
	if i := strings.IndexAny(expr, " .("); i > 0 {
		return expr[:i]
	}
	return expr
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'' || s[0] == '`') {
		return s[1 : len(s)-1]
	}
	return s
}

// parseGoScope reads the file's syntax for function parameters and call sites.
// Facts cannot express "this call passes a group to this parameter"; the Go
// parser can, and it is the same file the facts came from. Function, closure
// and block ranges let bindings stay inside their declaring scope.
func parseGoScope(path string) goSyntax {
	syn := goSyntax{imports: map[string]string{}}
	src, err := os.ReadFile(path)
	if err != nil {
		return syn
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return syn
	}
	syn.pkg = file.Name.Name
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := ""
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "_" || name == "." {
			continue
		}
		syn.imports[importPath] = name
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			syn.funcs = append(syn.funcs, scopeOf(src, fset, fn))
			syn.scopes = append(syn.scopes, lineScope{
				start: fset.Position(fn.Body.Pos()).Line,
				end:   fset.Position(fn.Body.End()).Line,
			})
		}
	}
	wrapper := func(name *ast.Ident, value ast.Expr) {
		call, ok := value.(*ast.CallExpr)
		if !ok || name.Name == "_" {
			return
		}
		w := goWrapper{name: name.Name, line: fset.Position(name.Pos()).Line,
			callee: exprText(src, fset, call.Fun), value: exprText(src, fset, call)}
		if len(call.Args) > 0 {
			w.base = exprText(src, fset, call.Args[0])
		}
		syn.wrappers = append(syn.wrappers, w)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BlockStmt:
			// Every block is a scope: a router declared inside { ... } must
			// stop being visible (and protected) when the block ends (T31).
			syn.scopes = append(syn.scopes, lineScope{
				start: fset.Position(node.Pos()).Line,
				end:   fset.Position(node.End()).Line,
			})
		case *ast.AssignStmt:
			if len(node.Lhs) == 1 && len(node.Rhs) == 1 {
				if ident, ok := node.Lhs[0].(*ast.Ident); ok {
					wrapper(ident, node.Rhs[0])
				}
				if sel, ok := node.Lhs[0].(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok {
						syn.fields = append(syn.fields, goFieldSet{recvVar: x.Name, field: sel.Sel.Name,
							expr: exprText(src, fset, node.Rhs[0]), line: fset.Position(node.Pos()).Line})
					}
				}
			}
		case *ast.CompositeLit:
			if typ := goTypeName(node.Type); typ != "" {
				for _, elt := range node.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok {
						syn.fields = append(syn.fields, goFieldSet{typ: typ, field: key.Name,
							expr: exprText(src, fset, kv.Value), line: fset.Position(kv.Pos()).Line})
					}
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) == 1 && len(node.Values) == 1 {
				wrapper(node.Names[0], node.Values[0])
			}
		case *ast.CallExpr:
			site := callSite{line: fset.Position(node.Pos()).Line}
			switch fun := node.Fun.(type) {
			case *ast.Ident:
				site.fn = fun.Name
			case *ast.SelectorExpr:
				x, ok := fun.X.(*ast.Ident)
				if !ok {
					return true
				}
				site.fn, site.qual = fun.Sel.Name, x.Name
			default:
				return true
			}
			site.args = make([]string, len(node.Args))
			for i, arg := range node.Args {
				site.args[i] = exprText(src, fset, arg)
			}
			syn.calls = append(syn.calls, site)
		}
		return true
	})
	return syn
}

func scopeOf(src []byte, fset *token.FileSet, fn *ast.FuncDecl) funcScope {
	scope := funcScope{
		name:   fn.Name.Name,
		start:  fset.Position(fn.Pos()).Line,
		end:    fset.Position(fn.End()).Line,
		method: fn.Recv != nil,
	}
	if fn.Recv != nil && len(fn.Recv.List) == 1 {
		recv := fn.Recv.List[0]
		scope.recvType = goTypeName(recv.Type)
		if len(recv.Names) == 1 {
			scope.recvName = recv.Names[0].Name
		}
	}
	if scope.recvName != "" && fn.Body != nil {
		seen := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			outer, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			inner, ok := outer.X.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := inner.X.(*ast.Ident); ok && x.Name == scope.recvName && !seen[inner.Sel.Name] {
				seen[inner.Sel.Name] = true
				scope.delegates = append(scope.delegates, inner.Sel.Name)
			}
			return true
		})
	}
	for _, field := range fn.Type.Params.List {
		typ := exprText(src, fset, field.Type)
		if len(field.Names) == 0 {
			scope.params = append(scope.params, paramRef{typ: typ})
			continue
		}
		for _, name := range field.Names {
			scope.params = append(scope.params, paramRef{name: name.Name, typ: typ})
		}
	}
	return scope
}

func exprText(src []byte, fset *token.FileSet, expr ast.Expr) string {
	start := fset.Position(expr.Pos()).Offset
	end := fset.Position(expr.End()).Offset
	if start >= 0 && end <= len(src) && start < end {
		return strings.TrimSpace(string(src[start:end]))
	}
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, expr); err != nil {
		return ""
	}
	return buf.String()
}
