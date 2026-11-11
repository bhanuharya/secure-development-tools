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
	"strings"
)

// This file is the same-file scope model behind resolve_go.go. Facts say what
// is registered where; this model says which group/router a receiver refers to
// at that line. Only the current file is consulted (SPEC §5): a router that is
// created or mounted elsewhere stays unknown.

// mwRef is one middleware expression on a route's chain.
type mwRef struct {
	file  string
	line  int
	expr  string
	place string // "", "on router", "on group /api", "wraps the handler"
}

// routeState is a resolved group/router: the prefixes it adds and the
// middleware inherited from its creation up to a given line.
type routeState struct {
	prefixes []string
	mws      []mwRef
	unknown  bool
	reason   string // the receiver name, for the Unresolved sentence
}

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
	state *routeState // snapshots for chi closures (captured at closure start)
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
}

type callSite struct {
	fn   string
	args []string
	line int
}

type fileResolver struct {
	file      string
	root      string
	framework string
	matcher   *gateMatcher
	engines   map[string]bool
	groups    []Fact
	chis      []Fact
	uses      []Fact
	routes    []Fact
	bindings  []binding
	funcs     []funcScope
	calls     []callSite
	unknown   []string
}

var routerParamRe = regexp.MustCompile(`(?i)(gin\.(RouterGroup|Engine|IRouter|IRoutes)|echo\.(Group|Echo)|fiber\.(Router|App)|chi\.(Router|Mux)|http\.ServeMux)`)

// newFileResolver indexes one file's facts and its Go syntax (functions and
// calls) for same-file scope resolution.
func newFileResolver(file string, facts []Fact, root string, gates *gateMatcher) *fileResolver {
	fr := &fileResolver{file: file, root: root, matcher: gates, engines: map[string]bool{}}
	var imports []string
	for _, f := range facts {
		switch f.Kind {
		case "import":
			imports = append(imports, f.Metavars["$IMPORT"])
		case "engine":
			fr.engines[f.Metavars["$R"]] = true
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
	fr.funcs, fr.calls = parseGoScope(filepath.Join(root, file))
	fr.addGroupBindings()
	fr.addChiBindings()
	return fr
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
		fr.bindings = append(fr.bindings, binding{
			name:  name,
			start: f.Line,
			end:   math.MaxInt,
			node: &groupNode{
				baseName: f.Metavars["$BASE"],
				baseLine: f.Line,
				prefix:   f.Metavars["$PREFIX"],
				mws:      factMWs(fr.file, f),
			},
		})
	}
}

// addChiBindings turns each chi.Route/Group closure into a scoped binding. The
// snapshot is taken in source order so nested closures inherit the outer one.
func (fr *fileResolver) addChiBindings() {
	sort.Slice(fr.chis, func(i, j int) bool { return fr.chis[i].Line < fr.chis[j].Line })
	for _, f := range fr.chis {
		name := f.Metavars["$P"]
		if name == "" {
			continue
		}
		state := fr.stateOfExpr(f.Metavars["$R"], f.Line, 0)
		if prefix := f.Metavars["$PREFIX"]; prefix != "" {
			state.prefixes = append(state.prefixes, prefix)
		}
		fr.bindings = append(fr.bindings, binding{name: name, start: f.Line, end: f.EndLine, state: state})
	}
}

// bindingAt returns the innermost binding of name visible at line.
func (fr *fileResolver) bindingAt(name string, line int) *binding {
	var best *binding
	for i := range fr.bindings {
		b := &fr.bindings[i]
		if b.name != name || line < b.start || line > b.end {
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
				state.mws = append(state.mws, mwRef{file: fr.file, line: line, expr: arg, place: groupPlace(state)})
			}
		}
	case "With":
		for _, arg := range args {
			state.mws = append(state.mws, mwRef{file: fr.file, line: line, expr: arg, place: groupPlace(state)})
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
		case b.state != nil:
			state = cloneState(b.state)
		case b.node != nil:
			state = fr.stateOfNode(b.node, depth)
		default:
			state = &routeState{}
		}
	} else if fn, idx := fr.paramAt(name, line); fn != nil {
		scope = fn
		state = fr.paramState(fn, idx, depth)
	} else if fr.engines[name] || name == "http" {
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
// at line: same binding (scope), registered earlier.
func (fr *fileResolver) usesBefore(name string, line int, b *binding, scope *funcScope, state *routeState) []mwRef {
	var out []mwRef
	for _, u := range fr.uses {
		if u.Metavars["$R"] != name || u.Line >= line {
			continue
		}
		if scope != nil {
			if u.Line < scope.start || u.Line > scope.end {
				continue
			}
		} else if fr.bindingAt(name, u.Line) != b {
			continue // the call belongs to a shadowing group or router
		}
		for _, expr := range factArgs(u) {
			out = append(out, mwRef{file: fr.file, line: u.Line, expr: expr, place: groupPlace(state)})
		}
	}
	return out
}

// paramState resolves a router function parameter from the call sites in the
// same file. No call site means the router was passed in from another file.
func (fr *fileResolver) paramState(fn *funcScope, idx, depth int) *routeState {
	var states []*routeState
	for _, c := range fr.calls {
		if c.fn != fn.name || idx >= len(c.args) {
			continue
		}
		states = append(states, fr.stateOfExpr(c.args[idx], c.line, depth+1))
	}
	if len(states) == 0 {
		return &routeState{unknown: true, reason: fn.params[idx].name}
	}
	state := cloneState(states[0])
	for _, other := range states[1:] {
		if !sameState(state, other) {
			return &routeState{unknown: true, reason: fn.params[idx].name}
		}
	}
	return state
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

func (fr *fileResolver) addUnknown(name string) {
	name = receiverName(name)
	if name == "" {
		name = "router"
	}
	sentence := fmt.Sprintf("%s router %s is created or mounted in another file; protection unknown", fr.file, name)
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
	out := &routeState{unknown: s.unknown, reason: s.reason}
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
// argument.
func splitArgs(src string) []string {
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
// parser can, and it is the same file the facts came from.
func parseGoScope(path string) ([]funcScope, []callSite) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, nil
	}
	var funcs []funcScope
	var calls []callSite
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			funcs = append(funcs, scopeOf(src, fset, fn))
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		args := make([]string, len(call.Args))
		for i, arg := range call.Args {
			args[i] = exprText(src, fset, arg)
		}
		calls = append(calls, callSite{fn: ident.Name, args: args, line: fset.Position(call.Pos()).Line})
		return true
	})
	return funcs, calls
}

func scopeOf(src []byte, fset *token.FileSet, fn *ast.FuncDecl) funcScope {
	scope := funcScope{
		name:  fn.Name.Name,
		start: fset.Position(fn.Pos()).Line,
		end:   fset.Position(fn.End()).Line,
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
