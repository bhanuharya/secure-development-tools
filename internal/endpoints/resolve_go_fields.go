package endpoints

import (
	"fmt"
	"go/ast"
	"path"
	"strings"
)

// Routers kept in struct fields. A service type often holds the engine
// (type RestAPI struct{ Router *fiber.App }), sets it once (r.Router = app or
// &RestAPI{Router: app}) and registers routes through it: a.Router.Get(...), or
// its own Get/Post methods that forward to a.Router.Get(path, handlers...).
// The field's state is the state of the router assigned to it, read at the
// assignment. Middleware registered on that router later in the assigning
// function is therefore not seen; a gate added that way leaves the route
// public, which a reviewer can see in the evidence.

// goRouteVerbs are the method names a forwarding wrapper type defines.
var goRouteVerbs = map[string]bool{
	"Get": true, "Post": true, "Put": true, "Patch": true, "Delete": true, "Head": true,
	"Options": true, "All": true, "Any": true, "Add": true, "Handle": true, "HandleFunc": true,
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
}

// goTypeName is the base name of a type expression: *pkg.T[K] gives T.
func goTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return goTypeName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.IndexExpr:
		return goTypeName(t.X)
	case *ast.IndexListExpr:
		return goTypeName(t.X)
	case *ast.UnaryExpr:
		return goTypeName(t.X)
	}
	return ""
}

// typedFieldSets gives each recv.Field = x assignment the type of the method
// receiver it is made on; assignments on other variables are dropped.
func typedFieldSets(sets []goFieldSet, funcs []funcScope) []goFieldSet {
	var out []goFieldSet
	for _, set := range sets {
		if set.typ == "" {
			for _, fn := range funcs {
				if fn.recvName == set.recvVar && set.line >= fn.start && set.line <= fn.end {
					set.typ = fn.recvType
					break
				}
			}
		}
		if set.typ != "" {
			out = append(out, set)
		}
	}
	return out
}

// enclosingFunc is the function or method declaration around line.
func (fr *fileResolver) enclosingFunc(line int) *funcScope {
	for i := range fr.funcs {
		if fn := &fr.funcs[i]; line >= fn.start && line <= fn.end {
			return fn
		}
	}
	return nil
}

// receiverFieldState resolves a route receiver that is a method receiver
// forwarding to one of its fields (a.Post(...) with RestAPI.Post calling
// a.Router.Post), or a field of it (a.Router.Get(...)).
func (fr *fileResolver) receiverFieldState(name string, line, depth int) (*routeState, bool) {
	fn := fr.enclosingFunc(line)
	if fn == nil || fn.recvName == "" || fn.recvType == "" {
		return nil, false
	}
	switch {
	case name == fn.recvName:
		field, ok := fr.delegateField(fn.recvType)
		if !ok {
			return nil, false
		}
		return fr.fieldState(fn.recvType, field, depth), true
	case strings.HasPrefix(name, fn.recvName+"."):
		field := strings.TrimPrefix(name, fn.recvName+".")
		if !goIdentRe.MatchString(field) {
			return nil, false
		}
		return fr.fieldState(fn.recvType, field, depth), true
	}
	return nil, false
}

// delegateField is the one field that typ's verb methods forward to.
func (fr *fileResolver) delegateField(typ string) (string, bool) {
	field := ""
	for _, other := range fr.packageFiles() {
		for _, fn := range other.funcs {
			if fn.recvType != typ || !goRouteVerbs[fn.name] {
				continue
			}
			for _, d := range fn.delegates {
				if field != "" && field != d {
					return "", false
				}
				field = d
			}
		}
	}
	return field, field != ""
}

// fieldState combines every assignment of typ.field in the package.
func (fr *fileResolver) fieldState(typ, field string, depth int) *routeState {
	var states []*routeState
	for _, other := range fr.packageFiles() {
		for _, set := range other.fields {
			if set.typ == typ && set.field == field {
				states = append(states, other.stateOfExpr(set.expr, set.line, depth+1))
			}
		}
	}
	reason := typ + "." + field
	if len(states) == 0 {
		return &routeState{unknown: true, reason: reason, why: goNoField}
	}
	state := cloneState(states[0])
	for _, other := range states[1:] {
		if !sameState(state, other) {
			return &routeState{unknown: true, reason: reason, why: goFieldsDiffer}
		}
	}
	return state
}

// packageFiles are the resolvers of the files in fr's package.
func (fr *fileResolver) packageFiles() []*fileResolver {
	if fr.project == nil {
		return []*fileResolver{fr}
	}
	dir := path.Dir(fr.file)
	var out []*fileResolver
	for _, other := range fr.project.all() {
		if path.Dir(other.file) == dir && other.pkg == fr.pkg {
			out = append(out, other)
		}
	}
	return out
}

const (
	goNoField      = "no field"
	goFieldsDiffer = "fields differ"
)

// helperUses returns the middleware that functions called before line register
// on name: r.setupMiddlewares(app) followed by routes on app. Each callee is
// read once, without following its own calls.
func (fr *fileResolver) helperUses(name string, line int, inScope func(int) bool, state *routeState) []mwRef {
	if fr.project == nil {
		return nil
	}
	var out []mwRef
	for _, c := range fr.calls {
		if c.line >= line || !inScope(c.line) {
			continue
		}
		idx := -1
		for i, arg := range c.args {
			if strings.TrimSpace(arg) == name {
				idx = i
				break
			}
		}
		if idx < 0 || goRouteVerbs[c.fn] || c.fn == "Use" || c.fn == "Group" || c.fn == "Route" || c.fn == "Mount" {
			continue
		}
		for _, callee := range fr.calleesOf(c) {
			fn := callee.fn
			if idx >= len(fn.params) || !routerParamRe.MatchString(fn.params[idx].typ) {
				continue
			}
			param := fn.params[idx].name
			for _, u := range callee.fr.uses {
				if u.Metavars["$R"] != param || u.Line < fn.start || u.Line > fn.end {
					continue
				}
				for _, mw := range callee.fr.useMWs(u, state) {
					mw.place = fmt.Sprintf("%s (registered in %s)", mw.place, fn.name)
					out = append(out, mw)
				}
			}
		}
	}
	return out
}

type goCallee struct {
	fr *fileResolver
	fn *funcScope
}

// calleesOf lists the declarations a call can reach (the inverse of callersOf).
func (fr *fileResolver) calleesOf(c callSite) []goCallee {
	key := fmt.Sprintf("%s:%d:%s.%s", fr.file, c.line, c.qual, c.fn)
	if cached, ok := fr.project.callees[key]; ok {
		return cached
	}
	var out []goCallee
	dir := path.Dir(fr.file)
	for _, other := range fr.project.all() {
		samePkg := path.Dir(other.file) == dir && other.pkg == fr.pkg
		for i := range other.funcs {
			fn := &other.funcs[i]
			if fn.name == c.fn && other.reaches(fn, fr, c, samePkg) {
				out = append(out, goCallee{fr: other, fn: fn})
			}
		}
	}
	fr.project.callees[key] = out
	return out
}
