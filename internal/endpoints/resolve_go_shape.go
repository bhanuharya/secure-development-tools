package endpoints

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"
)

// The route fact matches any $R.Get("...", x) call, and other calls share that
// shape: fiber's c.Get("Accept-Language", "en") reads a request header and
// slog.Any("key", v) builds a log attribute. These are not routes, so they are
// dropped rather than reported as unresolved routes. Separately, fiber, gin and
// echo add a missing leading slash themselves (grp.Get("ping", h) serves
// /ping), so such a path is a route, not an unresolvable one.

// goContextTypeRe matches a request-context parameter type. A receiver of one
// of these types is a request, never a router.
var goContextTypeRe = regexp.MustCompile(`^\*?(fiber\.Ctx|gin\.Context|echo\.Context)$`)

// goVarScope is a variable visible from start to end (a parameter of the
// function or closure whose body spans those lines).
type goVarScope struct {
	name  string
	start int
	end   int
}

// contextParams returns the request-context parameters of one function or
// closure, visible in its body.
func contextParams(src []byte, fset *token.FileSet, typ *ast.FuncType, body *ast.BlockStmt) []goVarScope {
	if typ == nil || typ.Params == nil || body == nil {
		return nil
	}
	var out []goVarScope
	for _, field := range typ.Params.List {
		if !goContextTypeRe.MatchString(exprText(src, fset, field.Type)) {
			continue
		}
		for _, name := range field.Names {
			out = append(out, goVarScope{name: name.Name,
				start: fset.Position(body.Pos()).Line, end: fset.Position(body.End()).Line})
		}
	}
	return out
}

// notRouter reports a call with a route's shape whose receiver cannot be a
// router: a request context, or an imported package other than net/http
// (http.HandleFunc registers on the default mux).
func (fr *fileResolver) notRouter(receiver string, line int) bool {
	if !token.IsIdentifier(receiver) {
		return false
	}
	for _, v := range fr.ctxVars {
		if v.name == receiver && line >= v.start && line <= v.end {
			return true
		}
	}
	// A local router or parameter of the same name shadows a package.
	if fr.bindingAt(receiver, line) != nil || fr.wrapperAt(receiver, line) != nil {
		return false
	}
	if fn, _ := fr.paramAt(receiver, line); fn != nil {
		return false
	}
	for importPath, name := range fr.imports {
		if name == "" {
			name = goDefaultPkgName(importPath)
		}
		if name == receiver {
			return importPath != "net/http"
		}
	}
	return false
}

// goStringLit reports an argument that is a string literal.
func goStringLit(arg string) bool {
	arg = strings.TrimSpace(arg)
	return len(arg) >= 2 && (arg[0] == '"' || arg[0] == '`') && arg[len(arg)-1] == arg[0]
}

// slashOptional reports a file that imports a framework adding a missing
// leading slash to route and group paths (fiber, gin, echo). chi panics on such
// a path and net/http reads it as a host pattern, so there it stays
// unresolved.
func (fr *fileResolver) slashOptional() bool {
	for importPath := range fr.imports {
		for _, fw := range []string{"gofiber/fiber", "gin-gonic/gin", "labstack/echo"} {
			if strings.Contains(importPath, fw) {
				return true
			}
		}
	}
	return false
}

// routePath returns a route's literal path with its leading slash, or false
// when the path is not one the framework serves.
func (fr *fileResolver) routePath(raw string) (string, bool) {
	switch {
	case strings.HasPrefix(raw, "/"):
		return raw, true
	case fr.slashOptional() && !strings.ContainsAny(raw, " \t"):
		return "/" + raw, true
	}
	return "", false
}

// literalPrefix returns a group or Use prefix given as a string literal, with
// its leading slash.
func (fr *fileResolver) literalPrefix(arg string) (string, bool) {
	if !goStringLit(arg) {
		return "", false
	}
	return fr.routePath(unquote(arg))
}
