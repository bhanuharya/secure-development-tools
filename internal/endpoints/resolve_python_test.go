package endpoints

import (
	"os"
	"path/filepath"
	"testing"
)

func pyTestRoute(file string, line, defLine int, receiver, verb, path, handler string) Fact {
	return Fact{
		Kind: "route", File: file, Line: line,
		Metavars: map[string]string{
			"$X": receiver, "$VERB": verb, "$PATH": path, "$H": handler,
		},
		MetavarLines: map[string]int{"$PATH": line, "$H": defLine},
	}
}

func pyTestDecorator(file string, line, defLine int, name, handler string) Fact {
	return Fact{
		Kind: "decorator", File: file, Line: line,
		Metavars:     map[string]string{"$DEC": name, "$H": handler},
		MetavarLines: map[string]int{"$DEC": line, "$H": defLine},
	}
}

func pyTestRouter(file string, line int, prefix string, deps ...string) Fact {
	f := Fact{Kind: "router", File: file, Line: line, Metavars: map[string]string{"$R": "router", "$PREFIX": prefix}}
	if len(deps) > 0 {
		f.Metavars["$DEPS"] = deps[0]
	}
	return f
}

// TestPyDecoratorOrder pins Flask/FastAPI decorator semantics: only decorators
// below the route decorator wrap the registered function.
func TestPyDecoratorOrder(t *testing.T) {
	cases := []struct {
		name       string
		gateLine   int
		protection Protection
	}{
		{name: "above the route does not wrap it", gateLine: 4, protection: ProtPublic},
		{name: "below the route wraps it", gateLine: 6, protection: ProtAuthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := []Fact{
				{Kind: "flask_app", File: "app.py", Line: 1, Metavars: map[string]string{"$R": "app"}},
				pyTestRoute("app.py", 5, 7, "app", "post", "/transfer", "transfer"),
				pyTestDecorator("app.py", tc.gateLine, 7, "login_required", "transfer"),
			}
			routes, _ := resolvePython(facts, t.TempDir(), defaultGates)
			if len(routes) != 1 || routes[0].Protection != tc.protection {
				t.Fatalf("got %+v, want one %s route", routes, tc.protection)
			}
		})
	}
}

// TestPyStackedRegistrations keeps one route per decorator and gives a route
// only the dependencies written on that decorator.
func TestPyStackedRegistrations(t *testing.T) {
	secure := pyTestRoute("main.py", 4, 6, "app", "post", "/admin/secure", "update")
	secure.Metavars["$DEPS"] = "[Depends(require_auth)]"
	facts := []Fact{
		{Kind: "fastapi_app", File: "main.py", Line: 2, Metavars: map[string]string{"$R": "app"}},
		secure,
		pyTestRoute("main.py", 5, 6, "app", "post", "/admin/open", "update"),
	}
	routes, _ := resolvePython(facts, t.TempDir(), defaultGates)
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	byPath := map[string]Route{}
	for _, r := range routes {
		byPath[r.Path] = r
	}
	if got := byPath["/admin/secure"].Protection; got != ProtAuthenticated {
		t.Errorf("/admin/secure = %s, want authenticated", got)
	}
	if got := byPath["/admin/open"].Protection; got != ProtPublic {
		t.Errorf("/admin/open = %s, want public", got)
	}
}

// TestPySameNameFunctionsAreSeparate keeps a gate on one update() away from a
// second update() in the same file.
func TestPySameNameFunctionsAreSeparate(t *testing.T) {
	facts := []Fact{
		{Kind: "flask_app", File: "main.py", Line: 1, Metavars: map[string]string{"$R": "app"}},
		pyTestRoute("main.py", 4, 6, "app", "post", "/admin/secure", "update"),
		pyTestDecorator("main.py", 5, 6, "login_required", "update"),
		pyTestRoute("main.py", 10, 12, "app", "post", "/transfer", "update"),
	}
	routes, _ := resolvePython(facts, t.TempDir(), defaultGates)
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	for _, r := range routes {
		want := ProtPublic
		if r.Path == "/admin/secure" {
			want = ProtAuthenticated
		}
		if r.Protection != want {
			t.Errorf("%s = %s, want %s", r.Path, r.Protection, want)
		}
	}
}

// TestPyAppDependencies covers routes registered on the app and routes of a
// router included into it in the same file.
func TestPyAppDependencies(t *testing.T) {
	facts := []Fact{
		{Kind: "fastapi_app", File: "main.py", Line: 2, Metavars: map[string]string{"$R": "app"}},
		{Kind: "fastapi_app_deps", File: "main.py", Line: 2, Metavars: map[string]string{"$R": "app", "$DEPS": "[Depends(require_auth)]"}},
		pyTestRoute("main.py", 4, 5, "app", "post", "/admin/users", "users"),
		pyTestRouter("main.py", 6, "/api"),
		pyTestRoute("main.py", 8, 9, "router", "post", "/transfer", "transfer"),
		{Kind: "include_router", File: "main.py", Line: 11, Metavars: map[string]string{"$A": "app", "$R": "router"}},
	}
	routes, _ := resolvePython(facts, t.TempDir(), defaultGates)
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	for _, r := range routes {
		if r.Protection != ProtAuthenticated {
			t.Errorf("%s = %s, want authenticated", r.Path, r.Protection)
		}
	}
}

// TestPyMountPrefixRules pins the framework difference: Flask replaces the
// blueprint prefix, FastAPI adds the include prefix.
func TestPyMountPrefixRules(t *testing.T) {
	flask := []Fact{
		{Kind: "flask_app", File: "app.py", Line: 1, Metavars: map[string]string{"$R": "app"}},
		{Kind: "blueprint", File: "app.py", Line: 3, Metavars: map[string]string{"$R": "bp", "$PREFIX": "/internal"}},
		pyTestRoute("app.py", 5, 6, "bp", "post", "/transfer", "transfer"),
		{Kind: "register_blueprint", File: "app.py", Line: 8, Metavars: map[string]string{"$A": "app", "$R": "bp", "$PREFIX": "/api"}},
	}
	routes, _ := resolvePython(flask, t.TempDir(), defaultGates)
	if len(routes) != 1 || routes[0].Path != "/api/transfer" {
		t.Fatalf("flask blueprint got %+v, want /api/transfer", routes)
	}

	fastapi := []Fact{
		{Kind: "fastapi_app", File: "main.py", Line: 1, Metavars: map[string]string{"$R": "app"}},
		pyTestRouter("main.py", 3, "/api"),
		pyTestRoute("main.py", 5, 6, "router", "post", "/transfer", "transfer"),
		{Kind: "include_router", File: "main.py", Line: 8, Metavars: map[string]string{"$A": "app", "$R": "router", "$PREFIX": "/v1"}},
	}
	routes, _ = resolvePython(fastapi, t.TempDir(), defaultGates)
	if len(routes) != 1 || routes[0].Path != "/v1/api/transfer" {
		t.Fatalf("fastapi router got %+v, want /v1/api/transfer", routes)
	}
}

// TestPySourceRoutesReadsAsyncAndMultilineDecorators pins T31: a route stack on
// an async handler, with one registration spread over several lines, registers
// one route per decorator instead of dropping the stack.
func TestPySourceRoutesReadsAsyncAndMultilineDecorators(t *testing.T) {
	dir := t.TempDir()
	src := `from fastapi import Depends, FastAPI

app = FastAPI()


@app.post("/secure", dependencies=[Depends(require_auth)])
@app.post(
    "/transfer",
)
async def transfer():
    return {"ok": True}
`
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	facts := append(pySourceRoutes(dir, "main.py"),
		Fact{Kind: "fastapi_app", File: "main.py", Line: 3, Metavars: map[string]string{"$R": "app"}})
	routes, _ := resolvePython(facts, dir, defaultGates)
	got := map[string]Route{}
	for _, r := range routes {
		got[r.Path] = r
	}
	if len(got) != 2 {
		t.Fatalf("got %d routes %+v, want /secure and /transfer", len(got), routes)
	}
	if got["/secure"].Protection != ProtAuthenticated {
		t.Errorf("/secure = %s, want authenticated", got["/secure"].Protection)
	}
	if got["/transfer"].Protection != ProtPublic {
		t.Errorf("/transfer = %s, want public", got["/transfer"].Protection)
	}
}

// TestPySourceRoutesSkipStrings pins T36 finding 13: decorators written inside
// a module docstring or a function docstring are examples, not registrations.
func TestPySourceRoutesSkipStrings(t *testing.T) {
	dir := t.TempDir()
	src := `from fastapi import FastAPI

app = FastAPI()

DOCS = """
@app.post("/transfer")
async def transfer():
    return {}
"""


@app.post("/orders")
async def orders():
    """Example:

    @app.post("/internal")
    async def internal():
        return {}
    """
    return {}
`
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	facts := append(pySourceRoutes(dir, "main.py"),
		Fact{Kind: "fastapi_app", File: "main.py", Line: 3, Metavars: map[string]string{"$R": "app"}})
	routes, _ := resolvePython(facts, dir, defaultGates)
	if len(routes) != 1 || routes[0].Path != "/orders" {
		t.Fatalf("got %+v, want only /orders", routes)
	}
}

// TestPyEmptyBlueprintPrefixOverrides pins T31: url_prefix="" is an explicit
// override that removes the blueprint's own prefix, unlike an absent keyword.
func TestPyEmptyBlueprintPrefixOverrides(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		has    bool
		want   string
	}{
		{name: "explicit empty overrides", prefix: "", has: true, want: "/transfer"},
		{name: "absent keeps the blueprint prefix", want: "/public/transfer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mount := Fact{Kind: "register_blueprint", File: "app.py", Line: 8, Metavars: map[string]string{"$A": "app", "$R": "bp"}}
			if tc.has {
				mount.Metavars["$PREFIX"] = tc.prefix
			}
			facts := []Fact{
				{Kind: "flask_app", File: "app.py", Line: 1, Metavars: map[string]string{"$R": "app"}},
				{Kind: "blueprint", File: "app.py", Line: 3, Metavars: map[string]string{"$R": "bp", "$PREFIX": "/public"}},
				pyTestRoute("app.py", 5, 6, "bp", "post", "/transfer", "transfer"),
				mount,
			}
			routes, _ := resolvePython(facts, t.TempDir(), defaultGates)
			if len(routes) != 1 || routes[0].Path != tc.want {
				t.Fatalf("got %+v, want %s", routes, tc.want)
			}
		})
	}
}
