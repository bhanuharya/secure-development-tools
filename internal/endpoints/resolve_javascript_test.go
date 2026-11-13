package endpoints

import (
	"os"
	"path/filepath"
	"testing"
)

func jsRouteFact(file string, line int, receiver, method, path string) Fact {
	return Fact{
		Kind: "route", File: file, Line: line,
		Metavars: map[string]string{
			"$R": receiver, "$METHOD": method, "$PATH": path, "$A1": "handler",
		},
	}
}

// TestJSKeepsOnlyServerReceivers pins the receiver half of T15: client calls
// in the same file (and even in a file that imports express) are dropped, not
// reported unknown, while routers known only by name stay in the inventory.
func TestJSKeepsOnlyServerReceivers(t *testing.T) {
	importFact := Fact{Kind: "express_import", File: "app.js", Line: 1}
	cases := []struct {
		name   string
		facts  []Fact
		routes int
	}{
		{
			name:   "axios client is dropped",
			facts:  []Fact{jsRouteFact("app.js", 3, "axios", "post", "'/change-password'")},
			routes: 0,
		},
		{
			name:   "http client is dropped next to express",
			facts:  []Fact{importFact, jsRouteFact("app.js", 5, "http", "get", "'/health'")},
			routes: 0,
		},
		{
			name:   "supertest request call is dropped",
			facts:  []Fact{jsRouteFact("app.js", 4, "request(app)", "get", "'/orders'")},
			routes: 0,
		},
		{
			name:   "this.http is dropped",
			facts:  []Fact{jsRouteFact("app.ts", 4, "this.http", "get", "'/orders'")},
			routes: 0,
		},
		{
			name:   "express import keeps an unusual router name",
			facts:  []Fact{importFact, jsRouteFact("app.js", 5, "ordersApi", "get", "'/orders'")},
			routes: 1,
		},
		{
			name:   "conventional name needs no setup",
			facts:  []Fact{jsRouteFact("app.js", 3, "api", "get", "'/items'")},
			routes: 1,
		},
		{
			name:   "Router suffix is a server",
			facts:  []Fact{jsRouteFact("orders.js", 3, "catalogRouter", "get", "'/items'")},
			routes: 1,
		},
		{
			name:   "unrelated receiver without express is dropped",
			facts:  []Fact{jsRouteFact("app.js", 3, "repo", "get", "'/items'")},
			routes: 0,
		},
		{
			name: "bare Router call needs the express import",
			facts: []Fact{
				{Kind: "router_fn", File: "app.js", Line: 1, Metavars: map[string]string{"$R": "r"}},
				jsRouteFact("app.js", 3, "r", "get", "'/items'"),
			},
			routes: 0,
		},
		{
			name: "bare Router call with the express import is a server",
			facts: []Fact{
				importFact,
				{Kind: "router_fn", File: "app.js", Line: 2, Metavars: map[string]string{"$R": "r"}},
				jsRouteFact("app.js", 3, "r", "get", "'/items'"),
			},
			routes: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			routes, _ := resolveJS(tc.facts, t.TempDir(), defaultGates)
			if len(routes) != tc.routes {
				t.Fatalf("got %d routes, want %d", len(routes), tc.routes)
			}
		})
	}
}

// TestJSSkipsFrontendAndTestFiles covers the path and import skips directly;
// the express-client golden covers the same files through the engine excludes.
func TestJSSkipsFrontendAndTestFiles(t *testing.T) {
	files := []string{
		"App.jsx", "App.tsx",
		"src/main/webapp/app/account.reducer.ts",
		"public/app.js", "static/app.js",
		"test/orders.js", "tests/orders.js", "__tests__/orders.js",
		"orders.test.js", "orders.spec.ts",
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			facts := []Fact{jsRouteFact(file, 5, "api", "get", "'/items'")}
			routes, unresolved := resolveJS(facts, t.TempDir(), defaultGates)
			if len(routes) != 0 || len(unresolved) != 0 {
				t.Fatalf("got %d routes and %d sentences, want 0 and 0", len(routes), len(unresolved))
			}
		})
	}
	t.Run("react import", func(t *testing.T) {
		facts := []Fact{
			{Kind: "frontend_import", File: "account.ts", Line: 1},
			jsRouteFact("account.ts", 5, "api", "get", "'/items'"),
		}
		if routes, _ := resolveJS(facts, t.TempDir(), defaultGates); len(routes) != 0 {
			t.Fatalf("got %d routes, want 0", len(routes))
		}
	})
	t.Run("server file is kept", func(t *testing.T) {
		facts := []Fact{jsRouteFact("internal/orders.ts", 5, "api", "get", "'/items'")}
		if routes, _ := resolveJS(facts, t.TempDir(), defaultGates); len(routes) != 1 {
			t.Fatalf("got %d routes, want 1", len(routes))
		}
	})
}

// TestJSPathlessMount covers app.use(mw, router): Express mounts the router at
// "/" with that middleware, so its routes are resolved, not unknown (T24).
func TestJSPathlessMount(t *testing.T) {
	cases := []struct {
		name       string
		args       map[string]string
		protection Protection
	}{
		{
			name:       "middleware and router",
			args:       map[string]string{"$A1": "verifyToken", "$A2": "router"},
			protection: ProtAuthenticated,
		},
		{
			name:       "router alone",
			args:       map[string]string{"$A1": "router"},
			protection: ProtPublic,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			use := map[string]string{"$R": "app"}
			for k, v := range tc.args {
				use[k] = v
			}
			facts := []Fact{
				{Kind: "express_import", File: "app.js", Line: 1},
				{Kind: "engine", File: "app.js", Line: 3, Metavars: map[string]string{"$R": "app"}},
				{Kind: "router", File: "app.js", Line: 4, Metavars: map[string]string{"$R": "router"}},
				{Kind: "use", File: "app.js", Line: 6, Metavars: use},
				jsRouteFact("app.js", 7, "router", "post", "'/transfer'"),
			}
			routes, unresolved := resolveJS(facts, t.TempDir(), defaultGates)
			if len(routes) != 1 {
				t.Fatalf("got %d routes and %v, want 1", len(routes), unresolved)
			}
			if routes[0].Path != "/transfer" || routes[0].Protection != tc.protection {
				t.Fatalf("got %s %s, want /transfer %s", routes[0].Path, routes[0].Protection, tc.protection)
			}
		})
	}
}

// TestJSFactoryBindingsAreLexical pins T36 finding 10: two functions may each
// declare their own `app`; a use() in the first factory must not protect a
// route registered in the second.
func TestJSFactoryBindingsAreLexical(t *testing.T) {
	dir := t.TempDir()
	src := `const express = require('express');

function privateApp() {
  const app = express();
  app.use(requireAuth);
  app.post('/private', handle);
}

function publicApp() {
  const app = express();
  app.post('/transfer', handle);
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	facts := []Fact{
		{Kind: "express_import", File: "app.js", Line: 1},
		{Kind: "engine", File: "app.js", Line: 4, Metavars: map[string]string{"$R": "app"}},
		{Kind: "use", File: "app.js", Line: 5, Metavars: map[string]string{"$R": "app", "$A1": "requireAuth"}},
		jsRouteFact("app.js", 6, "app", "post", "'/private'"),
		{Kind: "engine", File: "app.js", Line: 10, Metavars: map[string]string{"$R": "app"}},
		jsRouteFact("app.js", 11, "app", "post", "'/transfer'"),
	}
	routes, _ := resolveJS(facts, dir, defaultGates)
	got := map[string]Protection{}
	for _, r := range routes {
		got[r.Path] = r.Protection
	}
	if got["/private"] != ProtAuthenticated || got["/transfer"] != ProtPublic {
		t.Fatalf("got %v, want /private authenticated and /transfer public", got)
	}
}

// TestJSRouterBindingsAreLexical covers the router half: each factory owns its
// router, so its use() and its mount apply to that declaration only.
func TestJSRouterBindingsAreLexical(t *testing.T) {
	dir := t.TempDir()
	src := `const express = require('express');
const app = express();

function privateApi() {
  const router = express.Router();
  router.use(requireAuth);
  router.post('/orders', handle);
  app.use('/api/private', router);
}

function publicApi() {
  const router = express.Router();
  router.post('/transfer', handle);
  app.use('/api/public', router);
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	facts := []Fact{
		{Kind: "express_import", File: "app.js", Line: 1},
		{Kind: "engine", File: "app.js", Line: 2, Metavars: map[string]string{"$R": "app"}},
		{Kind: "router", File: "app.js", Line: 5, Metavars: map[string]string{"$R": "router"}},
		{Kind: "use", File: "app.js", Line: 6, Metavars: map[string]string{"$R": "router", "$A1": "requireAuth"}},
		jsRouteFact("app.js", 7, "router", "post", "'/orders'"),
		{Kind: "use", File: "app.js", Line: 8, Metavars: map[string]string{"$R": "app", "$A1": "'/api/private'", "$A2": "router"}},
		{Kind: "router", File: "app.js", Line: 12, Metavars: map[string]string{"$R": "router"}},
		jsRouteFact("app.js", 13, "router", "post", "'/transfer'"),
		{Kind: "use", File: "app.js", Line: 14, Metavars: map[string]string{"$R": "app", "$A1": "'/api/public'", "$A2": "router"}},
	}
	routes, _ := resolveJS(facts, dir, defaultGates)
	got := map[string]Protection{}
	for _, r := range routes {
		got[r.Path] = r.Protection
	}
	if got["/api/private/orders"] != ProtAuthenticated || got["/api/public/transfer"] != ProtPublic {
		t.Fatalf("got %v, want /api/private/orders authenticated and /api/public/transfer public", got)
	}
}

func TestExpandTemplate(t *testing.T) {
	consts := map[string]string{"base": "/api/account"}
	cases := []struct{ in, want string }{
		{"`${base}/x`", "/api/account/x"},
		{"`${base}/${tenant}`", "/api/account/{tenant}"},
		{"`/accounts/${req.params.id}`", "/accounts/{id}"},
		{"`${unknown}`", "{unknown}"},
	}
	for _, tc := range cases {
		if got := expandTemplate(tc.in, consts); got != tc.want {
			t.Errorf("expandTemplate(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestNestGlobalGuard covers the branch the golden fixture cannot show both
// ways: the same unguarded controller is public without a service-wide guard
// and unknown with one.
func TestNestGlobalGuard(t *testing.T) {
	controller := []Fact{
		{Kind: "controller", File: "app.ts", Line: 3, Metavars: map[string]string{"$C": "HealthController", "$PREFIX": "health"}},
		{Kind: "route", File: "app.ts", Line: 6, Metavars: map[string]string{"$C": "HealthController", "$M": "status", "$VERB": "Get", "$PATH": "status"}},
	}
	cases := []struct {
		name       string
		facts      []Fact
		protection Protection
		unresolved int
	}{
		{name: "no global guard is public", facts: controller, protection: ProtPublic},
		{
			name:       "global guard leaves the route unknown",
			facts:      append(append([]Fact{}, controller...), Fact{Kind: "app_guard", File: "module.ts", Line: 9}),
			protection: ProtUnknown,
			unresolved: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			routes, unresolved := resolveJS(tc.facts, t.TempDir(), defaultGates)
			if len(routes) != 1 {
				t.Fatalf("got %d routes, want 1", len(routes))
			}
			if routes[0].Protection != tc.protection {
				t.Errorf("protection = %s, want %s", routes[0].Protection, tc.protection)
			}
			if len(unresolved) != tc.unresolved {
				t.Errorf("unresolved = %v, want %d sentences", unresolved, tc.unresolved)
			}
		})
	}
}
