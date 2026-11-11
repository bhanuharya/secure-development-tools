package endpoints

import "testing"

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
