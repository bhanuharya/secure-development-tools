package endpoints

import "testing"

// TestConfiguredAuthGatesReachResolvers proves endpoints.authGates is applied
// by every family that uses the gate list, not only parsed by the config.
func TestConfiguredAuthGatesReachResolvers(t *testing.T) {
	configured := newGateMatcher([]string{"checkCaller"})
	goFacts := []Fact{
		{Kind: "engine", File: "main.go", Line: 6, Metavars: map[string]string{"$R": "r"}},
		{Kind: "route", File: "main.go", Line: 8, Metavars: map[string]string{
			"$R": "r", "$VERB": "POST", "$PATH": "/orders", "$A1": "checkCaller", "$A2": "createOrder",
		}},
	}
	jsFacts := []Fact{
		{Kind: "express_import", File: "app.js", Line: 1},
		{Kind: "engine", File: "app.js", Line: 3, Metavars: map[string]string{"$R": "app"}},
		{Kind: "use", File: "app.js", Line: 4, Metavars: map[string]string{"$R": "app", "$A1": "checkCaller"}},
		jsRouteFact("app.js", 5, "app", "post", "'/orders'"),
	}
	pyFacts := []Fact{
		{Kind: "flask_app", File: "app.py", Line: 1, Metavars: map[string]string{"$R": "app"}},
		{Kind: "route", File: "app.py", Line: 5, Metavars: map[string]string{
			"$X": "app", "$PATH": "/orders", "$H": "orders", "$VERB": "POST",
		}},
		// Below the route decorator: it wraps the function before registration
		// (T24 point 1).
		{Kind: "decorator", File: "app.py", Line: 6, Metavars: map[string]string{"$H": "orders", "$DEC": "checkCaller"}},
	}
	cases := []struct {
		name string
		get  func(*gateMatcher) []Route
	}{
		{"go", func(g *gateMatcher) []Route {
			routes, _ := resolveGo(goFacts, t.TempDir(), g)
			return routes
		}},
		{"javascript", func(g *gateMatcher) []Route {
			routes, _ := resolveJS(jsFacts, t.TempDir(), g)
			return routes
		}},
		{"python", func(g *gateMatcher) []Route {
			routes, _ := resolvePython(pyFacts, t.TempDir(), g)
			return routes
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if routes := tc.get(defaultGates); len(routes) != 1 || routes[0].Protection != ProtPublic {
				t.Fatalf("without config: %+v", routes)
			}
			if routes := tc.get(configured); len(routes) != 1 || routes[0].Protection != ProtAuthenticated {
				t.Fatalf("with authGates: %+v", routes)
			}
		})
	}
}

func TestGateMatcherQuotesConfiguredNames(t *testing.T) {
	re := newGateMatcher([]string{"check.caller"})
	if !re.re.MatchString("check.caller") {
		t.Fatal("literal name does not match itself")
	}
	if re.re.MatchString("checkXcaller") {
		t.Fatal("configured gate was compiled as a regular expression")
	}
	if defaultGates.re.MatchString("checkCaller") {
		t.Fatal("default gate list must not know checkCaller")
	}
}
