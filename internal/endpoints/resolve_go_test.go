package endpoints

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGateMatchingUsesCallableName pins T23: the gate list sees the called
// name, never argument values such as a CORS Authorization header.
func TestGateMatchingUsesCallableName(t *testing.T) {
	cases := []struct {
		expr string
		gate bool
	}{
		{"AuthMiddleware", true},
		{"r.middleware.EnsureTokenValidity", true},
		{`RequireRole("admin")`, true},
		{`cors.New(cors.Config{AllowHeaders: []string{"Authorization"}})`, false},
		{`cors({allowedHeaders: ['Authorization']})`, false},
	}
	for _, tc := range cases {
		if got := defaultGates.re.MatchString(callableName(tc.expr)); got != tc.gate {
			t.Errorf("%s: gate=%v, want %v", tc.expr, got, tc.gate)
		}
	}
	if roleRe.MatchString(callableName(`cors({allowedHeaders: ['Authorization']})`)) {
		t.Error("argument value named a role")
	}
}

// TestSplitHandlersPerFramework pins the argument order: gin, fiber, chi and
// net/http put the handler last; echo puts it first.
func TestSplitHandlersPerFramework(t *testing.T) {
	cases := []struct {
		framework string
		args      []string
		handler   string
		mw        string
	}{
		{"gin", []string{"AuthMiddleware", "handle"}, "handle", "AuthMiddleware"},
		{"fiber", []string{"AuthMiddleware", "handle"}, "handle", "AuthMiddleware"},
		{"echo", []string{"handle", "AuthMiddleware"}, "handle", "AuthMiddleware"},
		{"fiber", []string{"handle"}, "handle", ""},
	}
	for _, tc := range cases {
		handler, mw := splitHandlers(tc.framework, tc.args)
		if handler != tc.handler || strings.Join(mw, ",") != tc.mw {
			t.Errorf("%s %v: handler=%q mw=%v", tc.framework, tc.args, handler, mw)
		}
	}
}

// TestPrefixAppliesOnSegmentBoundary pins Fiber's Use("/x", mw): it covers the
// prefix itself and deeper paths, never a longer segment with the same start.
func TestPrefixAppliesOnSegmentBoundary(t *testing.T) {
	cases := []struct {
		prefix, path string
		want         bool
	}{
		{"", "/transfer", true},
		{"/admin", "/admin", true},
		{"/admin", "/admin/users", true},
		{"/admin", "/administrators", false},
		{"/admin", "/transfer", false},
	}
	for _, tc := range cases {
		if got := prefixApplies(tc.prefix, tc.path); got != tc.want {
			t.Errorf("prefixApplies(%q, %q) = %v, want %v", tc.prefix, tc.path, got, tc.want)
		}
	}
}

// TestGoBindingsStayInDeclaringScope pins T23: a group resolved in one
// function must not decide a route that receives a router parameter in
// another function.
func TestGoBindingsStayInDeclaringScope(t *testing.T) {
	dir := t.TempDir()
	src := `package main

import "github.com/gin-gonic/gin"

func protectedServer() *gin.Engine {
	r := gin.New()
	g := r.Group("/api", AuthMiddleware())
	g.POST("/orders", createOrder)
	return r
}

func mount(g *gin.RouterGroup) {
	g.POST("/transfer", transferFunds)
}

func createOrder(c *gin.Context) {}
func transferFunds(c *gin.Context) {}
func AuthMiddleware() gin.HandlerFunc { return nil }
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	facts := []Fact{
		{Kind: "import", File: "main.go", Line: 3, Metavars: map[string]string{"$IMPORT": "github.com/gin-gonic/gin"}},
		{Kind: "engine", File: "main.go", Line: 6, Metavars: map[string]string{"$R": "r"}},
		{Kind: "group", File: "main.go", Line: 7, Metavars: map[string]string{
			"$G": "g", "$BASE": "r", "$PREFIX": "/api", "$A1": "AuthMiddleware()",
		}},
		{Kind: "route", File: "main.go", Line: 8, Metavars: map[string]string{
			"$R": "g", "$VERB": "POST", "$PATH": "/orders", "$A1": "createOrder",
		}},
		{Kind: "route", File: "main.go", Line: 13, Metavars: map[string]string{
			"$R": "g", "$VERB": "POST", "$PATH": "/transfer", "$A1": "transferFunds",
		}},
	}
	routes, _ := resolveGo(facts, dir, defaultGates)
	got := map[string]Protection{}
	for _, route := range routes {
		got[route.Path] = route.Protection
	}
	if got["/api/orders"] != ProtAuthenticated {
		t.Errorf("/api/orders: %q, want authenticated", got["/api/orders"])
	}
	if got["/transfer"] != ProtUnknown {
		t.Errorf("/transfer: %q, want unknown (router parameter is not mounted in this file)", got["/transfer"])
	}
}
