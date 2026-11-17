package endpoints

import (
	"strings"
	"testing"
)

func goFact(kind, file string, line int, vars map[string]string) Fact {
	return Fact{Kind: kind, File: file, Line: line, Metavars: vars}
}

// TestGoCallersWithSamePathDifferentMiddleware: one function registered from
// two callers gives one route per caller, except when both callers end on the
// same path with different middleware, which cannot be decided.
func TestGoCallersWithSamePathDifferentMiddleware(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": "module example.com/svc\n",
		"main.go": `package main

import (
	"github.com/gofiber/fiber/v2"

	"example.com/svc/api"
)

func main() {
	app := fiber.New()
	open := app.Group("/v1")
	locked := app.Group("/v1", requireToken)
	staff := app.Group("/staff", requireToken)
	api.Register(open)
	api.Register(locked)
	api.Register(staff)
}
`,
		"api/api.go": `package api

import "github.com/gofiber/fiber/v2"

func Register(grp fiber.Router) {
	grp.Post("/transfer", transfer)
}
`,
	})
	fiberImport := map[string]string{"$IMPORT": "github.com/gofiber/fiber/v2"}
	facts := []Fact{
		goFact("import", "main.go", 4, fiberImport),
		goFact("engine", "main.go", 10, map[string]string{"$R": "app"}),
		goFact("group", "main.go", 11, map[string]string{"$G": "open", "$BASE": "app", "$PREFIX": "/v1"}),
		goFact("group", "main.go", 12, map[string]string{"$G": "locked", "$BASE": "app", "$PREFIX": "/v1", "$A1": "requireToken"}),
		goFact("group", "main.go", 13, map[string]string{"$G": "staff", "$BASE": "app", "$PREFIX": "/staff", "$A1": "requireToken"}),
		goFact("import", "api/api.go", 3, fiberImport),
		goFact("route", "api/api.go", 6, map[string]string{"$R": "grp", "$METHOD": "Post", "$PATH": "/transfer", "$A1": "transfer"}),
	}
	routes, unresolved := resolveGo(facts, root, defaultGates)
	got := map[string]Protection{}
	for _, r := range routes {
		got[r.Path] = r.Protection
	}
	want := map[string]Protection{"/v1/transfer": ProtUnknown, "/staff/transfer": ProtAuthenticated}
	if len(got) != len(want) || got["/v1/transfer"] != want["/v1/transfer"] || got["/staff/transfer"] != want["/staff/transfer"] {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	if len(unresolved) != 1 || !strings.Contains(unresolved[0], "the calls to Register pass routers with different prefixes or middleware") {
		t.Errorf("unresolved = %v", unresolved)
	}
}

func TestGoDefaultPkgName(t *testing.T) {
	cases := map[string]string{
		"github.com/gofiber/fiber/v2":   "fiber",
		"example.com/shop/internal/api": "api",
		"example.com/x/my-pkg":          "my_pkg",
	}
	for in, want := range cases {
		if got := goDefaultPkgName(in); got != want {
			t.Errorf("goDefaultPkgName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGoImportDirFollowsNestedModules(t *testing.T) {
	root := writeTree(t, map[string]string{
		"svc/go.mod":          "module example.com/svc\n",
		"svc/cmd/main.go":     "package main\n",
		"svc/internal/x/x.go": "package x\n",
	})
	p := newGoProject(root, defaultGates)
	if got := p.importDir("svc/cmd/main.go", "example.com/svc/internal/x"); got != "svc/internal/x" {
		t.Errorf("importDir = %q, want svc/internal/x", got)
	}
	if got := p.importDir("svc/cmd/main.go", "github.com/gofiber/fiber/v2"); got != "" {
		t.Errorf("a package outside the module resolved to %q", got)
	}
}
