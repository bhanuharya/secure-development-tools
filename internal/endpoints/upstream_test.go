package endpoints

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
)

func TestUpstreamDeclsFromRepositoryFile(t *testing.T) {
	root := writeTree(t, map[string]string{RepoEndpointsFile: "upstreamAuth:\n" +
		"  - service: orders\n    paths: [\"/api/**\"]\n    by: API gateway (JWT)\n" +
		"  - paths: [\"/internal/**\"]\n"})
	decls, notes := upstreamDecls(root, config.EndpointsCfg{UpstreamAuth: []config.UpstreamAuth{{By: "mesh mTLS"}}})
	if len(decls) != 2 || decls[0].source != "scan configuration endpoints.upstreamAuth" || decls[1].By != "API gateway (JWT)" {
		t.Fatalf("decls = %+v", decls)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], `upstreamAuth[1] not applied: "by" must say`) {
		t.Fatalf("notes = %q", notes)
	}
	if _, notes := upstreamDecls(writeTree(t, map[string]string{RepoEndpointsFile: "upstreamAuth: [\n"}), config.EndpointsCfg{}); len(notes) != 1 {
		t.Fatalf("a broken file must give one note, got %q", notes)
	}
	if decls, notes := upstreamDecls(t.TempDir(), config.EndpointsCfg{}); len(decls) != 0 || len(notes) != 0 {
		t.Fatal("no file, no declarations, no notes")
	}
}

func TestUpstreamAuthCoversByServiceAndPath(t *testing.T) {
	decls := []upstreamDecl{{config.UpstreamAuth{Service: "orders", Paths: []string{"/api/**"}, By: "API gateway"}, RepoEndpointsFile}}
	routes := applyUpstreamAuth([]Route{
		{Service: "orders", Method: "POST", Path: "/api/transfer", Protection: ProtPublic, Evidence: []string{"main.go:9 no gate"}},
		{Service: "orders", Method: "GET", Path: "/health", Protection: ProtPublic},
		{Service: "billing", Method: "POST", Path: "/api/transfer", Protection: ProtPublic},
	}, decls)
	if routes[0].UpstreamAuth != "API gateway" || routes[0].Protection != ProtPublic {
		t.Fatalf("covered route = %+v (protection must stay what the service enforces)", routes[0])
	}
	if got := routes[0].Evidence[len(routes[0].Evidence)-1]; got != ".secure-dev/endpoints.yaml: authenticated upstream by API gateway" {
		t.Fatalf("evidence = %q", got)
	}
	if routes[1].UpstreamAuth != "" || routes[2].UpstreamAuth != "" {
		t.Fatal("other paths and services are not covered")
	}
}

func TestAnalyzeJudgesUpstreamAuthenticatedRoutesAsAuthenticated(t *testing.T) {
	inv := &Inventory{Schema: Schema, Routes: []Route{
		{Service: ".", Method: "POST", Path: "/api/admin/refunds", File: "main.go", Line: 3, Protection: ProtPublic,
			UpstreamAuth: "API gateway", Evidence: []string{"x: authenticated upstream by API gateway"}, Confidence: "high"},
		{Service: ".", Method: "POST", Path: "/api/roles", File: "main.go", Line: 4, Protection: ProtRole,
			Roles: []string{"admin"}, Evidence: []string{"main.go:4 middleware RequireRole(...)"}, Confidence: "high"},
	}}
	findings, err := Analyze(inv, config.EndpointsCfg{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Rule.ID != RuleSensitiveRouteWithoutRole {
		ids := []string{}
		for _, f := range findings {
			ids = append(ids, f.Rule.ID)
		}
		t.Fatalf("findings = %v, want only %s (not sensitive-route-public)", ids, RuleSensitiveRouteWithoutRole)
	}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
