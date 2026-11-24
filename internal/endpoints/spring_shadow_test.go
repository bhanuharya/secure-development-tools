package endpoints

import (
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
)

func TestResolveSpringSingleStarMatcherDepthShadow(t *testing.T) {
	facts := []Fact{
		{
			Kind: "security_chain", File: "SecurityConfig.java", Line: 5, EndLine: 14,
			Metavars: map[string]string{"$HTTP": "http"},
		},
		{
			Kind: "security_matcher", File: "SecurityConfig.java", Line: 8, Column: 13,
			Metavars: map[string]string{
				"$MATCHER": "antMatchers",
				"$PATTERN": "/api/admin/*",
				"$ACCESS":  "hasRole",
				"$...ARGS": `"ADMIN"`,
			},
		},
		{
			Kind: "security_matcher", File: "SecurityConfig.java", Line: 9, Column: 13,
			Metavars: map[string]string{
				"$MATCHER": "antMatchers",
				"$PATTERN": "/api/public/*",
				"$ACCESS":  "permitAll",
			},
		},
		{
			Kind: "security_default", File: "SecurityConfig.java", Line: 10, Column: 13,
			Metavars: map[string]string{
				"$DEFAULT": "anyRequest",
				"$ACCESS":  "authenticated",
			},
		},
		{
			Kind: "route", File: "AdminController.java", Line: 10, EndLine: 12,
			Metavars: map[string]string{
				"$C":    "AdminController",
				"$VERB": "GetMapping",
				"$PATH": "/api/admin/users",
				"$M":    "listUsers",
			},
		},
		{
			Kind: "route", File: "AdminController.java", Line: 14, EndLine: 16,
			Metavars: map[string]string{
				"$C":    "AdminController",
				"$VERB": "GetMapping",
				"$PATH": "/api/admin/users/export",
				"$M":    "exportUsers",
			},
		},
		{
			Kind: "route", File: "AdminController.java", Line: 18, EndLine: 20,
			Metavars: map[string]string{
				"$C":    "AdminController",
				"$VERB": "GetMapping",
				"$PATH": "/api/public/catalog/items",
				"$M":    "publicNested",
			},
		},
	}

	routes, _ := resolveSpring(facts, "")
	if len(routes) != 3 {
		t.Fatalf("want 3 routes, got %d: %+v", len(routes), routes)
	}
	byPath := map[string]Route{}
	for _, r := range routes {
		byPath[r.Path] = r
	}
	if byPath["/api/admin/users"].Protection != ProtRole || byPath["/api/admin/users"].ShadowedBy != "" {
		t.Fatalf("single-segment admin route should match directly: %+v", byPath["/api/admin/users"])
	}
	nested := byPath["/api/admin/users/export"]
	if nested.Protection != ProtAuthenticated || !strings.Contains(nested.ShadowedBy, `"/api/admin/*"`) {
		t.Fatalf("nested admin route should be shadowed by single-star matcher: %+v", nested)
	}
	if byPath["/api/public/catalog/items"].ShadowedBy != "" {
		t.Fatalf("weaker single-star matcher must not shadow stricter fallback: %+v", byPath["/api/public/catalog/items"])
	}

	inv := &Inventory{Schema: Schema, Root: ".", Routes: routes}
	fs, err := Analyze(inv, config.Defaults().Endpoints)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(fs) != 1 || fs[0].Rule.ID != RuleSpringMatcherDepthMismatch {
		t.Fatalf("want 1 matcher-depth-mismatch finding, got %+v", fs)
	}
	if fs[0].Confidence != "high" || !strings.Contains(fs[0].Message, "/api/admin/*") {
		t.Fatalf("unexpected finding details: %+v", fs[0])
	}
}

func TestResolveSpringChainScopeSingleStarShadow(t *testing.T) {
	facts := []Fact{
		{
			Kind: "security_chain", File: "SecurityConfig.java", Line: 5, EndLine: 15,
			Metavars: map[string]string{"$HTTP": "http"},
		},
		{
			Kind: "security_scope", File: "SecurityConfig.java", Line: 7, Column: 9,
			Metavars: map[string]string{
				"$SCOPE":   "securityMatcher",
				"$OWNER":   "http",
				"$...ARGS": `"/api/internal/*"`,
			},
		},
		{
			Kind: "security_default", File: "SecurityConfig.java", Line: 9, Column: 9,
			Metavars: map[string]string{
				"$DEFAULT": "anyRequest",
				"$ACCESS":  "hasRole",
				"$...ARGS": `"INTERNAL"`,
			},
		},
		{
			Kind: "route", File: "InternalController.java", Line: 10, EndLine: 12,
			Metavars: map[string]string{
				"$C":    "InternalController",
				"$VERB": "GetMapping",
				"$PATH": "/api/internal/v2/export",
				"$M":    "exportData",
			},
		},
	}

	routes, _ := resolveSpring(facts, "")
	if len(routes) != 1 {
		t.Fatalf("want 1 route, got %d", len(routes))
	}
	if routes[0].Protection != ProtPublic {
		t.Fatalf("route outside single-star scope should be public, got %s", routes[0].Protection)
	}
	if !strings.Contains(routes[0].ShadowedBy, `"/api/internal/*"`) {
		t.Fatalf("expected ShadowedBy to cite single-star chain scope, got %q", routes[0].ShadowedBy)
	}
}
