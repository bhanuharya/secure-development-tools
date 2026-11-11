package endpoints_test

import (
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

const testGate = "main.go:9 middleware AuthMiddleware on group /api"

func testRoute(method, path string, p endpoints.Protection, line int, evidence ...string) endpoints.Route {
	return endpoints.Route{
		Service: ".", Framework: "gin", Method: method, Path: path,
		File: "main.go", Line: line, Protection: p, Evidence: evidence, Confidence: "high",
	}
}

func testInventory(routes ...endpoints.Route) *endpoints.Inventory {
	return &endpoints.Inventory{Schema: endpoints.Schema, Root: ".", Routes: routes}
}

func analyzeDefault(t *testing.T, routes ...endpoints.Route) []*finding.Finding {
	t.Helper()
	fs, err := endpoints.Analyze(testInventory(routes...), config.Defaults().Endpoints)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return fs
}

func TestAnalyzeUnprotectedAmongProtected(t *testing.T) {
	fs := analyzeDefault(t,
		testRoute("POST", "/api/orders", endpoints.ProtAuthenticated, 10, testGate),
		testRoute("PUT", "/api/orders/{id}", endpoints.ProtAuthenticated, 11, testGate),
		testRoute("PATCH", "/api/orders/{id}", endpoints.ProtAuthenticated, 12, testGate),
		testRoute("DELETE", "/api/orders/{id}", endpoints.ProtAuthenticated, 13, testGate),
		testRoute("POST", "/api/accounts", endpoints.ProtAuthenticated, 14, testGate),
		testRoute("POST", "/api/notes", endpoints.ProtPublic, 20),
	)
	if len(fs) != 1 || fs[0].Rule.ID != endpoints.RuleUnprotectedAmongProtected {
		t.Fatalf("want one rule-1 finding, got %+v", fs)
	}
	if !strings.Contains(fs[0].Message, testGate) {
		t.Fatalf("message does not name the peers' gate: %s", fs[0].Message)
	}
	if got := fs[0].Metadata["endpoint"]; got != "POST /api/notes" {
		t.Fatalf("metadata endpoint = %v", got)
	}
}

func TestAnalyzeThresholdsAndPublicOverride(t *testing.T) {
	routes := []endpoints.Route{
		testRoute("POST", "/api/orders", endpoints.ProtAuthenticated, 10, testGate),
		testRoute("PUT", "/api/orders/{id}", endpoints.ProtAuthenticated, 11, testGate),
		testRoute("PATCH", "/api/orders/{id}", endpoints.ProtAuthenticated, 12, testGate),
		testRoute("DELETE", "/api/orders/{id}", endpoints.ProtAuthenticated, 13, testGate),
		testRoute("POST", "/api/accounts", endpoints.ProtAuthenticated, 14, testGate),
		testRoute("POST", "/api/notes", endpoints.ProtPublic, 20),
	}
	cfg := config.Defaults().Endpoints
	cfg.PublicPaths = []string{`^/api/notes$`}
	if fs, err := endpoints.Analyze(testInventory(routes...), cfg); err != nil || len(fs) != 0 {
		t.Fatalf("public override must silence rule 1: %v %+v", err, fs)
	}
	cfg = config.Defaults().Endpoints
	cfg.MinRoutes = 7
	if fs, err := endpoints.Analyze(testInventory(routes...), cfg); err != nil || len(fs) != 0 {
		t.Fatalf("minRoutes must gate rule 1: %v %+v", err, fs)
	}
	cfg = config.Defaults().Endpoints
	cfg.Majority = 1
	if fs, err := endpoints.Analyze(testInventory(routes...), cfg); err != nil || len(fs) != 0 {
		t.Fatalf("majority must gate rule 1: %v %+v", err, fs)
	}
}

func TestAnalyzeSensitiveRules(t *testing.T) {
	fs := analyzeDefault(t,
		testRoute("DELETE", "/api/admin/sessions", endpoints.ProtRole, 18,
			`main.go:18 middleware RequireRole("admin") on group /admin`,
			"main.go:9 middleware AuthMiddleware on group /api"),
		testRoute("PUT", "/api/admin/roles/{id}", endpoints.ProtAuthenticated, 24,
			"main.go:24 middleware AuthMiddleware"),
		testRoute("GET", "/api/admin/users", endpoints.ProtPublic, 23),
	)
	if len(fs) != 2 {
		t.Fatalf("want rule 2 and rule 3, got %+v", fs)
	}
	if fs[0].Rule.ID != endpoints.RuleSensitiveRoutePublic || *fs[0].Location.StartLine != 23 {
		t.Fatalf("first finding = %+v", fs[0])
	}
	if fs[1].Rule.ID != endpoints.RuleSensitiveRouteWithoutRole || *fs[1].Location.StartLine != 24 {
		t.Fatalf("second finding = %+v", fs[1])
	}
	if !strings.Contains(fs[1].Message, "RequireRole") {
		t.Fatalf("rule 3 message does not name the role gate: %s", fs[1].Message)
	}
}

func TestAnalyzeExtraSensitivePathAndUnknown(t *testing.T) {
	cfg := config.Defaults().Endpoints
	cfg.SensitivePaths = []string{`/payouts`}
	fs, err := endpoints.Analyze(testInventory(
		testRoute("GET", "/api/payouts/rates", endpoints.ProtPublic, 30),
		testRoute("POST", "/api/unknown", endpoints.ProtUnknown, 31),
	), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Rule.ID != endpoints.RuleSensitiveRoutePublic {
		t.Fatalf("want one extra-sensitive finding, got %+v", fs)
	}
	if fs[0].Metadata["protection"] != "public" {
		t.Fatalf("protection metadata = %v", fs[0].Metadata["protection"])
	}
}

func TestAnalyzeMostSevereRuleWins(t *testing.T) {
	fs := analyzeDefault(t,
		testRoute("POST", "/api/orders", endpoints.ProtAuthenticated, 10, testGate),
		testRoute("PUT", "/api/orders/{id}", endpoints.ProtAuthenticated, 11, testGate),
		testRoute("PATCH", "/api/orders/{id}", endpoints.ProtAuthenticated, 12, testGate),
		testRoute("DELETE", "/api/orders/{id}", endpoints.ProtAuthenticated, 13, testGate),
		testRoute("POST", "/api/accounts", endpoints.ProtAuthenticated, 14, testGate),
		testRoute("POST", "/api/funds/transfer", endpoints.ProtPublic, 20),
	)
	if len(fs) != 1 || fs[0].Rule.ID != endpoints.RuleSensitiveRoutePublic {
		t.Fatalf("public transfer must be the ERROR, not rule 1: %+v", fs)
	}
	if got := fs[0].Metadata["endpoint"]; got != "POST /api/funds/transfer" {
		t.Fatalf("metadata endpoint = %v", got)
	}
}

func TestAnalyzePublicByDesignSkipsOnlyRuleOne(t *testing.T) {
	fs := analyzeDefault(t,
		testRoute("POST", "/api/orders", endpoints.ProtAuthenticated, 10, testGate),
		testRoute("PUT", "/api/orders/{id}", endpoints.ProtAuthenticated, 11, testGate),
		testRoute("PATCH", "/api/orders/{id}", endpoints.ProtAuthenticated, 12, testGate),
		testRoute("DELETE", "/api/orders/{id}", endpoints.ProtAuthenticated, 13, testGate),
		testRoute("POST", "/api/accounts", endpoints.ProtAuthenticated, 14, testGate),
		testRoute("POST", "/api/v1/registration", endpoints.ProtPublic, 20),
		testRoute("POST", "/api/v2/registration", endpoints.ProtPublic, 21),
		testRoute("POST", "/registration/validate-account", endpoints.ProtPublic, 22),
		testRoute("POST", "/api/v1/auth/reset-password", endpoints.ProtPublic, 23),
		testRoute("POST", "/api/reports", endpoints.ProtPublic, 24),
	)
	if len(fs) != 2 {
		t.Fatalf("want rule 1 for reports and rule 2 for reset-password, got %+v", fs)
	}
	if fs[0].Rule.ID != endpoints.RuleSensitiveRoutePublic || *fs[0].Location.StartLine != 23 {
		t.Fatalf("public-by-design sensitive path must stay rule 2: %+v", fs[0])
	}
	if fs[1].Rule.ID != endpoints.RuleUnprotectedAmongProtected || *fs[1].Location.StartLine != 24 {
		t.Fatalf("onboarding must not silence rule 1 for other routes: %+v", fs[1])
	}
}

func TestAnalyzeSelfServiceWithoutParameterHasNoFinding(t *testing.T) {
	fs := analyzeDefault(t,
		testRoute("DELETE", "/api/admin/sessions", endpoints.ProtRole, 18,
			`main.go:18 middleware RequireRole("admin") on group /admin`),
		testRoute("POST", "/api/account/change-password", endpoints.ProtAuthenticated, 20, testGate),
		testRoute("POST", "/api/account/update-email", endpoints.ProtAuthenticated, 21, testGate),
		testRoute("POST", "/api/users/{id}/change-password", endpoints.ProtAuthenticated, 22, testGate),
		testRoute("POST", "/api/admin/change-password", endpoints.ProtAuthenticated, 23, testGate),
	)
	if len(fs) != 2 {
		t.Fatalf("want only the two routes that act on another account, got %+v", fs)
	}
	for i, line := range []int{22, 23} {
		if fs[i].Rule.ID != endpoints.RuleSensitiveRouteWithoutRole || *fs[i].Location.StartLine != line {
			t.Fatalf("finding %d = %+v", i, fs[i])
		}
	}
}

func TestAnalyzeRoleRuleNeedsARoleRoute(t *testing.T) {
	fs := analyzeDefault(t,
		testRoute("PUT", "/api/admin/roles/{id}", endpoints.ProtAuthenticated, 24, testGate),
	)
	if len(fs) != 0 {
		t.Fatalf("no role route means no rule 3: %+v", fs)
	}
}
