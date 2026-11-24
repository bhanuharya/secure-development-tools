package endpoints_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
)

func TestParseInvariantsValidationFailsClosed(t *testing.T) {
	badCases := map[string]string{
		"unknown field": `
apiVersion: secure-dev/invariants/v1alpha1
kind: SecurityInvariants
bogusKey: true
`,
		"wrong apiVersion": `
apiVersion: secure-dev/invariants/v99
kind: SecurityInvariants
`,
		"duplicate id": `
apiVersion: secure-dev/invariants/v1alpha1
kind: SecurityInvariants
routeInvariants:
  - id: dup
    paths: ["/api/**"]
  - id: dup
    paths: ["/admin/**"]
`,
		"invalid minProtection": `
apiVersion: secure-dev/invariants/v1alpha1
kind: SecurityInvariants
routeInvariants:
  - id: bad-prot
    paths: ["/api/**"]
    minProtection: supersecret
`,
		"relative path": `
apiVersion: secure-dev/invariants/v1alpha1
kind: SecurityInvariants
routeInvariants:
  - id: rel-path
    paths: ["api/**"]
`,
		"bad evidence regex": `
apiVersion: secure-dev/invariants/v1alpha1
kind: SecurityInvariants
routeInvariants:
  - id: bad-re
    paths: ["/api/**"]
    requireEvidence: ["[unclosed"]
`,
	}
	for name, raw := range badCases {
		t.Run(name, func(t *testing.T) {
			if _, err := endpoints.ParseInvariants([]byte(raw), "test.yaml"); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestAnalyzeWithRootEnforcesSecurityInvariantsAndBlocksPolicy(t *testing.T) {
	dir := t.TempDir()

	// Write .secure-dev/invariants.yaml
	mustWriteFile(t, filepath.Join(dir, endpoints.RepoInvariantsFile), `
apiVersion: secure-dev/invariants/v1alpha1
kind: SecurityInvariants
routeInvariants:
  - id: ledger-role-and-idempotency
    description: Ledger mutations require LEDGER_WRITER role, no GET, and idempotency middleware.
    paths: ["/api/v1/ledger/**"]
    forbidMethods: [GET, ANY]
    minProtection: role
    requireRoles: [LEDGER_WRITER, FINANCE_ADMIN]
    requireEvidence: ["Idempotency"]
    severity: error
    cwe: ["CWE-862", "CWE-841"]
  - id: orders-require-principal
    paths: ["/api/v1/orders/**"]
    minProtection: authenticated
    requirePrincipalCheck: true
    severity: error
    cwe: ["CWE-639"]
`)

	// Write handler file: one handler delegates without touching caller principal, one binds principal.
	mustWriteFile(t, filepath.Join(dir, "handlers.go"), `package main
func getOrderNoPrincipal(c *gin.Context) {
	c.JSON(200, service.FetchOrder(c.Param("orderId")))
}
func getOrderWithPrincipal(c *gin.Context) {
	uid := c.Get("userID")
	c.JSON(200, service.FetchOrderForUser(c.Param("orderId"), uid))
}
`)

	inv := &endpoints.Inventory{
		Schema: endpoints.Schema,
		Root:   ".",
		Routes: []endpoints.Route{
			// Violates ledger invariant: wrong role + missing Idempotency evidence
			{
				Service: ".", Framework: "gin", Method: "POST", Path: "/api/v1/ledger/payout",
				Handler: "createPayout", File: "handlers.go", Line: 10,
				Protection: endpoints.ProtRole, Roles: []string{"SUPPORT"},
				Evidence: []string{`routes.go:4 middleware RequireRole("SUPPORT")`}, Confidence: "high",
			},
			// Satisfies ledger invariant completely
			{
				Service: ".", Framework: "gin", Method: "POST", Path: "/api/v1/ledger/transfer",
				Handler: "createTransfer", File: "handlers.go", Line: 11,
				Protection: endpoints.ProtRole, Roles: []string{"LEDGER_WRITER"},
				Evidence: []string{`routes.go:5 middleware RequireRole("LEDGER_WRITER")`, `routes.go:6 middleware IdempotencyKey`}, Confidence: "high",
			},
			// Violates orders-require-principal (opaque service call wouldn't trigger heuristic BOLA,
			// but explicit repo invariant catches missing caller principal!)
			{
				Service: ".", Framework: "gin", Method: "GET", Path: "/api/v1/orders/{orderId}",
				Handler: "getOrderNoPrincipal", File: "handlers.go", Line: 2,
				Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high",
			},
			// Satisfies orders-require-principal
			{
				Service: ".", Framework: "gin", Method: "GET", Path: "/api/v1/orders/{orderId}/receipt",
				Handler: "getOrderWithPrincipal", File: "handlers.go", Line: 5,
				Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high",
			},
		},
	}

	fs, err := endpoints.AnalyzeWithRoot(dir, inv, config.Defaults().Endpoints)
	if err != nil {
		t.Fatalf("AnalyzeWithRoot: %v", err)
	}
	var invFindings []*finding.Finding
	for _, f := range fs {
		if f.Rule.ID == endpoints.RuleInvariantViolated {
			f.BaselineState = finding.StateNew
			invFindings = append(invFindings, f)
		}
	}
	if len(invFindings) != 2 {
		t.Fatalf("want 2 invariant findings, got %d: %+v", len(invFindings), invFindings)
	}
	if !strings.Contains(invFindings[0].Message, "orders-require-principal") {
		t.Errorf("expected orders-require-principal violation first (line 2), got: %s", invFindings[0].Message)
	}
	if !strings.Contains(invFindings[1].Message, "ledger-role-and-idempotency") || !strings.Contains(invFindings[1].Message, "Idempotency") {
		t.Errorf("expected ledger-role-and-idempotency violation citing Idempotency, got: %s", invFindings[1].Message)
	}

	// Verify invariant breaches (severity=error -> canonical high, baselineState=new) block default policy.
	out := policy.Evaluate(config.Defaults(), invFindings)
	if out.Status != "policy_failed" || len(out.Blockers) != 2 {
		t.Fatalf("expected 2 policy blockers, got status=%s blockers=%d", out.Status, len(out.Blockers))
	}
}

func TestExampleInvariantsFileParsesCleanly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".secure-dev", "invariants.yaml.example"))
	if err != nil {
		t.Fatalf("read example invariants: %v", err)
	}
	doc, err := endpoints.ParseInvariants(raw, ".secure-dev/invariants.yaml.example")
	if err != nil {
		t.Fatalf("example invariants must validate cleanly: %v", err)
	}
	if len(doc.RouteInvariants) == 0 || len(doc.DomainInvariants) == 0 {
		t.Fatalf("example invariants should include both routeInvariants and domainInvariants")
	}
}
