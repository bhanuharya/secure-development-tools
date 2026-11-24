package endpoints_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func TestAnalyzeStateChangeOnGetOrAny(t *testing.T) {
	fs := analyzeDefault(t,
		testRoute("GET", "/api/orders/{id}/delete", endpoints.ProtAuthenticated, 10, testGate),
		testRoute("ANY", "/api/sessions/{id}/revoke", endpoints.ProtAuthenticated, 11, testGate),
		// Safe look-alikes: proper mutating verb, read-only noun suffix, or denied.
		testRoute("POST", "/api/orders/{id}/delete", endpoints.ProtAuthenticated, 12, testGate),
		testRoute("DELETE", "/api/orders/{id}", endpoints.ProtAuthenticated, 13, testGate),
		testRoute("GET", "/api/transfers/history", endpoints.ProtAuthenticated, 14, testGate),
		testRoute("GET", "/api/refund/policy", endpoints.ProtAuthenticated, 15, testGate),
		testRoute("GET", "/api/reset-password/form", endpoints.ProtAuthenticated, 16, testGate),
		testRoute("GET", "/api/orders/{id}/approve", endpoints.ProtDenied, 17, "denyAll"),
	)
	if len(fs) != 2 {
		t.Fatalf("want 2 verb-tampering findings, got %d: %+v", len(fs), fs)
	}
	if fs[0].Rule.ID != endpoints.RuleStateChangeOnGetOrAny || *fs[0].Location.StartLine != 10 {
		t.Fatalf("first finding = %+v", fs[0])
	}
	if fs[1].Rule.ID != endpoints.RuleStateChangeOnGetOrAny || *fs[1].Location.StartLine != 11 {
		t.Fatalf("second finding = %+v", fs[1])
	}
	if !strings.Contains(fs[0].Message, "CSRF") || !strings.Contains(fs[1].Message, "HttpMethod.POST") {
		t.Fatalf("unexpected messages: %q / %q", fs[0].Message, fs[1].Message)
	}
}

func TestAnalyzeWithRootBOLA_SpringGoExpressPython(t *testing.T) {
	dir := t.TempDir()

	// 1. Spring MVC service with one vulnerable handler and one safe peer handler.
	mustWriteFile(t, filepath.Join(dir, "svc-java", "OrderController.java"), `package com.example;
public class OrderController {
    @GetMapping("/api/orders/{orderId}")
    public Order getOrder(@PathVariable String orderId) {
        return orderRepo.findById(orderId).orElseThrow();
    }

    @GetMapping("/api/invoices/{invoiceId}")
    public Invoice getInvoice(@PathVariable String invoiceId, Principal principal) {
        return invoiceRepo.findByIdAndUserId(invoiceId, principal.getName()).orElseThrow();
    }

    @DeleteMapping("/api/admin/orders/{orderId}")
    public void adminDelete(@PathVariable String orderId) {
        orderRepo.deleteById(orderId);
    }
}
`)

	// 2. Go service with named handler in sibling file, safe scoped handler, and inline closure.
	mustWriteFile(t, filepath.Join(dir, "svc-go", "routes.go"), `package main
func register(api Router) {
	api.GET("/api/accounts/:accountId", getAccount)
	api.GET("/api/profiles/:profileId", getProfile)
	api.DELETE("/api/cards/:cardId", func(c *gin.Context) {
		db.Delete(&Card{}, c.Param("cardId"))
	})
	api.GET("/api/docs/:version", getDocs)
}
`)
	mustWriteFile(t, filepath.Join(dir, "svc-go", "handlers.go"), `package main
func getAccount(c *gin.Context) {
	var acc Account
	db.First(&acc, c.Param("accountId"))
	c.JSON(200, acc)
}

func getProfile(c *gin.Context) {
	uid := c.Get("userID")
	var prof Profile
	db.Where("id = ? AND user_id = ?", c.Param("profileId"), uid).First(&prof)
	c.JSON(200, prof)
}

func getDocs(c *gin.Context) {
	db.First(&Doc{}, c.Param("version"))
}
`)

	// 3. Express service with vulnerable inline arrow and safe req.user handler.
	mustWriteFile(t, filepath.Join(dir, "svc-js", "orders.js"), `router.get('/api/tickets/:ticketId', async (req, res) => {
  const t = await prisma.ticket.findUnique({ where: { id: req.params.ticketId } });
  res.json(t);
});
router.get('/api/messages/:messageId', async (req, res) => {
  const m = await prisma.message.findFirst({ where: { id: req.params.messageId, ownerId: req.user.id } });
  res.json(m);
});
`)

	// 4. FastAPI service with vulnerable handler and safe current_user handler.
	mustWriteFile(t, filepath.Join(dir, "svc-py", "routes.py"), `@router.get("/api/wallets/{wallet_id}")
def get_wallet(wallet_id: int, db: Session = Depends(get_db)):
    return db.query(Wallet).filter(Wallet.id == wallet_id).first()

@router.get("/api/loans/{loan_id}")
def get_loan(loan_id: int, current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Loan).filter(Loan.id == loan_id, Loan.user_id == current_user.id).first()
`)

	inv := &endpoints.Inventory{
		Schema: endpoints.Schema,
		Root:   ".",
		Routes: []endpoints.Route{
			// Spring
			{Service: "svc-java", Framework: "spring-mvc", Method: "GET", Path: "/api/orders/{orderId}", Handler: "OrderController.getOrder", File: "svc-java/OrderController.java", Line: 3, Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high"},
			{Service: "svc-java", Framework: "spring-mvc", Method: "GET", Path: "/api/invoices/{invoiceId}", Handler: "OrderController.getInvoice", File: "svc-java/OrderController.java", Line: 8, Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high"},
			{Service: "svc-java", Framework: "spring-mvc", Method: "DELETE", Path: "/api/admin/orders/{orderId}", Handler: "OrderController.adminDelete", File: "svc-java/OrderController.java", Line: 13, Protection: endpoints.ProtRole, Roles: []string{"ADMIN"}, Evidence: []string{"role"}, Confidence: "high"},
			// Go
			{Service: "svc-go", Framework: "gin", Method: "GET", Path: "/api/accounts/{accountId}", Handler: "getAccount", File: "svc-go/routes.go", Line: 3, Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high"},
			{Service: "svc-go", Framework: "gin", Method: "GET", Path: "/api/profiles/{profileId}", Handler: "getProfile", File: "svc-go/routes.go", Line: 4, Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high"},
			{Service: "svc-go", Framework: "gin", Method: "DELETE", Path: "/api/cards/{cardId}", Handler: "func", File: "svc-go/routes.go", Line: 5, Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high"},
			{Service: "svc-go", Framework: "gin", Method: "GET", Path: "/api/docs/{version}", Handler: "getDocs", File: "svc-go/routes.go", Line: 8, Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high"},
			// Express
			{Service: "svc-js", Framework: "express", Method: "GET", Path: "/api/tickets/{ticketId}", Handler: "inline", File: "svc-js/orders.js", Line: 1, Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high"},
			{Service: "svc-js", Framework: "express", Method: "GET", Path: "/api/messages/{messageId}", Handler: "inline", File: "svc-js/orders.js", Line: 5, Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high"},
			// FastAPI
			{Service: "svc-py", Framework: "fastapi", Method: "GET", Path: "/api/wallets/{wallet_id}", Handler: "get_wallet", File: "svc-py/routes.py", Line: 1, Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high"},
			{Service: "svc-py", Framework: "fastapi", Method: "GET", Path: "/api/loans/{loan_id}", Handler: "get_loan", File: "svc-py/routes.py", Line: 5, Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high"},
			// Path-escape attempt must fail closed (stay silent, never read outside root)
			{Service: "svc-go", Framework: "gin", Method: "GET", Path: "/api/escape/{id}", Handler: "getAccount", File: "../outside.go", Line: 1, Protection: endpoints.ProtAuthenticated, Evidence: []string{"auth"}, Confidence: "high"},
		},
	}

	fs, err := endpoints.AnalyzeWithRoot(dir, inv, config.Defaults().Endpoints)
	if err != nil {
		t.Fatalf("AnalyzeWithRoot: %v", err)
	}

	gotByEndpoint := map[string]*finding.Finding{}
	for _, f := range fs {
		if f.Rule.ID != endpoints.RuleBolaUnscopedObjectAccess {
			t.Fatalf("unexpected non-BOLA finding: %+v", f)
		}
		ep, _ := f.Metadata["endpoint"].(string)
		gotByEndpoint[ep] = f
	}

	wantFlagged := []string{
		"GET /api/orders/{orderId}",
		"GET /api/accounts/{accountId}",
		"DELETE /api/cards/{cardId}",
		"GET /api/tickets/{ticketId}",
		"GET /api/wallets/{wallet_id}",
	}
	if len(gotByEndpoint) != len(wantFlagged) {
		t.Fatalf("want %d BOLA findings, got %d: %+v", len(wantFlagged), len(gotByEndpoint), gotByEndpoint)
	}
	for _, ep := range wantFlagged {
		f, ok := gotByEndpoint[ep]
		if !ok {
			t.Errorf("missing expected BOLA finding for %s", ep)
			continue
		}
		if f.Confidence != "high" {
			t.Errorf("%s: want high confidence (service has bound peer), got %q", ep, f.Confidence)
		}
		if !strings.Contains(f.Message, "Peer handler") {
			t.Errorf("%s: expected peer handler reference in message: %s", ep, f.Message)
		}
	}
}

func TestCompareProtectionRegressions(t *testing.T) {
	prevInv := testInventory(
		endpoints.Route{Service: ".", Method: "DELETE", Path: "/api/admin/users/{id}", File: "main.go", Line: 10, Protection: endpoints.ProtRole, Roles: []string{"ADMIN"}, Confidence: "high"},
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/orders", File: "main.go", Line: 11, Protection: endpoints.ProtAuthenticated, Confidence: "high"},
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/audit/export", File: "main.go", Line: 12, Protection: endpoints.ProtRole, Roles: []string{"ADMIN"}, Confidence: "high"},
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/billing/refund", File: "main.go", Line: 13, Protection: endpoints.ProtRole, Roles: []string{"ADMIN", "USER"}, Confidence: "high"},
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/roles/swap", File: "main.go", Line: 14, Protection: endpoints.ProtRole, Roles: []string{"ADMIN"}, Confidence: "high"},
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/roles/drop", File: "main.go", Line: 15, Protection: endpoints.ProtRole, Roles: []string{"ADMIN"}, Confidence: "high"},
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/roles/add", File: "main.go", Line: 16, Protection: endpoints.ProtRole, Roles: nil, Confidence: "high"},
		endpoints.Route{Service: ".", Method: "GET", Path: "/api/public/ping", File: "main.go", Line: 17, Protection: endpoints.ProtPublic, Confidence: "high"},
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/unknown/op", File: "main.go", Line: 18, Protection: endpoints.ProtUnknown, Confidence: "low"},
		endpoints.Route{Service: ".", Method: "GET", Path: "/api/internal/metrics", File: "main.go", Line: 19, Protection: endpoints.ProtDenied, Confidence: "high"},
	)

	curInv := testInventory(
		// 1. Downgraded role -> authenticated (FLAG)
		endpoints.Route{Service: ".", Method: "DELETE", Path: "/api/admin/users/{id}", File: "main.go", Line: 10, Protection: endpoints.ProtAuthenticated, Confidence: "high"},
		// 2. Downgraded authenticated -> public (FLAG)
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/orders", File: "main.go", Line: 11, Protection: endpoints.ProtPublic, Confidence: "high"},
		// 3. Widened roles [ADMIN] -> [ADMIN, SUPPORT] (FLAG)
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/audit/export", File: "main.go", Line: 12, Protection: endpoints.ProtRole, Roles: []string{"ADMIN", "SUPPORT"}, Confidence: "high"},
		// Narrowed roles [ADMIN, USER] -> [ADMIN] (must NOT flag)
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/billing/refund", File: "main.go", Line: 13, Protection: endpoints.ProtRole, Roles: []string{"ADMIN"}, Confidence: "high"},
		// 4. Replaced with newly allowed role [ADMIN] -> [SUPPORT] (FLAG)
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/roles/swap", File: "main.go", Line: 14, Protection: endpoints.ProtRole, Roles: []string{"SUPPORT"}, Confidence: "high"},
		// 5. Dropped explicit role list [ADMIN] -> [] (FLAG)
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/roles/drop", File: "main.go", Line: 15, Protection: endpoints.ProtRole, Roles: nil, Confidence: "high"},
		// Added explicit role list [] -> [ADMIN] (must NOT flag)
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/roles/add", File: "main.go", Line: 16, Protection: endpoints.ProtRole, Roles: []string{"ADMIN"}, Confidence: "high"},
		// Strengthened public -> authenticated (must NOT flag)
		endpoints.Route{Service: ".", Method: "GET", Path: "/api/public/ping", File: "main.go", Line: 17, Protection: endpoints.ProtAuthenticated, Confidence: "high"},
		// Unknown -> public (uncertainty must NOT flag)
		endpoints.Route{Service: ".", Method: "POST", Path: "/api/unknown/op", File: "main.go", Line: 18, Protection: endpoints.ProtPublic, Confidence: "high"},
		// Denied -> unknown (uncertainty must NOT flag)
		endpoints.Route{Service: ".", Method: "GET", Path: "/api/internal/metrics", File: "main.go", Line: 19, Protection: endpoints.ProtUnknown, Confidence: "low"},
	)

	regs := endpoints.CompareProtection(endpoints.Snapshot(prevInv), curInv)
	if len(regs) != 5 {
		t.Fatalf("want 5 protection regressions, got %d: %+v", len(regs), regs)
	}
	for _, f := range regs {
		if f.Rule.ID != endpoints.RuleProtectionDowngraded {
			t.Errorf("wrong rule id: %s", f.Rule.ID)
		}
		if f.Severity.Canonical != finding.SevHigh {
			t.Errorf("regression must be high severity, got %s", f.Severity.Canonical)
		}
		if f.BaselineState != finding.StateNew {
			t.Errorf("regression must be BaselineState=new, got %s", f.BaselineState)
		}
		if f.Confidence != "high" {
			t.Errorf("regression must be high confidence, got %s", f.Confidence)
		}
		if ep, _ := f.Metadata["endpoint"].(string); ep == "POST /api/billing/refund" {
			t.Errorf("narrowing roles [ADMIN, USER] -> [ADMIN] must not be reported as a regression")
		}
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
