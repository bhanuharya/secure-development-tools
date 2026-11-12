package endpoints_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
)

// TestMiddlewareCredentialsNeverReachInventoryOrFindings is the T30 regression: evidence
// quotes middleware arguments, and gin.BasicAuth's account map carries a literal credential.
// It must not survive into endpoints.json or a convention finding's message/metadata.
func TestMiddlewareCredentialsNeverReachInventoryOrFindings(t *testing.T) {
	const secret = "S3cretValue42" // not a provider-shaped token: only the container reveals it
	evidence := []string{`main.go:4 middleware gin.BasicAuth(gin.Accounts{"operator": "` + secret + `"}) on group /api`}

	routes := make([]endpoints.Route, 0, 5)
	for i, path := range []string{"/api/one", "/api/two", "/api/three", "/api/four"} {
		routes = append(routes, endpoints.Route{
			Service: ".", Framework: "gin", Method: "POST", Path: path, Handler: "handle",
			File: "main.go", Line: 5 + i, Protection: endpoints.ProtAuthenticated,
			Evidence: evidence, Confidence: "high",
		})
	}
	routes = append(routes, endpoints.Route{
		Service: ".", Framework: "gin", Method: "POST", Path: "/records", Handler: "handle",
		File: "main.go", Line: 10, Protection: endpoints.ProtPublic,
		Evidence: []string{"main.go:10 no gate middleware on the route"}, Confidence: "high",
	})
	inv := &endpoints.Inventory{Schema: endpoints.Schema, Root: ".",
		Routes: routes, Summary: map[string]int{"authenticated": 4, "public": 1}}

	findings, err := endpoints.Analyze(inv, config.Defaults().Endpoints)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want the public route's convention finding", len(findings))
	}
	raw, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatalf("finding carries the middleware credential: %s", raw)
	}
	if !strings.Contains(findings[0].Message, "[REDACTED]") {
		t.Errorf("finding message does not show redaction: %s", findings[0].Message)
	}

	var out bytes.Buffer
	if err := endpoints.WriteJSON(&out, inv); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatalf("endpoints.json carries the middleware credential: %s", out.String())
	}
}

// TestRedactionKeepsRoleEvidenceUseful guards the other side: role names and route paths are
// not credentials, so convention evidence must stay readable.
func TestRedactionKeepsRoleEvidenceUseful(t *testing.T) {
	inv := &endpoints.Inventory{Schema: endpoints.Schema, Root: ".", Routes: []endpoints.Route{{
		Service: ".", Framework: "gin", Method: "GET", Path: "/api/admin/roles", Handler: "list",
		File: "main.go", Line: 9, Protection: endpoints.ProtRole, Roles: []string{"admin"},
		Evidence: []string{`main.go:9 middleware RequireRole("admin") on group /admin`}, Confidence: "high",
	}}, Summary: map[string]int{"role": 1}}
	var out bytes.Buffer
	if err := endpoints.WriteJSON(&out, inv); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	for _, want := range []string{"RequireRole", "admin", "/api/admin/roles"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("evidence lost %q: %s", want, out.String())
		}
	}
}
