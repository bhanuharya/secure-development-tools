package scanner

import (
	"fmt"
	"testing"
)

// A finding that moved (lines added above it) keeps its content identity; its
// line still separates two copies of the same code in one file.
func TestOpengrepContentIdentityIgnoresTheLine(t *testing.T) {
	result := func(line int) string {
		return fmt.Sprintf(`{"check_id":"rules.scp.java.debug.test-endpoint","path":"src/Api.java",`+
			`"start":{"line":%d,"col":5},"end":{"line":%d,"col":40},`+
			`"extra":{"lines":"    @PostMapping(\"/test-api\")","message":"m","severity":"WARNING","metadata":{}}}`, line, line)
	}
	payload := []byte(`{"results":[` + result(35) + `,` + result(43) + `],"errors":[]}`)
	res := (&OpengrepAdapter{}).Parse("test", "/repo", payload, "", 0)
	if len(res.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(res.Findings))
	}
	a, b := res.Findings[0].Fingerprint, res.Findings[1].Fingerprint
	if a.Value == b.Value {
		t.Fatal("two copies on different lines must keep different fingerprints")
	}
	if a.Content == "" || a.Content != b.Content {
		t.Fatalf("content identity must leave the line out: %q vs %q", a.Content, b.Content)
	}
	if a.Content == a.Value {
		t.Fatal("content identity must differ from the line-bound fingerprint")
	}
}
