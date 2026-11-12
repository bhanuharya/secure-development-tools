package endpoints

import "testing"

// TestAntMatch pins the Ant dialect Spring Security uses for its matchers:
// `**` spans segments, `*` and `?` stay inside one segment, `{x}` is one
// segment. The golden fixtures exercise the same matcher through the resolver.
func TestAntMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"exact", "/api/orders", "/api/orders", true},
		{"exact differs", "/api/orders", "/api/accounts", false},
		{"single star one segment", "/api/*", "/api/orders", true},
		{"single star not across segments", "/api/*", "/api/orders/1", false},
		{"double star matches prefix", "/api/**", "/api", true},
		{"double star matches deep path", "/api/**", "/api/v1/orders", true},
		{"double star zero segments mid pattern", "/**/orders", "/orders", true},
		{"double star mid pattern", "/**/orders", "/api/v1/orders", true},
		{"double star wrong prefix", "/api/**", "/orders", false},
		{"root double star", "/**", "/", true},
		{"root double star deep", "/**", "/api/v1", true},
		{"question mark one char", "/v?/x", "/v1/x", true},
		{"question mark not two chars", "/v?/x", "/v12/x", false},
		{"variable one segment", "/orders/{id}", "/orders/42", true},
		{"variable not several segments", "/orders/{id}", "/orders/42/items", false},
		{"variable not empty", "/orders/{id}/items", "/orders//items", false},
		{"constraint numeric", "/internal/{id:[0-9]+}", "/internal/42", true},
		{"constraint rejects letters", "/internal/{id:[0-9]+}", "/internal/export", false},
		{"constraint anchored", "/internal/{id:[0-9]+}", "/internal/42abc", false},
		{"constraint quantifier", "/v/{id:[0-9]{2}}", "/v/42", true},
		{"constraint rejects other length", "/v/{id:[0-9]{2}}", "/v/4", false},
		{"embedded constraint", "/files/report-{id:[0-9]+}.pdf", "/files/report-2024.pdf", true},
		{"embedded constraint rejects text", "/files/report-{id:[0-9]+}.pdf", "/files/report-final.pdf", false},
		{"star inside segment", "/files/report-*.pdf", "/files/report-2024.pdf", true},
		{"star inside segment needs suffix", "/files/report-*.pdf", "/files/report-2024.txt", false},
		{"trailing slash insignificant", "/api/**", "/api/", true},
		{"case sensitive", "/API/**", "/api/x", false},
		{"root", "/", "/", true},
		{"empty", "", "", true},
		{"star matches empty segment", "/api/*/x", "/api//x", true},
		{"literal dot", "/api/v1.0/orders", "/api/v1.0/orders", true},
		{"dot is not a wildcard", "/api/v1.0/orders", "/api/v1x0/orders", false},
		{"nested wildcards", "/api/*/orders/**", "/api/v1/orders/1/items", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := antMatch(tt.pattern, tt.path); got != tt.want {
				t.Errorf("antMatch(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

// TestAntMatchConstraintCannotCompile keeps an invalid constraint distinct
// from a mismatch: skipping it would let a later permitAll hide the route.
func TestAntMatchConstraintCannotCompile(t *testing.T) {
	if got := antMatchResult("/archive/{id:[0-9}", "/archive/7"); got != antUnknown {
		t.Fatalf("antMatchResult = %v, want unknown", got)
	}
	if antMatch("/archive/{id:[0-9}", "/archive/7") {
		t.Error("antMatch reported a match for a constraint it cannot compile")
	}
}
