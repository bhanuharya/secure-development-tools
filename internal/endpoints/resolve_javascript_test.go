package endpoints

import "testing"

// TestNestGlobalGuard covers the branch the golden fixture cannot show both
// ways: the same unguarded controller is public without a service-wide guard
// and unknown with one.
func TestNestGlobalGuard(t *testing.T) {
	controller := []Fact{
		{Kind: "controller", File: "app.ts", Line: 3, Metavars: map[string]string{"$C": "HealthController", "$PREFIX": "health"}},
		{Kind: "route", File: "app.ts", Line: 6, Metavars: map[string]string{"$C": "HealthController", "$M": "status", "$VERB": "Get", "$PATH": "status"}},
	}
	cases := []struct {
		name       string
		facts      []Fact
		protection Protection
		unresolved int
	}{
		{name: "no global guard is public", facts: controller, protection: ProtPublic},
		{
			name:       "global guard leaves the route unknown",
			facts:      append(append([]Fact{}, controller...), Fact{Kind: "app_guard", File: "module.ts", Line: 9}),
			protection: ProtUnknown,
			unresolved: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			routes, unresolved := resolveJS(tc.facts, t.TempDir())
			if len(routes) != 1 {
				t.Fatalf("got %d routes, want 1", len(routes))
			}
			if routes[0].Protection != tc.protection {
				t.Errorf("protection = %s, want %s", routes[0].Protection, tc.protection)
			}
			if len(unresolved) != tc.unresolved {
				t.Errorf("unresolved = %v, want %d sentences", unresolved, tc.unresolved)
			}
		})
	}
}
