package config

import (
	"strings"
	"testing"
)

const endpointsBase = `apiVersion: secure-dev/v1alpha1
kind: ScanConfiguration
metadata:
  name: t
profiles:
  pr:
    mode: changed
    scanners: [gitleaks]
    requiredScanners: [gitleaks]
`

func TestEndpointsSectionParsed(t *testing.T) {
	raw := []byte(endpointsBase + `endpoints:
  authGates: ["AuthMiddleware", "verifyJwt"]
  publicPaths: ["^/api/v1/rates$"]
  sensitivePaths: ["/payouts"]
  minRoutes: 7
  majority: 0.8
`)
	cfg, _, err := Parse(raw, "test")
	if err != nil {
		t.Fatal(err)
	}
	ep := cfg.Endpoints
	if len(ep.AuthGates) != 2 || ep.AuthGates[0] != "AuthMiddleware" || ep.AuthGates[1] != "verifyJwt" {
		t.Fatalf("authGates = %v", ep.AuthGates)
	}
	if len(ep.PublicPaths) != 1 || ep.PublicPaths[0] != "^/api/v1/rates$" {
		t.Fatalf("publicPaths = %v", ep.PublicPaths)
	}
	if len(ep.SensitivePaths) != 1 || ep.SensitivePaths[0] != "/payouts" {
		t.Fatalf("sensitivePaths = %v", ep.SensitivePaths)
	}
	if ep.MinRoutes != 7 || ep.Majority != 0.8 {
		t.Fatalf("thresholds = %d/%v", ep.MinRoutes, ep.Majority)
	}
}

func TestEndpointsDefaultsWhenAbsent(t *testing.T) {
	cfg, _, err := Parse([]byte(endpointsBase), "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoints.MinRoutes != 0 || cfg.Endpoints.Majority != 0 {
		t.Fatalf("absent section must stay zero before merge: %+v", cfg.Endpoints)
	}
	merged := Merge(Defaults(), cfg)
	if merged.Endpoints.MinRoutes != DefaultMinRoutes || merged.Endpoints.Majority != DefaultMajority {
		t.Fatalf("defaults not applied: %+v", merged.Endpoints)
	}
	if len(merged.Endpoints.PublicPaths) != 0 || len(merged.Endpoints.SensitivePaths) != 0 {
		t.Fatalf("extra path lists must start empty: %+v", merged.Endpoints)
	}
}

func TestEndpointsPartialOverlayKeepsDefaultThreshold(t *testing.T) {
	cfg, _, err := Parse([]byte(endpointsBase+`endpoints:
  sensitivePaths: ["/payouts"]
`), "test")
	if err != nil {
		t.Fatal(err)
	}
	merged := Merge(Defaults(), cfg)
	if merged.Endpoints.MinRoutes != DefaultMinRoutes || merged.Endpoints.Majority != DefaultMajority {
		t.Fatalf("partial overlay clobbered thresholds: %+v", merged.Endpoints)
	}
	if len(merged.Endpoints.SensitivePaths) != 1 {
		t.Fatalf("partial overlay lost the list: %+v", merged.Endpoints)
	}
}

func TestEndpointsRejectsInvalidValues(t *testing.T) {
	cases := map[string]string{
		"majority above one":  "  majority: 1.5\n",
		"negative minRoutes":  "  minRoutes: -1\n",
		"bad public regex":    "  publicPaths: [\"(\"]\n",
		"bad sensitive regex": "  sensitivePaths: [\"[\"]\n",
	}
	for name, section := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Parse([]byte(endpointsBase+"endpoints:\n"+section), "test"); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

// The inventory is a full-profile scanner only: it reads a whole service and
// is too slow for a changed-file scan (SPEC §8).
func TestEndpointsScannerInFullAndPRProfiles(t *testing.T) {
	cfg := Defaults()
	has := func(list []string, want string) bool {
		for _, s := range list {
			if s == want {
				return true
			}
		}
		return false
	}
	// Full and pull request scans inventory endpoints: a pull request that adds a public sensitive
	// route is reported on the pull request, not only by the next branch scan.
	for _, name := range []string{"full", "pr"} {
		if !has(cfg.Profiles[name].Scanners, "endpoints") || !has(cfg.Profiles[name].RequiredScanners, "endpoints") {
			t.Fatalf("profile %s must select and require endpoints", name)
		}
	}
	if has(cfg.Profiles["release"].Scanners, "endpoints") {
		t.Fatal("profile release must not select endpoints")
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("defaults with endpoints do not validate: %v", err)
	}
}

func TestUpstreamAuthValidation(t *testing.T) {
	cfg := Defaults()
	cfg.Endpoints.UpstreamAuth = []UpstreamAuth{{Paths: []string{"/api/**"}}}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), `"by" must say`) {
		t.Fatalf("missing by: %v", err)
	}
	cfg.Endpoints.UpstreamAuth = []UpstreamAuth{{Paths: []string{"api/**"}, By: "gateway"}}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "must start with /") {
		t.Fatalf("relative pattern: %v", err)
	}
	cfg.Endpoints.UpstreamAuth = []UpstreamAuth{{Service: "orders", Paths: []string{"/api/**"}, By: "gateway"}}
	if err := Validate(cfg); err != nil {
		t.Fatalf("valid declaration rejected: %v", err)
	}
}
