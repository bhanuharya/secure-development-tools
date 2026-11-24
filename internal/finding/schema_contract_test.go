package finding_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func TestFindingSchemaContractIncludesEndpointsAdapter(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "schemas", "finding-v1alpha1.json")
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Required   []string `json:"required"`
		Properties struct {
			SchemaVersion struct {
				Const string `json:"const"`
			} `json:"schemaVersion"`
			Fingerprint struct {
				Properties struct {
					Algorithm struct {
						Const string `json:"const"`
					} `json:"algorithm"`
					Value struct {
						Pattern string `json:"pattern"`
					} `json:"value"`
				} `json:"properties"`
			} `json:"fingerprint"`
			Scanner struct {
				Properties struct {
					Adapter struct {
						Enum []string `json:"enum"`
					} `json:"adapter"`
				} `json:"properties"`
			} `json:"scanner"`
			Category struct {
				Enum []string `json:"enum"`
			} `json:"category"`
			Severity struct {
				Properties struct {
					Canonical struct {
						Enum []string `json:"enum"`
					} `json:"canonical"`
				} `json:"properties"`
			} `json:"severity"`
			BaselineState struct {
				Enum []string `json:"enum"`
			} `json:"baselineState"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	adapters := toSet(schema.Properties.Scanner.Properties.Adapter.Enum)
	if !adapters["endpoints"] {
		t.Fatalf("schemas/finding-v1alpha1.json scanner.adapter enum missing \"endpoints\": %v", schema.Properties.Scanner.Properties.Adapter.Enum)
	}
	categories := toSet(schema.Properties.Category.Enum)
	severities := toSet(schema.Properties.Severity.Properties.Canonical.Enum)
	states := toSet(schema.Properties.BaselineState.Enum)
	fpRe := regexp.MustCompile(schema.Properties.Fingerprint.Properties.Value.Pattern)

	inv := &endpoints.Inventory{
		Schema: endpoints.Schema,
		Root:   ".",
		Routes: []endpoints.Route{
			{Service: ".", Framework: "gin", Method: "GET", Path: "/api/orders/{id}/delete", File: "main.go", Line: 10, Protection: endpoints.ProtAuthenticated, Confidence: "high"},
			{Service: ".", Framework: "spring-mvc", Method: "GET", Path: "/api/admin/users/export", File: "Ctrl.java", Line: 20, Protection: endpoints.ProtAuthenticated, ShadowedBy: `Sec.java:8 .antMatchers("/api/admin/*").hasRole("ADMIN")`, Confidence: "high"},
		},
	}
	fs, err := endpoints.Analyze(inv, config.Defaults().Endpoints)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	prev := map[string]endpoints.RouteSnapshot{
		endpoints.SnapshotKey(".", "GET", "/api/orders/{id}/delete"): {
			Service: ".", Method: "GET", Path: "/api/orders/{id}/delete", Protection: string(endpoints.ProtRole), Roles: []string{"ADMIN"},
		},
	}
	fs = append(fs, endpoints.CompareProtection(prev, inv)...)
	if len(fs) != 3 {
		t.Fatalf("want 3 contract findings, got %d", len(fs))
	}

	for _, f := range fs {
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal finding: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("unmarshal finding: %v", err)
		}
		for _, req := range schema.Required {
			if _, ok := m[req]; !ok {
				t.Errorf("%s: missing required schema field %q", f.Rule.ID, req)
			}
		}
		if f.SchemaVersion != schema.Properties.SchemaVersion.Const {
			t.Errorf("%s: schemaVersion=%q want %q", f.Rule.ID, f.SchemaVersion, schema.Properties.SchemaVersion.Const)
		}
		if f.Fingerprint.Algorithm != schema.Properties.Fingerprint.Properties.Algorithm.Const {
			t.Errorf("%s: fingerprint.algorithm=%q want %q", f.Rule.ID, f.Fingerprint.Algorithm, schema.Properties.Fingerprint.Properties.Algorithm.Const)
		}
		if !fpRe.MatchString(f.Fingerprint.Value) {
			t.Errorf("%s: fingerprint.value=%q does not match %s", f.Rule.ID, f.Fingerprint.Value, schema.Properties.Fingerprint.Properties.Value.Pattern)
		}
		if !adapters[f.Scanner.Adapter] {
			t.Errorf("%s: scanner.adapter=%q not in schema enum", f.Rule.ID, f.Scanner.Adapter)
		}
		if !categories[f.Category] {
			t.Errorf("%s: category=%q not in schema enum", f.Rule.ID, f.Category)
		}
		if !severities[f.Severity.Canonical] {
			t.Errorf("%s: severity=%q not in schema enum", f.Rule.ID, f.Severity.Canonical)
		}
		if !states[f.BaselineState] {
			t.Errorf("%s: baselineState=%q not in schema enum", f.Rule.ID, f.BaselineState)
		}
		if !f.Redaction.Applied {
			t.Errorf("%s: redaction.applied must be true", f.Rule.ID)
		}
	}
	_ = finding.SchemaVersion
}

func toSet(items []string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, s := range items {
		out[s] = true
	}
	return out
}
