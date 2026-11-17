package endpoints_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
	"github.com/bhanuharya/secure-development-tools/internal/report"
)

func TestRedactionReviewShapes(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "endpoints", "redaction")
	var cases []struct {
		Name, Text string
		Evidence   bool
		Secrets    []string
	}
	var expected map[string]string
	readJSONFixture(t, filepath.Join(root, "cases.json"), &cases)
	readJSONFixture(t, filepath.Join(root, "expected-evidence.json"), &expected)
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			out := report.Redact(tc.Text)
			if tc.Evidence {
				inv := &endpoints.Inventory{Routes: []endpoints.Route{{Evidence: []string{tc.Text}}}}
				var buf bytes.Buffer
				if err := endpoints.WriteJSON(&buf, inv); err != nil {
					t.Fatal(err)
				}
				var clean endpoints.Inventory
				if err := json.Unmarshal(buf.Bytes(), &clean); err != nil {
					t.Fatal(err)
				}
				out = clean.Routes[0].Evidence[0]
				if out != expected[tc.Name] {
					t.Errorf("evidence = %q, want %q", out, expected[tc.Name])
				}
			}
			for _, secret := range tc.Secrets {
				if strings.Contains(out, secret) {
					t.Fatalf("credential survived: %s", out)
				}
			}
		})
	}
}

func readJSONFixture(t *testing.T, path string, dst any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatal(err)
	}
}
