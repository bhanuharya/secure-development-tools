package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecretCorpus runs the shared secret-shape corpus (also run by the Python redactor's
// tests) through Redact and through the final JSON guard every artifact passes.
func TestSecretCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "redaction", "corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct{ Name, Path, Text, Secret string }
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if got := Redact(c.Text); strings.Contains(got, c.Secret) {
				t.Errorf("Redact kept the secret: %q", got)
			}
			out, err := MarshalRedacted(map[string]any{"evidence": []string{c.Text}, "message": c.Text})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(out), c.Secret) || strings.Contains(string(out), jsonEscaped(c.Secret)) {
				t.Errorf("MarshalRedacted kept the secret: %s", out)
			}
		})
	}
}

func jsonEscaped(s string) string {
	b, _ := json.Marshal(s)
	return strings.Trim(string(b), `"`)
}
