package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuleFilesIncludesFlutterPackForDart(t *testing.T) {
	pack := t.TempDir()
	for _, f := range []string{"common/secrets.yaml", "dart/security.yaml", "flutter/mobile.yaml", "go/security.yaml"} {
		p := filepath.Join(pack, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("rules: []\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SDT_RULES_PACK_DIR", pack)

	got := strings.Join(ruleFiles("", []string{"dart"}), "\n")
	for _, want := range []string{"common/secrets.yaml", "dart/security.yaml", "flutter/mobile.yaml"} {
		if !strings.Contains(got, want) {
			t.Errorf("dart scan is missing %s; got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "go/security.yaml") {
		t.Errorf("dart scan picked up go rules:\n%s", got)
	}
	if other := strings.Join(ruleFiles("", []string{"go"}), "\n"); strings.Contains(other, "flutter/") {
		t.Errorf("go scan picked up flutter rules:\n%s", other)
	}
}

// A repository with only TypeScript still gets the JavaScript folder, whose
// rules for both languages would otherwise never run on it.
func TestRuleFilesIncludeTheJavaScriptPackForTypeScript(t *testing.T) {
	pack := t.TempDir()
	for _, f := range []string{"javascript/security.yaml", "typescript/security.yaml", "go/security.yaml"} {
		p := filepath.Join(pack, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("rules: []\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SDT_RULES_PACK_DIR", pack)

	got := ruleFiles("", []string{"typescript"})
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "javascript/security.yaml") || !strings.Contains(joined, "typescript/security.yaml") || strings.Contains(joined, "go/") {
		t.Fatalf("typescript scan loads the wrong folders:\n%s", joined)
	}
	if both := ruleFiles("", []string{"javascript", "typescript"}); len(both) != len(got) {
		t.Fatalf("a folder is loaded twice when both languages are present: %v", both)
	}
}
