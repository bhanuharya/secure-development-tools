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
