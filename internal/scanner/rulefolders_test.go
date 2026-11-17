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

// The vendored-title overlay is data for the rules harness, never --config.
func TestRuleFilesSkipVendorTitleOverlay(t *testing.T) {
	pack := t.TempDir()
	for _, f := range []string{"vendor/titles.yaml", "vendor/semgrep/python/lang/security/rule.yaml"} {
		p := filepath.Join(pack, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("rules: []\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SDT_RULES_PACK_DIR", pack)
	got := strings.Join(ruleFiles("", []string{"python"}), "\n")
	if strings.Contains(got, "titles.yaml") {
		t.Fatalf("the title overlay was passed as a rule file:\n%s", got)
	}
	if !strings.Contains(got, "vendor/semgrep/python/lang/security/rule.yaml") {
		t.Fatalf("vendored rule missing:\n%s", got)
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

// Vendored rules are loaded for the repository's languages only: every language's rules made the
// engine's start-up three times longer on every scan.
func TestRuleFilesLoadVendoredRulesForDetectedLanguagesOnly(t *testing.T) {
	pack := t.TempDir()
	for _, f := range []string{
		"common/secrets.yaml",
		"vendor/semgrep/java/lang/security/rule.yaml",
		"vendor/semgrep/python/lang/security/rule.yaml",
		"vendor/semgrep/javascript/lang/security/rule.yaml",
		"vendor/semgrep/yaml/kubernetes/rule.yaml",
		"vendor/semgrep/php/lang/rule.yaml",
	} {
		p := filepath.Join(pack, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("rules: []\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SDT_RULES_PACK_DIR", pack)
	vendored := func(langs ...string) string {
		var out []string
		for _, f := range ruleFiles("", langs) {
			if rel, err := filepath.Rel(filepath.Join(pack, "vendor", "semgrep"), f); err == nil && !strings.HasPrefix(rel, "..") {
				out = append(out, strings.SplitN(filepath.ToSlash(rel), "/", 2)[0])
			}
		}
		return strings.Join(out, " ")
	}
	// yaml is always loaded (configuration files), like the project's yaml folder.
	if got := vendored("java"); got != "java yaml" {
		t.Errorf("java repository loads vendored %q, want java and yaml only", got)
	}
	// TypeScript uses the JavaScript rules, which declare both languages.
	if got := vendored("typescript"); got != "javascript yaml" {
		t.Errorf("typescript repository loads vendored %q", got)
	}
	if got := vendored("php", "python"); got != "php python yaml" {
		t.Errorf("php and python repository loads vendored %q", got)
	}
}

func TestDetectLanguagesSeesEveryRuleFolderLanguage(t *testing.T) {
	root := writeTree(t, map[string]string{
		"web/App.tsx": "", "web/menu.jsx": "", "build.gradle.kts": "", "native/lib.c": "",
		"site/index.php": "", "crate/src/main.rs": "", "package.json": "{}",
	})
	got := map[string]bool{}
	for _, l := range detectLanguages(root) {
		got[l] = true
	}
	for _, want := range []string{"typescript", "javascript", "kotlin", "c", "php", "rust", "json"} {
		if !got[want] {
			t.Errorf("%s not detected; got %v", want, got)
		}
	}
}
