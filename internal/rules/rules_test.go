package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const twoRules = "rules:\n- id: a\n  languages: [python]\n  severity: WARNING\n  message: m\n  patterns:\n  - pattern: foo(...)\n- id: b\n  languages: [python]\n  severity: ERROR\n  message: m\n  patterns:\n  - pattern: bar(...)\n"

func TestCountRules(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "r1.yaml")
	f2 := filepath.Join(dir, "r2.yaml")
	writeFile(t, f1, twoRules)
	writeFile(t, f2, "rules:\n- id: c\n  message: m\n  severity: INFO\n  languages: [go]\n  patterns:\n  - pattern: baz\n")
	total, invalid := CountRules([]string{f1, f2})
	if total != 3 || len(invalid) != 0 {
		t.Fatalf("total=%d invalid=%v", total, invalid)
	}
	writeFile(t, f2, "not: [valid")
	_, invalid = CountRules([]string{f2})
	if len(invalid) != 1 {
		t.Fatalf("want 1 invalid, got %v", invalid)
	}
}

func TestTitleProblems(t *testing.T) {
	pack := t.TempDir()
	t.Setenv("SDT_RULES_PACK_DIR", pack)
	first := filepath.Join(pack, "python", "security.yaml")
	vendored := filepath.Join(pack, "vendor", "semgrep", "python", "lang", "security", "rule.yaml")
	vendoredID := "vendor.semgrep.python.lang.security.rule"
	rule := func(id, title string) string {
		out := "rules:\n- id: " + id + "\n  message: m\n"
		if title != "" {
			out += "  metadata:\n    title: " + title + "\n"
		}
		return out
	}
	long := strings.Repeat("x", MaxRuleTitleLength+1)
	cases := []struct {
		name, first, vendored string
		titles                map[string]string
		want                  string
	}{
		{"titled", rule("a", "A readable title"), rule("rule", ""), map[string]string{vendoredID: "Overlay title"}, ""},
		{"first party missing", rule("a", ""), rule("rule", ""), map[string]string{vendoredID: "Overlay title"}, `rule "a" has no metadata.title`},
		{"first party too long", rule("a", long), rule("rule", ""), map[string]string{vendoredID: "Overlay title"}, "title is 61 characters"},
		{"vendored missing", rule("a", "A readable title"), rule("rule", ""), map[string]string{}, "has no overlay title"},
		{"vendored too long", rule("a", "A readable title"), rule("rule", ""), map[string]string{vendoredID: long}, "overlay title is 61 characters"},
		{"stale overlay", rule("a", "A readable title"), rule("rule", ""), map[string]string{vendoredID: "Overlay title", "vendor.semgrep.gone": "Gone"}, `overlay entry "vendor.semgrep.gone" has no rule`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			writeFile(t, first, c.first)
			writeFile(t, vendored, c.vendored)
			problems := TitleProblems([]string{first, vendored}, c.titles)
			if c.want == "" {
				if len(problems) != 0 {
					t.Fatalf("clean rules reported: %v", problems)
				}
				return
			}
			if len(problems) != 1 || !strings.Contains(problems[0], c.want) {
				t.Fatalf("want one problem containing %q, got %v", c.want, problems)
			}
		})
	}
}

func TestLoadTitles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "titles.yaml")
	writeFile(t, path, "vendor.semgrep.a:  A title  \nvendor.semgrep.b: \"Another: title\"\n")
	titles, err := LoadTitles(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(titles) != 2 || titles["vendor.semgrep.a"] != "A title" || titles["vendor.semgrep.b"] != "Another: title" {
		t.Fatalf("titles=%v", titles)
	}
	if _, err := LoadTitles(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("a missing overlay must be an error")
	}
}

func TestBundleHashMatchesShell(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.yaml"), twoRules)
	writeFile(t, filepath.Join(dir, "sub", "b.py"), "print(1)\n")
	// Reference implementation via shell pipeline (same as vendor script).
	out, err := shellBundle(dir)
	if err != nil {
		t.Skipf("sha256sum unavailable: %v", err)
	}
	got, err := BundleHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != out {
		t.Fatalf("bundle hash mismatch: go=%s shell=%s", got, out)
	}
}

func TestFindTests(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "r.yaml")
	writeFile(t, rule, twoRules)
	writeFile(t, filepath.Join(dir, "r.py"), "# ruleid: a\nfoo(1)\n")
	writeFile(t, filepath.Join(dir, "r.fixed.py"), "foo(1)\n")
	writeFile(t, filepath.Join(dir, "other.go"), "package x\n")
	got := FindTests(rule)
	if len(got) != 1 || !strings.HasSuffix(got[0], "r.py") {
		t.Fatalf("autofix fixtures must be excluded, got %v", got)
	}
	for _, g := range got {
		if g == rule {
			t.Fatal("rule file must never match itself as a test")
		}
	}
	// Ours convention: <stem>.test.<ext>, discovered even for yaml-ish targets.
	yamlRule := filepath.Join(dir, "s.yaml")
	writeFile(t, yamlRule, twoRules)
	writeFile(t, filepath.Join(dir, "s.test.yaml"), "# ruleid: a\n")
	yamlTest := filepath.Join(dir, "s.test.txt")
	writeFile(t, yamlTest, "# ruleid: a\n")
	got = FindTests(yamlRule)
	if len(got) != 2 {
		t.Fatalf("want both .test. fixtures, got %v", got)
	}
}

func TestFindTestsIncludesDart(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "security.yaml")
	fixture := filepath.Join(dir, "security.test.dart")
	writeFile(t, rule, "rules:\n- id: scp.dart.test\n  languages: [dart]\n  message: test\n  severity: WARNING\n  pattern: Random()\n")
	writeFile(t, fixture, "// ruleid: scp.dart.test\nRandom();\n")
	got := FindTests(rule)
	if len(got) != 1 || got[0] != fixture {
		t.Fatalf("Dart fixture not discovered: %v", got)
	}
	idx := IndexAnnotations([]string{dir})
	if len(idx["scp.dart.test"]) != 1 || idx["scp.dart.test"][0] != fixture {
		t.Fatalf("Dart annotation not indexed: %v", idx)
	}
}

func TestRuleIDs(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "r.yaml")
	writeFile(t, f, twoRules)
	ids := RuleIDs(f)
	if len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("ids=%v", ids)
	}
}

func TestIndexAnnotationsFindsSharedFixtures(t *testing.T) {
	dir := t.TempDir()
	// One fixture covering two rules (upstream pickle.py pattern).
	writeFile(t, filepath.Join(dir, "shared.py"),
		"# ruleid: avoid-pickle\nimport pickle\n# ok: avoid-dill\nimport json\n")
	idx := IndexAnnotations([]string{dir})
	if len(idx["avoid-pickle"]) != 1 || len(idx["avoid-dill"]) != 1 {
		t.Fatalf("index=%v", idx)
	}
	if _, ok := idx["unrelated"]; ok {
		t.Fatal("unrelated rule must not index")
	}
}

func TestDiscoverSkipsTestFixtures(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "r.yaml"), twoRules)
	writeFile(t, filepath.Join(dir, "r.test.py"), "# ruleid: a\n")
	files, err := DiscoverRuleFiles([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("test fixtures must not be discovered as rules: %v", files)
	}
}

func TestDiscoverSkipsVendorTitleOverlay(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "vendor", "titles.yaml"), "vendor.demo: A title\n")
	writeFile(t, filepath.Join(dir, "vendor", "demo", "r.yaml"), twoRules)
	files, err := DiscoverRuleFiles([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || filepath.Base(files[0]) != "r.yaml" {
		t.Fatalf("the title overlay must not be a rule file: %v", files)
	}
}

func TestEnforceManifest(t *testing.T) {
	root := t.TempDir()
	pack := filepath.Join(root, "rules", "opengrep-rules", "vendor", "demo")
	writeFile(t, filepath.Join(pack, "r.yaml"), twoRules)
	writeFile(t, filepath.Join(pack, "t.py"), "x\n")
	files, _ := DiscoverRuleFiles([]string{filepath.Join(root, "rules")})
	bundle, err := BundleHash(pack)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{Sources: []ManifestSource{{
		ID: "demo", PathPrefixes: []string{"vendor/demo"},
		ExpectedRuleCount: 2, BundleSHA256: bundle,
	}}}
	if problems := EnforceManifest(root, files, m); len(problems) != 0 {
		t.Fatalf("clean manifest flagged: %v", problems)
	}
	m.Sources[0].ExpectedRuleCount = 99
	if problems := EnforceManifest(root, files, m); len(problems) != 1 {
		t.Fatalf("count drift must flag exactly once: %v", problems)
	}
	m.Sources[0].ExpectedRuleCount = 2
	m.Sources[0].BundleSHA256 = "00" + bundle[2:]
	if problems := EnforceManifest(root, files, m); len(problems) != 1 {
		t.Fatalf("bundle tamper must flag exactly once: %v", problems)
	}
}
