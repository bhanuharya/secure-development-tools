package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func locFinding(id, rule, path string, line int) *finding.Finding {
	return &finding.Finding{
		ID: id, Category: finding.CatSAST, Rule: finding.Rule{ID: rule},
		Location: &finding.Location{Path: path, StartLine: &line},
	}
}

func writeFile(t *testing.T, root, name, content string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPlanSkipsSecretsAndLocationless(t *testing.T) {
	line := 3
	secret := &finding.Finding{ID: "s", Category: finding.CatSecret,
		Rule:     finding.Rule{ID: "scp.yaml.ci.unpinned-action"},
		Location: &finding.Location{Path: "a.yml", StartLine: &line}}
	noloc := &finding.Finding{ID: "n", Category: finding.CatSAST,
		Rule: finding.Rule{ID: "scp.yaml.ci.unpinned-action"}}
	ok := locFinding("g", "scp.yaml.ci.unpinned-action", "w.yml", 2)
	matched, res := Plan([]*finding.Finding{secret, noloc, ok}, map[string]bool{}, "")
	if len(matched) != 1 {
		t.Fatalf("want only the actionable finding matched, got %d (%v)", len(matched), res.Skipped)
	}
	if len(res.Skipped) != 2 {
		t.Fatalf("want 2 skips, got %v", res.Skipped)
	}
}

func TestPlanQuarantineAndSuggestions(t *testing.T) {
	known := locFinding("g", "scp.yaml.ci.unpinned-action", "w.yml", 2)
	unknown := locFinding("u", "some.other.rule", "w.yml", 3)
	matched, res := Plan([]*finding.Finding{known, unknown}, map[string]bool{"gha-pin-action/v1": true}, "")
	if len(matched) != 0 {
		t.Fatal("quarantined transform must not match")
	}
	if len(res.Quarantined) != 1 || len(res.Suggestions) != 1 {
		t.Fatalf("want 1 quarantine + 1 suggestion, got %+v", res)
	}
}

func TestApplyGhaPin(t *testing.T) {
	after, err := registered("gha-pin-action/v1").Apply("w.yml",
		[]string{"x", "      - uses: actions/checkout@main"}, 2, nil)
	_ = after
	_ = err
	// Network-dependent resolution tested live; unit covers the no-match path.
	if _, err := registered("gha-pin-action/v1").Apply("w.yml",
		[]string{"x", "run: echo hi"}, 2, nil); err == nil {
		t.Fatal("expected error when line has no uses: reference")
	}
	if _, err := registered("gha-pin-action/v1").Apply("w.yml",
		[]string{"x", "- uses: actions/checkout@11bd71901bbe5b1630cehdbbb3cf82794aa88d5483"}, 2, nil); err == nil {
		t.Fatal("expected error when already pinned")
	}
}

func registered(id string) Transform {
	for _, tr := range Classes() {
		if tr.ID == id {
			return tr
		}
	}
	panic("missing transform " + id)
}

func TestApplyPyHashAndYaml(t *testing.T) {
	h := registered("py-hashlib-sha256/v1")
	after, err := h.Apply("a.py", []string{"import hashlib", "h = hashlib.md5(data)"}, 2, nil)
	if err != nil || after != "h = hashlib.sha256(data)" {
		t.Fatalf("got %q, %v", after, err)
	}
	if _, err := h.Apply("a.py", []string{"h = hashlib.sha256(data)"}, 1, nil); err == nil {
		t.Fatal("expected error when line already safe")
	}
	y := registered("py-yaml-safe-load/v1")
	after, err = y.Apply("a.py", []string{"d = yaml.unsafe_load(doc)"}, 1, nil)
	if err != nil || after != "d = yaml.safe_load(doc)" {
		t.Fatalf("got %q, %v", after, err)
	}
	after, err = y.Apply("a.py", []string{"d = yaml.load(doc, Loader=yaml.Loader)"}, 1, nil)
	if err != nil || after != "d = yaml.load(doc, Loader=yaml.SafeLoader)" {
		t.Fatalf("got %q, %v", after, err)
	}
	after, err = y.Apply("a.py", []string{"d = yaml.load(doc, Loader=yaml.CUnsafeLoader)"}, 1, nil)
	if err != nil || after != "d = yaml.load(doc, Loader=yaml.CSafeLoader)" {
		t.Fatalf("got %q, %v", after, err)
	}
}

func TestApplyEditsAtomicPerFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.py", "import hashlib\nh = hashlib.md5(x)\n")
	writeFile(t, root, "b.py", "import hashlib\nclean = 1\n")
	f1 := locFinding("f1", "scp.python.crypto.weak-md5", "a.py", 2)
	f2 := locFinding("f2", "scp.python.crypto.weak-md5", "b.py", 5) // out of range
	matched := map[*finding.Finding]Transform{f1: registered("py-hashlib-sha256/v1"), f2: registered("py-hashlib-sha256/v1")}
	res, err := ApplyEdits(root, matched, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Edits) != 1 {
		t.Fatalf("want only the fixable file edited, got %+v", res.Edits)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "a.py"))
	if !strings.Contains(string(raw), "hashlib.sha256(x)") {
		t.Fatalf("a.py not fixed: %s", raw)
	}
	// Preview must not write.
	root2 := t.TempDir()
	writeFile(t, root2, "a.py", "h = hashlib.md5(x)\n")
	edits, _ := Preview(root2, map[*finding.Finding]Transform{
		locFinding("f1", "scp.python.crypto.weak-md5", "a.py", 1): registered("py-hashlib-sha256/v1"),
	})
	if len(edits) != 1 {
		t.Fatalf("want 1 preview edit, got %d", len(edits))
	}
	raw2, _ := os.ReadFile(filepath.Join(root2, "a.py"))
	if strings.Contains(string(raw2), "sha256") {
		t.Fatal("preview must not write files")
	}
}

func TestDiffFormat(t *testing.T) {
	d := Diff([]Edit{{Path: "a.py", Line: 2, Before: "x", After: "y", RuleID: "r", ClassID: "c/v1"}})
	if !strings.Contains(d, "-x") || !strings.Contains(d, "+y") || !strings.Contains(d, "a.py") {
		t.Fatalf("bad diff:\n%s", d)
	}
}
