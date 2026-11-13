package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A real scan must name a vendored finding from the overlay: the vendored
// rule file itself carries no metadata.title. This exercises the plan, the
// merged rule file, the parser and the report writer together.
func TestScanNamesVendoredRuleFromOverlay(t *testing.T) {
	for _, tool := range []string{"git", "opengrep", "gitleaks"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	source, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	repo := gitRepo(t)
	write(t, repo, "app/legacy.py", "def version():\n    return \"1\"\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "first")
	write(t, repo, "app/legacy.py", "import hashlib\n\ndef digest(value):\n    return hashlib.md5(value).hexdigest()\n")
	git(t, repo, "add", "-A")

	t.Chdir(repo)
	outDir := filepath.Join(repo, "out")
	t.Setenv("SDT_RULES_PACK_DIR", filepath.Join(source, "rules", "opengrep-rules"))
	t.Setenv("SDT_OUTPUT_DIR", outDir)
	t.Setenv("SDT_CACHE_DIR", filepath.Join(repo, ".cache"))
	for _, unset := range []string{"SDT_CONFIG", "SDT_BASE"} {
		t.Setenv(unset, "")
	}
	var out bytes.Buffer
	root := NewRoot()
	root.SetArgs([]string{"scan", "--staged"})
	root.SetOut(&out)
	root.SetErr(&out)
	err = root.Execute()
	var exit *ExitError
	if err != nil && (!errors.As(err, &exit) || exit.Code != ExitPolicyFailed) {
		t.Fatalf("scan failed: %v\n%s", err, out.String())
	}

	raw, err := os.ReadFile(filepath.Join(outDir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Findings []struct {
			Rule struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	const ruleID = "vendor.semgrep.python.lang.security.insecure-hash-algorithm-md5"
	for _, f := range report.Findings {
		if f.Rule.ID != ruleID {
			continue
		}
		if f.Rule.Name != "MD5 used for security purposes" {
			t.Fatalf("vendored rule name = %q, want the overlay title", f.Rule.Name)
		}
		return
	}
	t.Fatalf("scan did not report %s:\n%s", ruleID, strings.Join(strings.Fields(out.String()), " "))
}
