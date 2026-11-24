package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
)

func TestGitleaksRejectsBlanketAllowlistRepoConfig(t *testing.T) {
	cases := []struct {
		name string
		toml string
	}{
		{
			name: "paths wildcard dot-star",
			toml: "[extend]\nuseDefault = true\n[allowlist]\npaths = [\".*\"]\n",
		},
		{
			name: "paths anchored dot-star",
			toml: "[allowlist]\npaths = ['^.*$']\n",
		},
		{
			name: "paths triple-quoted dot-star",
			toml: "[allowlist]\npaths = ['''.*''']\n",
		},
		{
			name: "regexes triple-double-quoted catch-all",
			toml: "[allowlist]\nregexes = [\"\"\"^.+$\"\"\"]\n",
		},
		{
			name: "regexes catch-all",
			toml: "[allowlist]\nregexes = [\".+\"]\n",
		},
		{
			name: "useDefault false without custom rules",
			toml: "[extend]\nuseDefault = false\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			cache := t.TempDir()
			if err := os.WriteFile(filepath.Join(repo, ".gitleaks.toml"), []byte(tc.toml), 0o644); err != nil {
				t.Fatal(err)
			}
			cfgPath, note, err := gitleaksDefaultConfigWithPolicy(cache, repo, true)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if note == "" {
				t.Fatalf("expected security note explaining rejected repo .gitleaks.toml")
			}
			raw, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			if !strings.Contains(text, "useDefault = true") {
				t.Fatalf("expected fallback to useDefault = true, got:\n%s", text)
			}
			if strings.Contains(text, ".gitleaks.toml") {
				t.Fatalf("rejected repo config must not be extended:\n%s", text)
			}
		})
	}
}

func TestGitleaksAcceptsBenignTripleQuotedRepoAllowlists(t *testing.T) {
	cases := []struct {
		name string
		toml string
	}{
		{
			name: "gitleaks triple-single-quoted mock path",
			toml: "[extend]\nuseDefault = true\n\n[allowlist]\ndescription = \"mock dataset\"\npaths = ['''(?:^|/)src/mock/''']\n",
		},
		{
			name: "triple-single-quoted scoped wildcard path",
			toml: "[extend]\nuseDefault = true\n[allowlist]\npaths = ['''testdata/fixtures/.*''']\n",
		},
		{
			name: "triple-double-quoted scoped regex",
			toml: "[extend]\nuseDefault = true\n[allowlist]\nregexes = [\"\"\"fake_fixture_token_[0-9]+\"\"\"]\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			cache := t.TempDir()
			if err := os.WriteFile(filepath.Join(repo, ".gitleaks.toml"), []byte(tc.toml), 0o644); err != nil {
				t.Fatal(err)
			}
			cfgPath, note, err := gitleaksDefaultConfigWithPolicy(cache, repo, true)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if note != "" {
				t.Fatalf("benign triple-quoted .gitleaks.toml was wrongly rejected: %s", note)
			}
			raw, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			if !strings.Contains(text, "path = ") || !strings.Contains(text, ".gitleaks.toml") {
				t.Fatalf("expected benign repo .gitleaks.toml to be extended, got:\n%s", text)
			}
		})
	}
}

func TestGitleaksTrustRepoConfigFalseIgnoresBenignRepoConfig(t *testing.T) {
	repo := t.TempDir()
	cache := t.TempDir()
	benign := "[extend]\nuseDefault = true\n[allowlist]\npaths = ['''testdata/fixtures/.*''']\n"
	if err := os.WriteFile(filepath.Join(repo, ".gitleaks.toml"), []byte(benign), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath, note, err := gitleaksDefaultConfigWithPolicy(cache, repo, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(note, "trustRepoConfig=false") {
		t.Fatalf("expected note mentioning trustRepoConfig=false, got %q", note)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "useDefault = true") {
		t.Fatalf("expected fallback to useDefault = true, got:\n%s", string(raw))
	}
}

func TestSubdirectoryRootUsesAbsoluteNativeAndRulePaths(t *testing.T) {
	tmp := t.TempDir()
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	// Relative cache root must still yield an absolute native report path so
	// child processes whose cwd is a subdirectory project.root can write it.
	rp, err := nativeReportPath(".cache/sdt", "trivy-fs.json")
	if err != nil {
		t.Fatalf("nativeReportPath: %v", err)
	}
	if !filepath.IsAbs(rp) {
		t.Fatalf("expected absolute report path, got %q", rp)
	}

	// Relative SDT_RULES_PACK_DIR must resolve to an absolute path.
	relRules := filepath.Join("rules", "opengrep-rules")
	if err := os.MkdirAll(relRules, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SDT_RULES_PACK_DIR", relRules)
	dir := rulePackDir(filepath.Join(tmp, "sub", "app"))
	if !filepath.IsAbs(dir) {
		t.Fatalf("expected absolute rulePackDir, got %q", dir)
	}
}

func TestValidateSafeArgRejectsFlagInjection(t *testing.T) {
	bad := []string{
		"--exec=id",
		"-n",
		"main --upload-pack=evil",
		"ref\nnewline",
		"ref\x00nul",
	}
	for _, v := range bad {
		if err := validateSafeArg(v, "ref"); err == nil {
			t.Errorf("expected validateSafeArg(%q) to fail", v)
		}
	}
	good := []string{
		"HEAD",
		"origin/main",
		"abc123def456",
		"ghcr.io/org/service:v1.2.3@sha256:0123456789abcdef",
	}
	for _, v := range good {
		if err := validateSafeArg(v, "ref"); err != nil {
			t.Errorf("expected validateSafeArg(%q) to pass, got %v", v, err)
		}
	}

	// Verify TrivyImageAdapter rejects leading-dash image reference before spawning trivy.
	fakeTrivy := filepath.Join(t.TempDir(), "trivy")
	if err := os.WriteFile(fakeTrivy, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SDT_TRIVY_BIN", fakeTrivy)
	adapter := &TrivyImageAdapter{}
	_, err := adapter.Plan(&sdtctx.ScanContext{
		ImageReference: "--format=evil",
		CacheRoot:      t.TempDir(),
	}, config.Defaults(), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "must not start with '-'") {
		t.Fatalf("expected TrivyImageAdapter.Plan to reject leading-dash image ref, got %v", err)
	}
}

func TestCrossCheckoutFingerprintDeterminism(t *testing.T) {
	rootA := filepath.Join(t.TempDir(), "checkout-alpha", "repo")
	rootB := filepath.Join(t.TempDir(), "nested", "checkout-beta", "repo")
	for _, r := range []string{rootA, rootB} {
		if err := os.MkdirAll(filepath.Join(r, "src"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(r, "src", "app.py"), []byte("x = eval(user_input)\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// 1. OpenGrep findings rooted at two different checkout directories.
	ogPayload := func(root string) []byte {
		p := filepath.Join(root, "src", "app.py")
		return []byte(fmt.Sprintf(`{
			"results": [{
				"check_id": "scp.python.eval-injection",
				"path": %q,
				"start": {"line": 1, "col": 5},
				"end": {"line": 1, "col": 21},
				"extra": {
					"message": "avoid eval",
					"severity": "ERROR",
					"lines": "x = eval(user_input)",
					"metadata": {"cwe": ["CWE-95"]}
				}
			}]
		}`, p))
	}
	og := &OpengrepAdapter{}
	resA := og.Parse("1.29.0", rootA, ogPayload(rootA), "", 0)
	resB := og.Parse("1.29.0", rootB, ogPayload(rootB), "", 0)
	if len(resA.Findings) != 1 || len(resB.Findings) != 1 {
		t.Fatalf("expected 1 opengrep finding each, got %d and %d", len(resA.Findings), len(resB.Findings))
	}
	if resA.Findings[0].Fingerprint.Value != resB.Findings[0].Fingerprint.Value {
		t.Fatalf("opengrep fingerprint drifted across checkouts: %s vs %s",
			resA.Findings[0].Fingerprint.Value, resB.Findings[0].Fingerprint.Value)
	}
	if resA.Findings[0].Location.Path != "src/app.py" || resB.Findings[0].Location.Path != "src/app.py" {
		t.Fatalf("expected repo-relative path src/app.py, got %q and %q",
			resA.Findings[0].Location.Path, resB.Findings[0].Location.Path)
	}

	// 2. Gitleaks findings rooted at two different checkout directories.
	glPayload := func(root string) []byte {
		p := filepath.Join(root, "src", "app.py")
		return []byte(fmt.Sprintf(`[{
			"RuleID": "generic-api-key",
			"File": %q,
			"StartLine": 1,
			"EndLine": 1,
			"Description": "Detected API key",
			"Match": "API_KEY=REDACTED",
			"Secret": "REDACTED"
		}]`, p))
	}
	gl := &GitleaksAdapter{}
	glA := gl.Parse("8.30.1", rootA, glPayload(rootA), "", 0)
	glB := gl.Parse("8.30.1", rootB, glPayload(rootB), "", 0)
	if len(glA.Findings) != 1 || len(glB.Findings) != 1 {
		t.Fatalf("expected 1 gitleaks finding each, got %d and %d", len(glA.Findings), len(glB.Findings))
	}
	if glA.Findings[0].Fingerprint.Value != glB.Findings[0].Fingerprint.Value {
		t.Fatalf("gitleaks fingerprint drifted across checkouts: %s vs %s",
			glA.Findings[0].Fingerprint.Value, glB.Findings[0].Fingerprint.Value)
	}

	// 3. TrivyFS findings rooted at two different checkout directories.
	tvPayload := func(root string) []byte {
		p := filepath.Join(root, "requirements.txt")
		return []byte(fmt.Sprintf(`{
			"Results": [{
				"Target": %q,
				"Vulnerabilities": [{
					"VulnerabilityID": "CVE-2024-0001",
					"PkgName": "flask",
					"InstalledVersion": "0.12.2",
					"FixedVersion": "2.3.3",
					"Severity": "HIGH",
					"Description": "example vuln"
				}]
			}]
		}`, p))
	}
	tv := &TrivyFSAdapter{}
	tvA := tv.Parse("0.73.0", rootA, tvPayload(rootA), "", 0)
	tvB := tv.Parse("0.73.0", rootB, tvPayload(rootB), "", 0)
	if len(tvA.Findings) != 1 || len(tvB.Findings) != 1 {
		t.Fatalf("expected 1 trivy-fs finding each, got %d and %d", len(tvA.Findings), len(tvB.Findings))
	}
	if tvA.Findings[0].Fingerprint.Value != tvB.Findings[0].Fingerprint.Value {
		t.Fatalf("trivy-fs fingerprint drifted across checkouts: %s vs %s",
			tvA.Findings[0].Fingerprint.Value, tvB.Findings[0].Fingerprint.Value)
	}
}
