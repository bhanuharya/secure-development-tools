package scanner

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// A history scan reports a secret at the line it had in the commit that added
// it. Here a config first held one secret on line 3; a later commit inserted a
// second secret above it, which also landed on line 3. Both must stay findings.
func TestGitleaksDifferentSecretsOnOneLineStayApart(t *testing.T) {
	payload := []byte(`[
		{"RuleID": "generic-api-key", "File": "/repo/config/admin.js", "StartLine": 3, "EndLine": 3, "Match": "API_TOKEN_SALT', 'REDACTED'", "Secret": "REDACTED", "Description": "key", "Commit": "2222222222222222"},
		{"RuleID": "generic-api-key", "File": "/repo/config/admin.js", "StartLine": 3, "EndLine": 3, "Match": "ADMIN_JWT_SECRET', 'REDACTED'", "Secret": "REDACTED", "Description": "key", "Commit": "1111111111111111"}
	]`)
	pr := (&GitleaksAdapter{}).Parse("8.30.1", "/repo", payload, "", 0)
	if len(pr.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(pr.Findings))
	}
	if pr.Findings[0].Fingerprint.Value == pr.Findings[1].Fingerprint.Value {
		t.Fatal("different secrets on one line must not share a fingerprint, or the scan's dedup drops one")
	}
}

// The same secret found again in another commit (a cherry-pick, a rebased
// branch) is still one finding: one secret, one rotation.
func TestGitleaksSameSecretInTwoCommitsStaysOne(t *testing.T) {
	payload := []byte(`[
		{"RuleID": "generic-api-key", "File": "/repo/config/plugins.js", "StartLine": 10, "Match": "secretKey: 'REDACTED'", "Secret": "REDACTED", "Commit": "aaaaaaaaaaaaaaaa"},
		{"RuleID": "generic-api-key", "File": "/repo/config/plugins.js", "StartLine": 10, "Match": "secretKey:  'REDACTED'", "Secret": "REDACTED", "Commit": "bbbbbbbbbbbbbbbb"}
	]`)
	pr := (&GitleaksAdapter{}).Parse("8.30.1", "/repo", payload, "", 0)
	if len(pr.Findings) != 2 || pr.Findings[0].Fingerprint.Value != pr.Findings[1].Fingerprint.Value {
		t.Fatal("the same match on the same line must keep one fingerprint, so the scan's dedup merges it")
	}
}

// Findings that never shared a line with a different secret keep the
// fingerprint they had before, so recorded review decisions still apply.
func TestGitleaksSingleMatchKeepsExistingFingerprint(t *testing.T) {
	payload := []byte(`[{"RuleID": "private-key", "File": "/repo/keys/a.json", "StartLine": 5, "Match": "-----BEGIN PRIVATE KEY----- REDACTED", "Secret": "REDACTED", "Commit": "cccccccccccccccc"}]`)
	pr := (&GitleaksAdapter{}).Parse("8.30.1", "/repo", payload, "", 0)
	if len(pr.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(pr.Findings))
	}
	line := 5
	want := finding.FingerprintValue(finding.CatSecret, "gitleaks", "private-key", "keys/a.json",
		fingerprintCtx("private-key\nkeys/a.json", &line))
	if got := pr.Findings[0].Fingerprint.Value; got != want {
		t.Fatalf("fingerprint changed for a finding with no same-line neighbour: got %s want %s", got, want)
	}
}

// End to end with the real scanner: build the history described above in a
// throwaway repository and check both secrets come out with their own identity.
func TestGitleaksHistoryScanKeepsBothSecrets(t *testing.T) {
	bin, err := exec.LookPath("gitleaks")
	if err != nil {
		t.Skip("gitleaks not installed")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, "admin.js"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	git("init", "-q")
	// Throwaway random values, generated per run: never real credentials.
	first, second := randomHex(t), randomHex(t)
	write("module.exports = ({ env }) => ({\n  auth: {\n    secret: env('ADMIN_JWT_SECRET', '" + first + "'),\n  },\n});\n")
	git("add", "admin.js")
	git("commit", "-q", "-m", "first")
	write("module.exports = ({ env }) => ({\n  apiToken: {\n    salt: env('API_TOKEN_SALT', '" + second + "'),\n  },\n  auth: {\n    secret: env('ADMIN_JWT_SECRET', '" + first + "'),\n  },\n});\n")
	git("commit", "-q", "-am", "second")

	report := filepath.Join(dir, "report.json")
	cmd := exec.Command(bin, "detect", "--source", repo, "--log-opts=--all", "--redact", "--no-banner",
		"--exit-code", "0", "--report-format", "json", "--report-path", report)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gitleaks: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), first) || strings.Contains(string(raw), second) {
		t.Fatal("gitleaks report must be redacted")
	}
	pr := (&GitleaksAdapter{}).Parse("8.30.1", repo, raw, "", 0)
	fingerprints := map[string]bool{}
	for _, f := range pr.Findings {
		if f.Location != nil && f.Location.Path == "admin.js" {
			fingerprints[f.Fingerprint.Value] = true
		}
	}
	if len(fingerprints) != 2 {
		t.Fatalf("want 2 distinct secrets in admin.js, got %d findings with %d identities", len(pr.Findings), len(fingerprints))
	}
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
