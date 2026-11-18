package app

import (
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func secretTestFinding(adapter, category, rule string, cwe []string, path string, line int) *finding.Finding {
	return &finding.Finding{
		Scanner:  finding.ScannerID{Adapter: adapter},
		Category: category,
		Rule:     finding.Rule{ID: rule, CWE: cwe},
		Location: &finding.Location{Path: path, StartLine: &line},
	}
}

func TestCollapseCrossScannerSecrets(t *testing.T) {
	cwe798 := []string{"CWE-798"}
	in := []*finding.Finding{
		secretTestFinding("gitleaks", finding.CatSecret, "private-key", nil, "keys/server.pem", 1),
		secretTestFinding("opengrep", finding.CatSAST, "scp.common.secrets.private-key", cwe798, "keys/server.pem", 1),
		// Same file, another line: a second secret, kept.
		secretTestFinding("opengrep", finding.CatSAST, "scp.yaml.spring.prod-literal-password", cwe798, "keys/server.pem", 9),
		// Same line, but not a hard-coded credential rule: a different issue, kept.
		secretTestFinding("opengrep", finding.CatSAST, "scp.java.path.request-path-to-file-operation", []string{"CWE-22"}, "keys/server.pem", 1),
		// A credential rule with no secret-scanner finding on its line: kept.
		secretTestFinding("opengrep", finding.CatSAST, "scp.common.secrets.aws-access-key-id", cwe798, "config/app.yml", 4),
	}
	out, dropped := collapseCrossScannerSecrets(in)
	if dropped != 1 || len(out) != 4 {
		t.Fatalf("dropped %d, kept %d; want 1 and 4", dropped, len(out))
	}
	for _, f := range out {
		if f.Rule.ID == "scp.common.secrets.private-key" {
			t.Fatalf("the code rule's copy of the secret-scanner finding was kept")
		}
	}
	if out[0].Rule.ID != "private-key" {
		t.Fatalf("the secret scanner's finding must stay first, got %s", out[0].Rule.ID)
	}
}

func TestCollapseCrossScannerSecretsWithoutSecretFindings(t *testing.T) {
	line := 3
	in := []*finding.Finding{{Category: finding.CatSAST, Rule: finding.Rule{ID: "x", CWE: []string{"CWE-798"}},
		Location: &finding.Location{Path: "a.yml", StartLine: &line}}}
	if out, dropped := collapseCrossScannerSecrets(in); dropped != 0 || len(out) != 1 {
		t.Fatalf("nothing to collapse without a secret-scanner finding: %d dropped", dropped)
	}
}

// The secret scanner's finding remembers the code-rule finding it replaced, so
// a baseline built from this scan still knows the code-rule finding.
func TestCollapseCrossScannerSecretsRecordsTheCollapsedIdentity(t *testing.T) {
	secret := secretTestFinding("gitleaks", finding.CatSecret, "private-key", nil, "keys/server.pem", 1)
	secret.Fingerprint = finding.Fingerprint{Algorithm: finding.FingerprintVersion, Value: "sha256:gitleaks"}
	code := secretTestFinding("opengrep", finding.CatSAST, "scp.common.secrets.private-key", []string{"CWE-798"}, "keys/server.pem", 1)
	code.Fingerprint = finding.Fingerprint{Algorithm: finding.FingerprintVersion, Value: "sha256:opengrep", Content: "sha256:opengrep-content"}
	out, dropped := collapseCrossScannerSecrets([]*finding.Finding{secret, code})
	if dropped != 1 || len(out) != 1 {
		t.Fatalf("dropped %d, kept %d; want 1 and 1", dropped, len(out))
	}
	got := out[0].Fingerprint.Collapsed
	if len(got) != 1 || got[0].Value != "sha256:opengrep" || got[0].Content != "sha256:opengrep-content" {
		t.Fatalf("collapsed identity not recorded: %+v", got)
	}
}
