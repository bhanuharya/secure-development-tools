package report

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func testFindings() []*finding.Finding {
	return []*finding.Finding{
		{
			ID: "f1", Message: "leak <x> & \"y\"",
			Rule:     finding.Rule{ID: "r1"},
			Severity: finding.Severity{Canonical: "high"},
		},
	}
}

// Canary: no raw secret may survive redaction across representative families.
func TestRedactCanary(t *testing.T) {
	slackToken := "xox" + "b-" + strings.Repeat("s", 12)
	canaries := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_123456789012345678901234567890123456", // gitleaks:allow — synthetic redaction canary
		slackToken,
		"sk-live-12345678901234567890",
		"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
		"token=supersecretvalue123",
	}
	for _, c := range canaries {
		got := Redact("prefix "+c+" suffix", c)
		if strings.Contains(got, c) {
			t.Fatalf("canary leaked: %q -> %q", c, got)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Fatalf("no redaction marker for %q", c)
		}
	}
}

func TestJUnitWellFormed(t *testing.T) {
	raw := ToJUnit("policy_failed", testFindings(), map[string]string{"f1": "block-secrets"})
	var v any
	if err := xml.Unmarshal(raw, &v); err != nil {
		t.Fatalf("JUnit not well-formed: %v\n%s", err, raw)
	}
	if !strings.Contains(string(raw), "<failure") {
		t.Fatal("blocker must render a failure element")
	}
}

func TestRedactCleanTextUntouched(t *testing.T) {
	in := "Upgrade lodash from 4.17.20 to 4.17.21"
	if got := Redact(in); got != in {
		t.Fatalf("clean text mangled: %q", got)
	}
}
