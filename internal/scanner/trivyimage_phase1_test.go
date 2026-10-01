package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

func trivyImageDoc(t *testing.T, repoDigest string, extra map[string]any) []byte {
	t.Helper()
	results := []any{
		map[string]any{
			"Target": "img:latest (debian 13.6)",
			"Vulnerabilities": []any{
				map[string]any{
					"VulnerabilityID": "CVE-2026-0001", "PkgName": "libc6",
					"InstalledVersion": "2.41-1", "FixedVersion": "2.41-2",
					"Severity": "HIGH", "Description": "Sample.",
				},
			},
		},
	}
	if extra != nil {
		results = append(results, extra)
	}
	doc := map[string]any{
		"Metadata": map[string]any{"ImageID": "sha256:abc123", "RepoDigests": []string{repoDigest}},
		"Results":  results,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Image misconfigurations must be normalized (Trivy owns IaC/misconfig
// alongside its vuln results); the image scanner must not drop the class.
func TestTrivyImageParsesMisconfigurations(t *testing.T) {
	misconfigTarget := map[string]any{
		"Target": "img:latest (Dockerfile)",
		"Misconfigurations": []any{
			map[string]any{
				"ID": "AVD-DS-0001", "Title": "Exposed port", "Message": "Restrict ports.",
				"Severity": "HIGH",
			},
		},
	}
	pr := (&TrivyImageAdapter{}).Parse("0.73.0", "/repo", trivyImageDoc(t, "juice@sha256:deadbeef", misconfigTarget), "", 0)
	if pr.Health != HealthCompleted {
		t.Fatalf("health=%s diag=%v", pr.Health, pr.Diagnostics)
	}
	if len(pr.Findings) != 2 {
		t.Fatalf("want vuln + misconfig = 2 findings, got %d", len(pr.Findings))
	}
	var mis *struct{ Cat string }
	_ = mis
	found := false
	for _, f := range pr.Findings {
		if f.Category == "misconfiguration" {
			found = true
			if f.Rule.ID != "AVD-DS-0001" {
				t.Fatalf("bad misconfig rule: %q", f.Rule.ID)
			}
			if f.Artifact == nil || f.Artifact.Image != "juice@sha256:deadbeef" {
				t.Fatalf("misconfig must carry resolved image identity: %+v", f.Artifact)
			}
			if f.Remediation == nil || !strings.Contains(f.Remediation.Guidance, "Restrict") {
				t.Fatalf("misconfig remediation lost: %+v", f.Remediation)
			}
		}
	}
	if !found {
		t.Fatal("no misconfiguration finding parsed")
	}
}

// The same CVE in two immutable image identities must never share a fingerprint.
func TestTrivyImageFingerprintIncludesIdentity(t *testing.T) {
	a := &TrivyImageAdapter{}
	p1 := a.Parse("0.73.0", "/repo", trivyImageDoc(t, "juice@sha256:aaa", nil), "", 0)
	p2 := a.Parse("0.73.0", "/repo", trivyImageDoc(t, "juice@sha256:bbb", nil), "", 0)
	if len(p1.Findings) != 1 || len(p2.Findings) != 1 {
		t.Fatal("expected one finding each")
	}
	if p1.Findings[0].Fingerprint.Value == p2.Findings[0].Fingerprint.Value {
		t.Fatal("fingerprints collide across distinct image identities")
	}
	if p1.Findings[0].Artifact.Image == p2.Findings[0].Artifact.Image {
		t.Fatal("artifact image identity not recorded distinctly")
	}
}

func TestTrivyImageRequiresImmutableIdentity(t *testing.T) {
	doc := trivyImageDoc(t, "", nil)
	var payload map[string]any
	if err := json.Unmarshal(doc, &payload); err != nil {
		t.Fatal(err)
	}
	payload["Metadata"] = map[string]any{}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	pr := (&TrivyImageAdapter{}).Parse("0.73.0", "/repo", raw, "", 0)
	if pr.Health != HealthMalformed {
		t.Fatalf("health=%s diagnostics=%v", pr.Health, pr.Diagnostics)
	}
}

// Missing/empty native reports are malformed, never clean passes.
func TestEmptyNativeReportsRejected(t *testing.T) {
	if pr := (&GitleaksAdapter{}).Parse("8.30.1", "/repo", nil, "", 0); pr.Health == HealthCompleted {
		t.Fatal("gitleaks empty report must not be completed")
	}
	if pr := (&TrivyFSAdapter{}).Parse("0.73.0", "/repo", []byte{}, "", 0); pr.Health == HealthCompleted {
		t.Fatal("trivy-fs empty report must not be completed")
	}
	if pr := (&TrivyImageAdapter{}).Parse("0.73.0", "/repo", nil, "", 0); pr.Health == HealthCompleted {
		t.Fatal("trivy-image empty report must not be completed")
	}
}
