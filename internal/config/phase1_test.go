package config

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, body string) *ScanConfiguration {
	t.Helper()
	raw := []byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nmetadata:\n  name: t\nprofiles:\n  pr:\n    mode: changed\n    scanners: [gitleaks]\n    requiredScanners: [gitleaks]\n" + body)
	cfg, _, err := Parse(raw, "test")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	return cfg
}

func TestNestedUnknownKeyFails(t *testing.T) {
	raw := []byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nmetadata:\n  name: t\nprofiles:\n  pr:\n    mode: changed\n    scanners: [gitleaks]\n    bogusNestedField: 1\n")
	if _, _, err := Parse(raw, "test"); err == nil {
		t.Fatal("nested unknown key must fail closed")
	}
}

func TestInvalidPolicyDefaultActionFails(t *testing.T) {
	raw := []byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nmetadata:\n  name: t\nprofiles:\n  pr:\n    mode: changed\n    scanners: [gitleaks]\npolicy:\n  defaultAction: nuke\n")
	if _, _, err := Parse(raw, "test"); err == nil {
		t.Fatal("invalid defaultAction must fail closed")
	}
}

func TestInvalidBehaviorOnRequiredScannerErrorFails(t *testing.T) {
	raw := []byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nmetadata:\n  name: t\nprofiles:\n  pr:\n    mode: changed\n    scanners: [gitleaks]\npolicy:\n  behaviorOnRequiredScannerError: ignore\n")
	if _, _, err := Parse(raw, "test"); err == nil {
		t.Fatal("invalid behaviorOnRequiredScannerError must fail closed")
	}
}

func TestZeroScannersFails(t *testing.T) {
	raw := []byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nmetadata:\n  name: t\nprofiles:\n  pr:\n    mode: changed\n    scanners: []\n")
	if _, _, err := Parse(raw, "test"); err == nil {
		t.Fatal("zero scanners must fail closed")
	}
}

func TestInvalidProfileTimeoutFails(t *testing.T) {
	raw := []byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nmetadata:\n  name: t\nprofiles:\n  pr:\n    mode: changed\n    scanners: [gitleaks]\n    timeout: soon\n")
	if _, _, err := Parse(raw, "test"); err == nil {
		t.Fatal("invalid profile timeout must fail closed")
	}
}

func TestUnknownMatchDimensionFails(t *testing.T) {
	for _, body := range []string{
		"policy:\n  rules:\n    - id: r\n      match:\n        categories: [nope]\n      action: fail\n",
		"policy:\n  rules:\n    - id: r\n      match:\n        severities: [nope]\n      action: fail\n",
		"policy:\n  rules:\n    - id: r\n      match:\n        baselineStates: [nope]\n      action: fail\n",
		"policy:\n  rules:\n    - id: r\n      match:\n        reachable: [maybe]\n      action: fail\n",
	} {
		cfg, _, err := Parse([]byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nmetadata:\n  name: t\nprofiles:\n  pr:\n    mode: changed\n    scanners: [gitleaks]\n"+body), "test")
		if err == nil {
			t.Fatalf("unknown match dimension must fail closed: %q (cfg=%v)", body, cfg != nil)
		}
	}
}

func TestAssuranceSensitiveControlsFail(t *testing.T) {
	for name, body := range map[string]string{
		"sendSecrets": "ai:\n  enabled: true\n  sendSecretFindings: true\n",
		"aiMode":      "ai:\n  enabled: true\n  mode: auto-fix\n",
		"provider":    "publish:\n  enabled: true\n  provider: pastebin\n",
		"baseline":    "baseline:\n  onIncompatibleFingerprintVersion: ignore\n",
	} {
		raw := []byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nmetadata:\n  name: t\nprofiles:\n  pr:\n    mode: changed\n    scanners: [gitleaks]\n" + body)
		if _, _, err := Parse(raw, "test"); err == nil {
			t.Fatalf("%s: unsupported assurance-sensitive control must fail closed", name)
		}
	}
}

// The effective digest must cover the complete effective config: scanner,
// output, and policy-match changes all alter it.
func TestEffectiveDigestCoversCompleteConfig(t *testing.T) {
	base := mustParse(t, "")
	if EffectiveDigest(base) == "" {
		t.Fatal("empty digest")
	}
	out := mustParse(t, "")
	out.Outputs.Directory = "other"
	if EffectiveDigest(base) == EffectiveDigest(out) {
		t.Fatal("output change must alter effective digest")
	}
	sc := mustParse(t, "")
	sc.Scanners.TrivyFS.Type = "custom"
	if EffectiveDigest(base) == EffectiveDigest(sc) {
		t.Fatal("scanner section change must alter effective digest")
	}
	pol := mustParse(t, "policy:\n  defaultAction: report\n  rules:\n    - id: r\n      match:\n        reachable: [reachable]\n      action: fail\n")
	plain := mustParse(t, "")
	if EffectiveDigest(pol) == EffectiveDigest(plain) {
		t.Fatal("policy match change must alter effective digest")
	}
	if !strings.HasPrefix(EffectiveDigest(base), "sha256:") {
		t.Fatal("digest must be sha256-prefixed")
	}
}
