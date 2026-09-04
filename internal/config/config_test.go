package config

import (
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	raw := []byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nmetadata:\n  name: t\nprofiles:\n  pr:\n    mode: changed\n    scanners: [gitleaks]\n")
	cfg, digest, err := Parse(raw, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("bad digest %q", digest)
	}
	if _, ok := cfg.Profiles["pr"]; !ok {
		t.Fatal("missing pr profile")
	}
}

func TestParseUnknownFieldFails(t *testing.T) {
	raw := []byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nbogusKey: 1\nprofiles:\n  pr:\n    mode: changed\n")
	if _, _, err := Parse(raw, "test"); err == nil {
		t.Fatal("expected unknown-field failure")
	}
}

func TestParseBadVersionFails(t *testing.T) {
	raw := []byte("apiVersion: secure-dev/v9\nkind: ScanConfiguration\nprofiles:\n  pr:\n    mode: changed\n")
	if _, _, err := Parse(raw, "test"); err == nil {
		t.Fatal("expected version failure")
	}
}

func TestParseUnknownScannerFails(t *testing.T) {
	raw := []byte("apiVersion: secure-dev/v1alpha1\nkind: ScanConfiguration\nprofiles:\n  pr:\n    scanners: [zap-ray]\n")
	if _, _, err := Parse(raw, "test"); err == nil {
		t.Fatal("expected scanner failure")
	}
}

func TestEffectiveDigestStable(t *testing.T) {
	a := Defaults()
	b := Defaults()
	if EffectiveDigest(a) != EffectiveDigest(b) {
		t.Fatal("digest not deterministic")
	}
}

func TestMergeOverlaysPublishAndAI(t *testing.T) {
	base := Defaults()
	over := &ScanConfiguration{
		Publish: Publish{Enabled: true, Provider: "github"},
		AI:      AI{Enabled: true, Mode: "explain-only", SourceContextLines: 10},
	}
	m := Merge(base, over)
	if !m.Publish.Enabled || m.Publish.Provider != "github" {
		t.Fatalf("publish overlay lost: %+v", m.Publish)
	}
	if !m.AI.Enabled || m.AI.SourceContextLines != 10 {
		t.Fatalf("ai overlay lost: %+v", m.AI)
	}
	// Empty overlay keeps defaults.
	m2 := Merge(base, &ScanConfiguration{})
	if m2.Publish.Provider != "auto" || m2.AI.Mode != "explain-only" {
		t.Fatal("defaults clobbered by empty overlay")
	}
}

func TestEnvOverlayNeverTouchesPolicy(t *testing.T) {
	cfg := Defaults()
	before := EffectiveDigest(cfg)
	ApplyEnvOverlay(cfg, func(k string) string {
		if k == "SDT_OUTPUT_DIR" {
			return "out-x"
		}
		return ""
	})
	if cfg.Outputs.Directory != "out-x" {
		t.Fatal("output overlay not applied")
	}
	if EffectiveDigest(cfg) != before {
		t.Fatal("policy digest must not change via env overlay")
	}
}
