package scanner

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every TOML string form reads as the value Gitleaks would see.
func TestParseGitleaksRepoConfigReadsEveryStringForm(t *testing.T) {
	text := strings.Join([]string{
		`[extend]`,
		`useDefault = true # keep the built-in rules`,
		`path = "shared/gitleaks.toml"`,
		``,
		`[allowlist]`,
		`description = "fixtures"`,
		`paths = [`,
		`  '''(?:^|/)a/[^/]+\.txt''',`,
		`  'b/[0-9]+',`,
		`  "c\\d\"q",`,
		`  """`,
		`d/""x""",`,
		`]`,
		`regexes = ["""line \`,
		`    joined"""]`,
	}, "\n") + "\n"
	cfg, err := parseGitleaksRepoConfig(text)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.extendPath != "shared/gitleaks.toml" || cfg.useDefaultFalse {
		t.Fatalf("extend: path %q useDefaultFalse %v", cfg.extendPath, cfg.useDefaultFalse)
	}
	if len(cfg.allowlists) != 1 {
		t.Fatalf("want 1 allowlist, got %d", len(cfg.allowlists))
	}
	al := cfg.allowlists[0]
	wantPaths := []string{`(?:^|/)a/[^/]+\.txt`, `b/[0-9]+`, `c\d"q`, `d/""x`}
	if !reflect.DeepEqual(al.paths, wantPaths) {
		t.Fatalf("paths:\n got %q\nwant %q", al.paths, wantPaths)
	}
	if want := []string{"line joined"}; !reflect.DeepEqual(al.regexes, want) {
		t.Fatalf("regexes: got %q want %q", al.regexes, want)
	}
}

// An [extend] path is followed: a catch-all in the file it names counts, and a file
// outside the repository is not extended at all.
func TestGitleaksRepoConfigFollowsExtendPath(t *testing.T) {
	cases := []struct {
		name, other, extend string
		unsafe              bool
	}{
		{"extended file has a catch-all", "[allowlist]\npaths = ['''.*''']\n", "shared/gitleaks.toml", true},
		{"extended file is narrow", "[allowlist]\npaths = ['''(?:^|/)docs/''']\n", "shared/gitleaks.toml", false},
		{"extended file outside the repository", "", "../elsewhere.toml", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			if tc.other != "" {
				if err := os.MkdirAll(filepath.Join(repo, "shared"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(repo, "shared", "gitleaks.toml"), []byte(tc.other), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cfgPath := filepath.Join(repo, ".gitleaks.toml")
			if err := os.WriteFile(cfgPath, []byte("[extend]\npath = \""+tc.extend+"\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			reason := unsafeRepoGitleaksReason(cfgPath)
			if (reason != "") != tc.unsafe {
				t.Fatalf("unsafe=%v want %v (reason %q)", reason != "", tc.unsafe, reason)
			}
		})
	}
}
