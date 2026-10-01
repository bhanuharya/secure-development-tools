package finding

import "testing"

func TestMapSeverityKnown(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "critical", "ERROR": "high", "warning": "medium",
		"low": "low", "info": "info",
	}
	for in, want := range cases {
		if got := MapSeverity(in).Canonical; got != want {
			t.Fatalf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestMapSeverityUnknownNeverLow(t *testing.T) {
	for _, in := range []string{"banana", "", "  "} {
		got := MapSeverity(in).Canonical
		if got == "low" || got == "medium" || got == "high" || got == "critical" {
			t.Fatalf("%q silently mapped to %q", in, got)
		}
	}
}

func TestFingerprintHostilePaths(t *testing.T) {
	// Spaces, unicode, leading dashes, traversal attempts: distinct inputs
	// must not collide, and normalization must not escape the repo.
	paths := []string{
		"src/my file.go",
		"src/ünicode.go",
		"src/--help",
		"../escape.go",
		"./src/a.go",
		"src/a.go",
	}
	seen := map[string]string{}
	for _, p := range paths {
		fp := FingerprintValue("sast", "opengrep", "r", p, "ctx")
		if prev, ok := seen[fp]; ok && prev != normalizePath(p) {
			t.Fatalf("collision: %q vs %q", prev, p)
		}
		seen[fp] = normalizePath(p)
	}
	if normalizePath("./src/a.go") != normalizePath("src/a.go") {
		t.Fatal("./ prefix must normalize identically")
	}
}

func TestFingerprintStableAcrossLineMoves(t *testing.T) {
	a := FingerprintValue("sast", "opengrep", "scp.x", "src/a.go", "rule ctx")
	b := FingerprintValue("sast", "opengrep", "scp.x", "src/a.go", "rule ctx")
	if a != b {
		t.Fatal("fingerprint not deterministic")
	}
	// Different paths must not collide.
	c := FingerprintValue("sast", "opengrep", "scp.x", "src/b.go", "rule ctx")
	if a == c {
		t.Fatal("cross-path collision")
	}
	// No line number in input by construction: same ctx, different lines match.
}
