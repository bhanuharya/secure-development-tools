package scanner

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
)

// fakeSecret derives a random-looking value from a label, so no credential-shaped
// literal is ever committed to this repository.
func fakeSecret(label string, n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		sum := sha256.Sum256([]byte(label + string(rune('a'+i))))
		b.WriteString(strings.NewReplacer("+", "a", "/", "b", "=", "").Replace(base64.StdEncoding.EncodeToString(sum[:])))
	}
	return b.String()[:n]
}

func fakeChecksum(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])[:40]
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// gitleaksHits runs the real engine the way a scan does and returns "rule path" pairs.
func gitleaksHits(t *testing.T, cfg *config.ScanConfiguration, root string) []string {
	t.Helper()
	ctx := testCtx()
	ctx.BaseRevision, ctx.MergeBase = "", "" // current tree
	ctx.CacheRoot = t.TempDir()
	a := &GitleaksAdapter{}
	task, err := a.PlanForProfile(ctx, cfg, root, "pr")
	if err != nil {
		t.Skipf("gitleaks not installed: %v", err)
	}
	if out, err := exec.Command(task.Executable, task.Args...).CombinedOutput(); err != nil {
		t.Fatalf("gitleaks failed: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(task.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	var hits []string
	for _, f := range a.Parse("test", root, raw, "", 0).Findings {
		hits = append(hits, f.Rule.ID+" "+f.Location.Path)
	}
	sort.Strings(hits)
	return hits
}

func TestGitleaksPlanUsesSdtDefaults(t *testing.T) {
	t.Setenv("GITLEAKS_CONFIG", "")
	ctx := testCtx()
	ctx.CacheRoot = t.TempDir()
	task, err := (&GitleaksAdapter{}).PlanForProfile(ctx, config.Defaults(), t.TempDir(), "full")
	if err != nil {
		t.Skipf("gitleaks not installed: %v", err)
	}
	want := filepath.Join(ctx.CacheRoot, "native", "gitleaks-config.toml")
	if !strings.Contains(strings.Join(task.Args, " "), "--config "+want) {
		t.Fatalf("sdt defaults not passed: %v", task.Args)
	}
	body, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), "[extend]\nuseDefault = true\n") {
		t.Fatalf("defaults must extend the built-in rules, got: %.60s", body)
	}
	if task.RuleBundle != "sdt-gitleaks-defaults" || len(task.RuleChecksums) != 1 {
		t.Fatalf("defaults must be recorded for the manifest: %q %v", task.RuleBundle, task.RuleChecksums)
	}
}

func TestGitleaksExplicitConfigWins(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scanners.Gitleaks.Config = "team.toml"
	ctx := testCtx()
	ctx.CacheRoot = t.TempDir()
	task, err := (&GitleaksAdapter{}).PlanForProfile(ctx, cfg, t.TempDir(), "full")
	if err != nil {
		t.Skipf("gitleaks not installed: %v", err)
	}
	joined := strings.Join(task.Args, " ")
	if !strings.Contains(joined, "--config team.toml") || strings.Contains(joined, "gitleaks-config.toml") {
		t.Fatalf("explicit config must replace the defaults: %v", task.Args)
	}
	if task.RuleBundle != "" {
		t.Fatalf("defaults recorded although not used: %q", task.RuleBundle)
	}
}

func TestGitleaksDefaultsExtendRepoConfig(t *testing.T) {
	t.Setenv("GITLEAKS_CONFIG", "")
	root := writeTree(t, map[string]string{".gitleaks.toml": "[extend]\nuseDefault = true\n"})
	cache := t.TempDir()
	path, err := gitleaksDefaultConfig(cache, root)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "path = ") || !strings.Contains(string(body), ".gitleaks.toml") || strings.Contains(string(body), "useDefault") {
		t.Fatalf("repository config must be the extended base, got: %.120s", body)
	}
}

// The noise the defaults remove, the leaks that must survive next to it, and the
// connection-string credentials the built-in rules do not report.
func TestGitleaksDefaultsCutNoiseAndKeepLeaks(t *testing.T) {
	t.Setenv("GITLEAKS_CONFIG", "")
	firebaseKey := "AIza" + fakeSecret("firebase", 35)
	root := writeTree(t, map[string]string{
		// Cut: package checksums next to a name containing "auth"/"key".
		"ios/Podfile.lock": "SPEC CHECKSUMS:\n  local_auth_darwin: " + fakeChecksum("a") + "\n",
		"pubspec.lock":     "  secret_key_store: " + fakeChecksum("b") + "\n",
		// Cut: Firebase client keys in generated app configuration.
		"android/app/google-services.json": `{"api_key":[{"current_key":"` + firebaseKey + `"}],` + "\n" +
			`"server_api_secret": "` + fakeSecret("server", 30) + `"}` + "\n",
		"lib/firebase_options.dart": "  apiKey: '" + firebaseKey + "',\n",
		// Keep: the same key anywhere else, and ordinary hardcoded secrets.
		"lib/maps.dart": "const mapsKey = '" + firebaseKey + "';\n",
		"src/main/resources/application-dev.yml": "oss:\n  access-key-secret: " + fakeSecret("oss", 24) + "\n" +
			"  url: jdbc:mysql://db.internal:3306/app?user=app&password=" + fakeSecret("jdbc", 12) + "\n",
		// Added: passwords inside connection URLs.
		"src/db.ts": `const a = "postgres://app:` + fakeSecret("pg", 14) + `@db.internal:5432/app";` + "\n",
		// Not secrets: placeholders, template variables, local and documentation hosts.
		"src/safe.ts": strings.Join([]string{
			`const a = "postgres://app:${DB_PASSWORD}@db.internal/app";`,
			`const b = "https://user:password@example.com/x";`,
			`const c = "postgres://postgres:postgres@localhost:5432/dev";`,
			`const d = "mysql://user:<password>@host/db";`,
			`const e = "amqp://guest:guest@127.0.0.1:5672";`,
			`const f = "jdbc:mysql://h/db?user=a&password=${DB_PASS}";`,
			`const g = "git@github.com:org/repo.git";`,
		}, "\n") + "\n",
	})
	got := strings.Join(gitleaksHits(t, config.Defaults(), root), "\n")
	want := strings.Join([]string{
		"gcp-api-key lib/maps.dart",
		"generic-api-key android/app/google-services.json",
		"generic-api-key src/main/resources/application-dev.yml",
		"sdt-jdbc-url-password src/main/resources/application-dev.yml",
		"sdt-url-embedded-credentials src/db.ts",
	}, "\n")
	if got != want {
		t.Fatalf("findings with sdt defaults:\n%s\n\nwant:\n%s", got, want)
	}
}

// A repository's own path allowlist keeps working, and the sdt rules still run.
func TestGitleaksRepoAllowlistComposesWithDefaults(t *testing.T) {
	t.Setenv("GITLEAKS_CONFIG", "")
	root := writeTree(t, map[string]string{
		".gitleaks.toml":   "[extend]\nuseDefault = true\n\n[allowlist]\ndescription = \"mock dataset\"\npaths = ['''(?:^|/)src/mock/''']\n",
		"src/mock/data.ts": `{ "sg_key": "` + fakeSecret("mock", 24) + `" }` + "\n",
		"src/db.ts":        `const a = "postgres://app:` + fakeSecret("pg", 14) + `@db.internal:5432/app";` + "\n",
		"ios/Podfile.lock": "  local_auth_darwin: " + fakeChecksum("a") + "\n",
	})
	got := strings.Join(gitleaksHits(t, config.Defaults(), root), "\n")
	if want := "sdt-url-embedded-credentials src/db.ts"; got != want {
		t.Fatalf("findings:\n%s\n\nwant:\n%s", got, want)
	}
}
