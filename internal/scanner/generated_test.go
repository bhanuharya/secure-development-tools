package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
)

func writeSource(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// written is about `size` bytes of source in lines of `width` characters.
func written(size, width int) string {
	line := strings.Repeat("x", width-1) + "\n"
	return strings.Repeat(line, size/width+1)
}

// Minified and generated files are recognised by what is in them, wherever
// they sit and whatever they are called; hand-written code never is.
func TestMachineWrittenFilesAreFoundByContent(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app.js", strings.Repeat("x", 30_000))                           // one line: a bundle without .min in its name
	writeSource(t, root, "static/dense.css", written(30_000, 400))                        // long lines throughout
	writeSource(t, root, "pages/[id].js", written(40_000, 80)+strings.Repeat("y", 6_000)) // one long line among ordinary ones
	writeSource(t, root, "src/app.js", written(30_000, 80))                               // hand-written, same name as the bundle
	writeSource(t, root, "src/small.js", strings.Repeat("x", 6_000))                      // too small to matter
	writeSource(t, root, "src/logo.png", strings.Repeat("x", 30_000))                     // not source code
	writeSource(t, root, "node_modules/lib/index.js", strings.Repeat("x", 30_000))        // directory already left out
	writeSource(t, root, "static/lib.min.js", strings.Repeat("x", 30_000))                // name already left out

	var got []string
	for _, file := range generatedFiles(root) {
		got = append(got, file.Path)
	}
	want := []string{"pages/[id].js", "static/dense.css", "app.js"} // largest first
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("machine-written files = %v, want %v", got, want)
	}
}

// Each file is excluded by its full path, so the bundle app.js does not take
// the hand-written src/app.js with it, and glob characters in a name are literal.
func TestGeneratedFilesAreExcludedByExactPath(t *testing.T) {
	files := []generatedFile{{"pages/[id].js", 46_000}, {"app.js", 30_000}}
	args, skipped, note := excludeFiles("/repo", files, generatedArgBytes)
	wantArgs := []string{"--exclude", "/repo/pages/[[]id].js", "--exclude", "/repo/app.js"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("arguments = %v, want %v", args, wantArgs)
	}
	if want := []string{"app.js", "pages/[id].js"}; !reflect.DeepEqual(skipped, want) {
		t.Fatalf("skipped = %v, want %v", skipped, want)
	}
	if want := "2 minified or generated files (0.1 MB) were not analysed by the code scan"; note != want {
		t.Fatalf("note = %q, want %q", note, want)
	}
	if args, skipped, note := excludeFiles("/repo", nil, generatedArgBytes); args != nil || skipped != nil || note != "" {
		t.Fatalf("nothing to leave out must add nothing, got %v %v %q", args, skipped, note)
	}
}

// A repository with more generated files than a command line holds still
// scans: the largest are left out, and the note says the rest were analysed.
func TestExclusionsStayWithinTheCommandLineBudget(t *testing.T) {
	var files []generatedFile
	for i := 0; i < 100; i++ {
		files = append(files, generatedFile{fmt.Sprintf("dist/chunk-%03d.js", i), int64(100_000 - i)})
	}
	args, skipped, note := excludeFiles("/repo", files, 400)
	size := 0
	for _, arg := range args {
		size += len(arg) + 1
	}
	if len(skipped) == 0 || len(skipped) == len(files) || size > 400 {
		t.Fatalf("%d of %d files excluded in %d bytes, want some within 400", len(skipped), len(files), size)
	}
	if skipped[0] != "dist/chunk-000.js" {
		t.Fatalf("the largest file must be left out first, got %v", skipped[:1])
	}
	if !strings.Contains(note, fmt.Sprintf("%d smaller ones were analysed", len(files)-len(skipped))) {
		t.Fatalf("the note must say what was still analysed: %q", note)
	}
}

func fakeOpengrep(t *testing.T) {
	t.Helper()
	fake := filepath.Join(t.TempDir(), "opengrep")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SDT_OPENGREP_BIN", fake)
}

// The plan leaves the bundle out, records it for the run manifest, and can be
// told to scan generated files after all.
func TestOpengrepPlanLeavesGeneratedFilesOutAndSaysSo(t *testing.T) {
	withRulePack(t)
	fakeOpengrep(t)
	root := t.TempDir()
	writeSource(t, root, "bundle.js", strings.Repeat("x", 30_000))
	writeSource(t, root, "src/app.js", written(30_000, 80))

	task, err := (&OpengrepAdapter{}).Plan(testCtx(), config.Defaults(), root)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(task.Args, " ")
	if !strings.Contains(joined, "--exclude "+filepath.Join(root, "bundle.js")) || strings.Contains(joined, filepath.Join(root, "src")) {
		t.Fatalf("only the bundle must be excluded, got: %s", joined)
	}
	if !reflect.DeepEqual(task.SkippedFiles, []string{"bundle.js"}) || !strings.HasPrefix(task.Note, "1 minified or generated file ") {
		t.Fatalf("the plan must record what it left out, got %v %q", task.SkippedFiles, task.Note)
	}
	if task.Args[len(task.Args)-1] != root {
		t.Fatalf("the scan target must stay the last argument, got %q", task.Args[len(task.Args)-1])
	}

	t.Setenv("SDT_SCAN_GENERATED_FILES", "1")
	task, err = (&OpengrepAdapter{}).Plan(testCtx(), config.Defaults(), root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(task.Args, " "), "bundle.js") || task.Note != "" {
		t.Fatalf("SDT_SCAN_GENERATED_FILES=1 must scan everything, got note %q", task.Note)
	}
}

// SDT_SCAN_THREADS caps the cores of the code scanner, so two scans fit on a
// small machine; unset or invalid, the scanner keeps its own default.
func TestOpengrepPlanUsesTheThreadLimit(t *testing.T) {
	withRulePack(t)
	fakeOpengrep(t)
	for value, want := range map[string]string{"": "", "2": "-j 2", " 3 ": "-j 3", "0": "", "-1": "", "many": ""} {
		t.Setenv("SDT_SCAN_THREADS", value)
		task, err := (&OpengrepAdapter{}).Plan(testCtx(), config.Defaults(), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		joined := " " + strings.Join(task.Args, " ") + " "
		if want == "" && strings.Contains(joined, " -j ") {
			t.Errorf("SDT_SCAN_THREADS=%q must not limit threads, got: %s", value, joined)
		}
		if want != "" && !strings.Contains(joined, " "+want+" ") {
			t.Errorf("SDT_SCAN_THREADS=%q must pass %q, got: %s", value, want, joined)
		}
	}
}

// End to end with the real engine: the exclusion removes exactly the generated
// file, not the hand-written file with the same name in another directory.
func TestRealEngineSkipsOnlyTheGeneratedFile(t *testing.T) {
	bin := whichBin(envOr("SDT_OPENGREP_BIN", "opengrep"))
	if bin == "" || strings.Contains(filepath.Base(bin), "semgrep") {
		t.Skip("opengrep binary not installed")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	call := "function run(input) { return eval(input); }\n"
	writeSource(t, root, "app.js", call+strings.Repeat("x", 30_000))
	writeSource(t, root, "pages/[id].js", call+strings.Repeat("x", 30_000))
	writeSource(t, root, "src/app.js", call+written(30_000, 80))
	writeSource(t, root, "src/pages/[id].js", call)
	rule := filepath.Join(t.TempDir(), "rule.yaml")
	if err := os.WriteFile(rule, []byte("rules:\n  - id: uses-eval\n    languages: [javascript]\n    severity: ERROR\n    message: eval\n    pattern: eval(...)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	excludes, skipped, _ := skipGenerated(root)
	if want := []string{"app.js", "pages/[id].js"}; !reflect.DeepEqual(skipped, want) {
		t.Fatalf("skipped = %v, want %v", skipped, want)
	}
	args := append([]string{"scan", "--json", "--no-git-ignore", "-q", "--config", rule}, excludes...)
	out, err := exec.Command(bin, append(args, root)...).Output()
	if err != nil && len(out) == 0 {
		t.Fatalf("opengrep failed: %v", err)
	}
	var data struct {
		Results []struct {
			Path string `json:"path"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		t.Fatalf("invalid opengrep JSON: %v", err)
	}
	found := map[string]bool{}
	for _, result := range data.Results {
		rel, _ := filepath.Rel(root, result.Path)
		found[filepath.ToSlash(rel)] = true
	}
	if want := map[string]bool{"src/app.js": true, "src/pages/[id].js": true}; !reflect.DeepEqual(found, want) {
		t.Fatalf("findings in %v, want exactly %v", found, want)
	}
}
