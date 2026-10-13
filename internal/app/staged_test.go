package app

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
)

func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	git(t, repo, "init", "-q", "-b", "main", ".")
	git(t, repo, "config", "user.email", "dev@example.invalid")
	git(t, repo, "config", "user.name", "dev")
	return repo
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func at(path string, first, last int) *finding.Finding {
	f := &finding.Finding{ID: path, Category: finding.CatSAST, Location: &finding.Location{Path: path}}
	if first > 0 {
		f.Location.StartLine, f.Location.EndLine = &first, &last
	}
	return f
}

// The lines a commit adds are read from the patch: per file, the new side of
// every hunk. A hunk that only removes lines adds none.
func TestAddedLinesAreTheNewSideOfEveryHunk(t *testing.T) {
	patch := strings.Join([]string{
		"diff --git a/new.py b/new.py",
		"new file mode 100644",
		"--- /dev/null",
		"+++ b/new.py",
		"@@ -0,0 +1,3 @@",
		"+a", "+b", "+c",
		"diff --git a/old.go b/old.go",
		"--- a/old.go",
		"+++ b/old.go",
		"@@ -4 +4 @@ func f() {",
		"-x", "+y",
		"@@ -10,2 +9,0 @@",
		"-gone", "-gone too",
		"@@ -20,0 +18,2 @@",
		// An added line that reads like a header of the patch.
		"+++ b/not-a-file", "+z",
		`\ No newline at end of file`,
		"diff --git a/was.txt b/now.txt",
		"similarity index 100%",
		"rename from was.txt",
		"rename to now.txt",
		"diff --git a/my file.txt b/my file.txt",
		"--- a/my file.txt\t",
		"+++ b/my file.txt\t",
		"@@ -1 +1,2 @@",
		"-a", "+a", "+b",
		`diff --git "a/qu\"ote.txt" "b/qu\"ote.txt"`,
		`--- "a/qu\"ote.txt"`,
		`+++ "b/qu\"ote.txt"`,
		"@@ -0,0 +1 @@",
		"+a",
		"diff --git a/image.png b/image.png",
		"Binary files a/image.png and b/image.png differ",
		"",
	}, "\n")
	want := map[string][]lineRange{
		"new.py":      {{1, 3}},
		"old.go":      {{4, 4}, {18, 19}},
		"my file.txt": {{1, 2}},
		`qu"ote.txt`:  {{1, 1}},
	}
	if got := addedLines(patch); !reflect.DeepEqual(got, want) {
		t.Fatalf("added lines = %v\nwant %v", got, want)
	}
}

// A finding counts for a commit when it is on a line the commit adds or
// changes. One on an untouched line of the same file was there before.
func TestOnlyFindingsOnAddedLinesAreKept(t *testing.T) {
	added := map[string][]lineRange{"a.py": {{10, 12}, {30, 30}}}
	in := []*finding.Finding{
		at("a.py", 11, 11), at("a.py", 30, 30), at("a.py", 8, 10), at("a.py", 12, 40), at("a.py", 0, 0),
		at("a.py", 9, 9), at("a.py", 13, 29), at("other.py", 11, 11),
		{ID: "no location", Category: finding.CatSecret},
	}
	kept, left := onAddedLines(in, added)
	if len(kept) != 5 || left != 4 {
		t.Fatalf("kept %d and left %d, want 5 and 4", len(kept), left)
	}
	for _, f := range kept[:4] {
		if f.Location.Path != "a.py" || *f.Location.StartLine > 30 || *f.Location.EndLine < 10 {
			t.Fatalf("kept a finding off the added lines: %s %d-%d", f.Location.Path, *f.Location.StartLine, *f.Location.EndLine)
		}
	}
}

// The scanners are given the files as they are staged. What is changed but not
// staged, not tracked or deleted is not in the commit and not in the snapshot.
func TestStagedSnapshotHoldsTheIndexNotTheWorkingTree(t *testing.T) {
	repo := gitRepo(t)
	write(t, repo, "app/a.py", "one\ntwo\nthree\n")
	write(t, repo, "app/gone.py", "x\n")
	write(t, repo, "app/same.py", "x\n")
	write(t, repo, ".gitleaksignore", "abc\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "first")

	write(t, repo, "app/a.py", "one\nTWO\nthree\nfour\n")
	git(t, repo, "add", "app/a.py")
	write(t, repo, "app/a.py", "one\nTWO\nthree\nfour\nnot staged\n")
	write(t, repo, "app/untracked.py", "x\n")
	git(t, repo, "rm", "-q", "app/gone.py")

	snapshot, err := newStagedSnapshot(filepath.Join(repo, "app"))
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string][]lineRange{"app/a.py": {{2, 2}, {4, 4}}}; !reflect.DeepEqual(snapshot.added, want) {
		t.Fatalf("added lines = %v, want %v", snapshot.added, want)
	}
	staged, err := os.ReadFile(filepath.Join(snapshot.dir, "app", "a.py"))
	if err != nil || string(staged) != "one\nTWO\nthree\nfour\n" {
		t.Fatalf("the snapshot holds %q (%v), want the staged content", staged, err)
	}
	if _, err := os.Stat(filepath.Join(snapshot.dir, ".gitleaksignore")); err != nil {
		t.Errorf("the repository's scanner settings are not in the snapshot: %v", err)
	}
	for _, absent := range []string{"app/gone.py", "app/same.py", "app/untracked.py"} {
		if _, err := os.Stat(filepath.Join(snapshot.dir, filepath.FromSlash(absent))); err == nil {
			t.Errorf("%s is in the snapshot and not in the commit", absent)
		}
	}
	snapshot.Close()
	if _, err := os.Stat(snapshot.dir); err == nil {
		t.Errorf("%s is left behind", snapshot.dir)
	}
}

// A commit that only removes, renames or changes modes has nothing to scan.
func TestACommitThatAddsNoLinesNeedsNoSnapshot(t *testing.T) {
	repo := gitRepo(t)
	write(t, repo, "a.py", "one\ntwo\n")
	write(t, repo, "b.py", "x\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "first")
	write(t, repo, "a.py", "one\n")
	git(t, repo, "add", "-A")
	git(t, repo, "mv", "b.py", "c.py")
	snapshot, err := newStagedSnapshot(repo)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if len(snapshot.added) != 0 || snapshot.dir != "" {
		t.Fatalf("added = %v, dir = %q: want nothing", snapshot.added, snapshot.dir)
	}
}

// Reports and cache of a staged scan go below the git directory: nothing for
// `git add -A` to pick up.
func TestStagedStateIsKeptInTheGitDirectory(t *testing.T) {
	repo := gitRepo(t)
	state, err := stagedStateDir(repo)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(repo, ".git", "sdt"); state != want {
		t.Fatalf("state directory = %s, want %s", state, want)
	}
	if mergeInProgress(repo) {
		t.Fatal("a new repository is not in a merge")
	}
}

// The hook goes where git looks for it, also when core.hooksPath names the
// folder, and a hook that sdt did not write is neither replaced nor removed.
func TestHookIsInstalledWhereGitLooksAndForeignHooksAreKept(t *testing.T) {
	repo := gitRepo(t)
	t.Chdir(repo)
	path, err := installHook(false)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(repo, ".git", "hooks", "pre-commit"); path != want {
		t.Fatalf("hook written to %s, want %s", path, want)
	}
	if _, err := installHook(false); err != nil {
		t.Fatalf("installing over sdt's own hook must work: %v", err)
	}

	git(t, repo, "config", "core.hooksPath", ".husky")
	write(t, repo, ".husky/pre-commit", "#!/bin/sh\nnpm test\n")
	if _, err := installHook(false); err == nil || !strings.Contains(err.Error(), "sdt scan --staged") {
		t.Fatalf("a foreign hook must be kept, with the line to add in the message: %v", err)
	}
	if kept, _ := os.ReadFile(filepath.Join(repo, ".husky", "pre-commit")); !strings.Contains(string(kept), "npm test") {
		t.Fatal("the foreign hook was changed")
	}
	if path, err = installHook(true); err != nil || path != filepath.Join(repo, ".husky", "pre-commit") {
		t.Fatalf("--force writes to the configured folder: %s, %v", path, err)
	}
}

// What the person committing reads names the file and line, says what blocks,
// and says how to commit anyway.
func TestStagedSummaryNamesThePlaceAndTheWayOut(t *testing.T) {
	staged.files, staged.note = 2, ""
	sqli := at("app/report.py", 7, 7)
	sqli.ID, sqli.Rule.ID, sqli.Severity.Canonical = "1", "vendor.semgrep.python.django.tainted-sql-string", finding.SevHigh
	sqli.Message = "Detected user input used to manually construct a SQL string. This is usually bad practice."
	same := at("app/report.py", 7, 7)
	same.ID, same.Rule.ID, same.Severity.Canonical = "2", "vendor.semgrep.python.sqlalchemy.raw-query", finding.SevMedium
	note := at("app/util.py", 3, 3)
	note.ID, note.Rule.ID, note.Severity.Canonical = "3", "scp.python.misc.debug", finding.SevLow
	out := policy.Outcome{Status: "policy_failed", Blockers: []policy.Match{{FindingID: "1", RuleID: "block-new-high-sast"}}}
	text := stagedSummary("policy_failed", []*finding.Finding{note, same, sqli}, out, nil, filepath.Join(".git", "sdt", "reports"), time.Second)
	for _, want := range []string{
		"1 problem in the lines being committed",
		"app/report.py:7  high  tainted-sql-string  (+1 more rule on this line)",
		"Detected user input used to manually construct a SQL string.",
		"app/util.py:3  low  misc.debug  (does not block)",
		stagedBypass,
		filepath.Join(".git", "sdt", "reports", "findings.json"),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the summary lacks %q:\n%s", want, text)
		}
	}
	if strings.Index(text, "app/report.py") > strings.Index(text, "app/util.py") {
		t.Errorf("what blocks comes first:\n%s", text)
	}
	if passed := stagedSummary("passed", nil, policy.Outcome{Status: "passed"}, nil, "reports", time.Second); !strings.Contains(passed, "nothing found (2 files") {
		t.Errorf("a clean commit gets one line: %q", passed)
	}
}

// The whole path, with the real scanners: a weakness the commit adds blocks it
// and is named with file and line; one that was in the file before does not
// count; nothing is left in the working tree.
func TestStagedScanReportsOnlyWhatTheCommitAdds(t *testing.T) {
	for _, tool := range []string{"git", "opengrep", "gitleaks"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	source, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	sample := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(source, "testdata", "detection", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	repo := gitRepo(t)
	write(t, repo, "app/legacy.py", sample("python/sqli.py"))
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "first")
	write(t, repo, "app/legacy.py", sample("python/sqli.py")+"\n\ndef version():\n    return \"1.0\"\n")
	write(t, repo, "app/ping.js", sample("node/cmd.js"))
	git(t, repo, "add", "-A")

	t.Chdir(repo)
	t.Setenv("SDT_RULES_PACK_DIR", filepath.Join(source, "rules", "opengrep-rules"))
	for _, unset := range []string{"SDT_OUTPUT_DIR", "SDT_CACHE_DIR", "SDT_CONFIG", "SDT_BASE"} {
		t.Setenv(unset, "")
	}
	var out bytes.Buffer
	root := NewRoot()
	root.SetArgs([]string{"scan", "--staged"})
	root.SetOut(&out)
	root.SetErr(&out)
	err = root.Execute()
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != ExitPolicyFailed {
		t.Fatalf("want the commit blocked by policy, got %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "app/ping.js:") {
		t.Errorf("the added weakness is not named with its file and line:\n%s", out.String())
	}
	if strings.Contains(out.String(), "app/legacy.py") {
		t.Errorf("a weakness that was in the file before is reported:\n%s", out.String())
	}
	if status := git(t, repo, "status", "--porcelain", "--untracked-files=all"); strings.Contains(status, "??") {
		t.Errorf("the scan left files in the working tree:\n%s", status)
	}
}
