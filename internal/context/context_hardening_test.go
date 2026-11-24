package context

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func initTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, string(out))
		}
	}
	run("init", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "-m", "init")
	return dir
}

func TestResolveRejectsLeadingDashGitRefs(t *testing.T) {
	repo := initTestRepo(t)

	for _, bad := range []string{"-flag", "--upload-pack=evil", "HEAD\n--flag", "bad ref"} {
		if _, _, err := Resolve(Inputs{Head: bad}, repo); err == nil {
			t.Errorf("expected Resolve to reject head=%q", bad)
		}
		if _, _, err := Resolve(Inputs{Head: "HEAD", Base: bad}, repo); err == nil {
			t.Errorf("expected Resolve to reject base=%q", bad)
		} else if !strings.Contains(err.Error(), "invalid base") {
			t.Errorf("expected clear invalid base error for %q, got %v", bad, err)
		}
	}
}
