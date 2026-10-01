package context

import (
	"os"
	"os/exec"
	"testing"
)

// Equivalence: identical inputs always yield identical digests (PRD NFR-001).
func TestDigestDeterministic(t *testing.T) {
	mk := func() *ScanContext {
		return &ScanContext{
			SchemaVersion: SchemaVersion, Event: EventPullRequest,
			HeadRevision: "abc", BaseRevision: "def", MergeBase: "def",
			ChangedPaths: []string{"b.go", "a.go"},
		}
	}
	if mk().Digest() != mk().Digest() {
		t.Fatal("context digest not deterministic")
	}
	other := mk()
	other.BaseRevision = "xyz"
	if mk().Digest() == other.Digest() {
		t.Fatal("different contexts must digest differently")
	}
}

func TestInvalidEvent(t *testing.T) {
	_, _, err := Resolve(Inputs{Event: "carrier-pigeon"}, t.TempDir())
	if err == nil {
		t.Fatal("expected invalid event error")
	}
}

func gitOK() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// Shallow clones must be detected so profiles can fail/inconclusive (CTX-003).
func TestShallowDetected(t *testing.T) {
	if !gitOK() {
		t.Skip("git not installed")
	}
	src := t.TempDir()
	run := func(dir string, args ...string) {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = dir
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run(src, "init", "-q")
	if err := os.WriteFile(src+"/f.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(src, "add", "-A")
	run(src, "commit", "-qm", "one")
	shallow := t.TempDir() + "/shallow"
	if out, err := exec.Command("git", "clone", "-q", "--depth", "1", "file://"+src, shallow).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	if !isShallow(shallow) {
		t.Fatal("shallow clone not detected")
	}
	if isShallow(src) {
		t.Fatal("full clone misreported as shallow")
	}
	ctx, _, err := Resolve(Inputs{Head: "HEAD"}, shallow)
	if err != nil {
		t.Fatal(err)
	}
	if !ctx.Shallow {
		t.Fatal("context must flag shallow history")
	}
}

// Staged mode resolves ChangedPaths from the index, flags the context, and
// digests differently from the same tree scanned committed.
func TestStagedResolvesIndex(t *testing.T) {
	if !gitOK() {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = repo
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(repo+"/a.go", []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-qm", "one")
	if err := os.WriteFile(repo+"/b.go", []byte("package b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "b.go")
	if err := os.WriteFile(repo+"/c.go", []byte("package c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// c.go is untracked: invisible to staged mode by design.
	staged, _, err := Resolve(Inputs{Head: "HEAD", Staged: true}, repo)
	if err != nil {
		t.Fatal(err)
	}
	if !staged.Staged {
		t.Fatal("context must flag staged mode")
	}
	if len(staged.ChangedPaths) != 1 || staged.ChangedPaths[0] != "b.go" {
		t.Fatalf("staged paths = %v, want [b.go]", staged.ChangedPaths)
	}
	committed, _, err := Resolve(Inputs{Head: "HEAD"}, repo)
	if err != nil {
		t.Fatal(err)
	}
	if staged.Digest() == committed.Digest() {
		t.Fatal("staged and committed contexts must never digest identically")
	}
}
