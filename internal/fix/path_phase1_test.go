package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func mapOf(f *finding.Finding) map[*finding.Finding]Transform {
	return map[*finding.Finding]Transform{f: registered("py-hashlib-sha256/v1")}
}

// Absolute finding paths must never be written outside the scan root.
func TestRefusesAbsolutePath(t *testing.T) {
	root := t.TempDir()
	f := locFinding("f1", "scp.python.crypto.weak-md5", "/etc/passwd", 1)
	edits, skipped := Preview(root, mapOf(f))
	if len(edits) != 0 {
		t.Fatalf("absolute path must produce no edits, got %+v", edits)
	}
	if len(skipped) == 0 || !strings.Contains(strings.Join(skipped, " "), "absolute") {
		t.Fatalf("absolute path must be skipped loudly, got %v", skipped)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "passwd")); !os.IsNotExist(err) {
		t.Fatal("absolute path escaped root")
	}
}

// Parent traversal must be refused.
func TestRefusesParentTraversal(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "ok.py", "h = hashlib.md5(x)\n")
	f := locFinding("f1", "scp.python.crypto.weak-md5", "../escape.py", 1)
	edits, skipped := Preview(root, mapOf(f))
	if len(edits) != 0 || len(skipped) == 0 {
		t.Fatalf("traversal must be refused: edits=%v skipped=%v", edits, skipped)
	}
	parent := filepath.Dir(root)
	if _, err := os.Stat(filepath.Join(parent, "escape.py")); !os.IsNotExist(err) {
		t.Fatal("traversal escaped root")
	}
}

// Symlinks resolving outside the root must be refused on preview and apply.
func TestRefusesSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "real.py")
	if err := os.WriteFile(target, []byte("h = hashlib.md5(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.py")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unsupported: " + err.Error())
	}
	f := locFinding("f1", "scp.python.crypto.weak-md5", "link.py", 1)
	edits, skipped := Preview(root, mapOf(f))
	if len(edits) != 0 || len(skipped) == 0 {
		t.Fatalf("symlink escape must be refused: edits=%v skipped=%v", edits, skipped)
	}
	if _, err := ApplyEdits(root, mapOf(f), true); err == nil {
		raw, _ := os.ReadFile(target)
		if strings.Contains(string(raw), "sha256") {
			t.Fatal("symlink target outside root was modified")
		}
	}
	raw, _ := os.ReadFile(target)
	if strings.Contains(string(raw), "sha256") {
		t.Fatal("symlink target outside root was modified")
	}
}

func TestRefusesInRootSymlink(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "real.py", "h = hashlib.md5(x)\n")
	if err := os.Symlink("real.py", filepath.Join(root, "link.py")); err != nil {
		t.Skip("symlinks unsupported: " + err.Error())
	}
	f := locFinding("f1", "scp.python.crypto.weak-md5", "link.py", 1)
	edits, skipped := Preview(root, mapOf(f))
	if len(edits) != 0 || len(skipped) == 0 {
		t.Fatalf("in-root symlink must be refused: edits=%v skipped=%v", edits, skipped)
	}
}

// A legitimate in-root file still fixes (no over-blocking).
func TestInRootStillFixes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.py", "h = hashlib.md5(x)\n")
	edits, _ := Preview(root, mapOf(locFinding("f1", "scp.python.crypto.weak-md5", "a.py", 1)))
	if len(edits) != 1 {
		t.Fatalf("in-root fix blocked: %+v", edits)
	}
}
