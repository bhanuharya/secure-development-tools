package app

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// lineRange is a run of lines in a file, both ends included.
type lineRange struct{ first, last int }

// stagedSnapshot is what a commit is about to add: for every file the commit
// adds lines to, those lines, and the file as it stands in the index, written
// to a directory of its own.
//
// The scanners run on that directory, not on the working tree. They then see
// exactly what will be committed (a file can be staged in part), and they read
// a handful of files however large the repository is.
type stagedSnapshot struct {
	dir   string
	added map[string][]lineRange
}

// Tracked files that steer the scanners. They are copied next to the staged
// files so that a repository's own allowlists apply here as they do in CI.
var scannerSettingsFiles = []string{".gitleaks.toml", ".gitleaksignore", ".semgrepignore"}

func newStagedSnapshot(root string) (*stagedSnapshot, error) {
	top, err := gitIn(root, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("--staged needs a git worktree: %w", err)
	}
	top = strings.TrimSpace(top)
	// Every option that a user's git configuration could change is set here:
	// the two prefixes, colour, an external diff program, renames.
	patch, err := gitIn(top, "-c", "core.quotePath=false", "diff", "--cached", "--no-color", "--no-ext-diff",
		"--no-textconv", "--ignore-submodules=all", "-U0", "-M", "--diff-filter=ACMR", "--src-prefix=a/", "--dst-prefix=b/")
	if err != nil {
		return nil, fmt.Errorf("read the staged changes: %w", err)
	}
	snapshot := &stagedSnapshot{added: addedLines(patch)}
	if len(snapshot.added) == 0 {
		return snapshot, nil
	}
	dir, err := os.MkdirTemp("", "sdt-staged-")
	if err != nil {
		return nil, err
	}
	// The scanners report paths below the directory they were given; a
	// temporary directory behind a symbolic link would not match them.
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	snapshot.dir = dir
	var paths bytes.Buffer
	for _, path := range snapshot.files() {
		paths.WriteString(path)
		paths.WriteByte(0)
	}
	// Only the settings files that are tracked: asking for one that is not
	// fails the whole checkout.
	if tracked, err := gitIn(top, append([]string{"ls-files", "-z", "--"}, scannerSettingsFiles...)...); err == nil {
		for _, path := range strings.Split(tracked, "\x00") {
			if path != "" && snapshot.added[path] == nil {
				paths.WriteString(path)
				paths.WriteByte(0)
			}
		}
	}
	checkout := exec.Command("git", "checkout-index", "--prefix="+dir+string(filepath.Separator), "-z", "--stdin")
	checkout.Dir = top
	checkout.Stdin = &paths
	if out, err := checkout.CombinedOutput(); err != nil {
		snapshot.Close()
		return nil, fmt.Errorf("write the staged files to %s: %v: %s", dir, err, strings.TrimSpace(string(out)))
	}
	return snapshot, nil
}

func (s *stagedSnapshot) Close() {
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
	}
}

func (s *stagedSnapshot) files() []string {
	files := make([]string, 0, len(s.added))
	for path := range s.added {
		files = append(files, path)
	}
	sort.Strings(files)
	return files
}

// addedLines reads a patch made with -U0 and returns, per file, the lines the
// new side adds or changes. A file that is only deleted, renamed or given
// another mode adds no lines and is not in the result.
func addedLines(patch string) map[string][]lineRange {
	added := map[string][]lineRange{}
	path := ""
	// A line of the change itself can look like a header ("+++ b/x" is the
	// added line "++ b/x"), so the lines of each hunk are counted off.
	body := 0
	for _, line := range strings.Split(patch, "\n") {
		if body > 0 {
			if !strings.HasPrefix(line, `\`) {
				body--
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "diff --git "):
			path = ""
		case strings.HasPrefix(line, "+++ "):
			path = patchPath(line[len("+++ "):])
		case strings.HasPrefix(line, "@@ "):
			removed, first, count, ok := hunk(line)
			if !ok {
				continue
			}
			body = removed + count
			if path != "" && count > 0 {
				added[path] = append(added[path], lineRange{first, first + count - 1})
			}
		}
	}
	return added
}

// patchPath is the file named on a "+++" line: quoted when the name has
// characters git escapes, followed by a tab when it has spaces.
func patchPath(name string) string {
	name = strings.TrimSuffix(name, "\r")
	name = strings.TrimSuffix(name, "\t")
	if strings.HasPrefix(name, `"`) {
		unquoted, err := strconv.Unquote(name)
		if err != nil {
			return ""
		}
		name = unquoted
	}
	if !strings.HasPrefix(name, "b/") {
		return "" // /dev/null
	}
	return name[len("b/"):]
}

// hunk reads "@@ -12,3 +14,2 @@": how many lines the old side loses, and the
// first line and the number of lines the new side gains. A count that is left
// out is 1.
func hunk(header string) (removed, first, count int, ok bool) {
	fields := strings.Fields(header)
	if len(fields) < 3 || !strings.HasPrefix(fields[1], "-") || !strings.HasPrefix(fields[2], "+") {
		return 0, 0, 0, false
	}
	side := func(text string) (start, n int, ok bool) {
		start, n = 0, 1
		parts := strings.SplitN(text[1:], ",", 2)
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return 0, 0, false
		}
		if len(parts) == 2 {
			if n, err = strconv.Atoi(parts[1]); err != nil {
				return 0, 0, false
			}
		}
		return start, n, true
	}
	_, removed, okOld := side(fields[1])
	first, count, okNew := side(fields[2])
	return removed, first, count, okOld && okNew
}

// onAddedLines keeps the findings that are on lines the commit adds or
// changes. What was in a file before is not this commit's doing; the full scan
// in CI reports it. A finding without a line counts when its file has added
// lines.
func onAddedLines(findings []*finding.Finding, added map[string][]lineRange) (kept []*finding.Finding, left int) {
	for _, f := range findings {
		if f.Location == nil || !touches(f.Location, added[f.Location.Path]) {
			left++
			continue
		}
		kept = append(kept, f)
	}
	return kept, left
}

func touches(location *finding.Location, ranges []lineRange) bool {
	if len(ranges) == 0 {
		return false
	}
	if location.StartLine == nil {
		return true
	}
	first, last := *location.StartLine, *location.StartLine
	if location.EndLine != nil && *location.EndLine > first {
		last = *location.EndLine
	}
	for _, r := range ranges {
		if first <= r.last && last >= r.first {
			return true
		}
	}
	return false
}

// mergeInProgress reports whether the commit being made concludes a merge.
// Its staged changes are mostly other people's commits.
func mergeInProgress(root string) bool {
	_, err := gitIn(root, "rev-parse", "--quiet", "--verify", "MERGE_HEAD")
	return err == nil
}

// stagedStateDir is where a staged scan keeps its reports and cache: inside
// the git directory, where nothing is ever added to a commit by accident.
func stagedStateDir(root string) (string, error) {
	out, err := gitIn(root, "rev-parse", "--git-path", "sdt")
	if err != nil {
		return "", err
	}
	path := strings.TrimSpace(out)
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	return path, nil
}

func gitIn(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok && len(exit.Stderr) > 0 {
			return "", fmt.Errorf("git: %s", strings.TrimSpace(string(exit.Stderr)))
		}
		return "", err
	}
	return string(out), nil
}
