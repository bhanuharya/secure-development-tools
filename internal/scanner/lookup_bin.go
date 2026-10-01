package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func whichBin(names ...string) string {
	for _, n := range names {
		if filepath.IsAbs(n) {
			if isExec(n) {
				return n
			}
			continue
		}
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

func isExec(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	return !fi.IsDir() && fi.Mode().Perm()&0o111 != 0
}

func runVersion(executable string) (string, error) {
	cmd := exec.Command(executable, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return "", nil
	}
	return strings.TrimSpace(lines[0]), nil
}
