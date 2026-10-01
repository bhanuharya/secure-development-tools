package rules

import (
	"os/exec"
	"sort"
	"strings"
)

func sortStrings(s []string) { sort.Strings(s) }

// shellBundle reproduces scripts/vendor_semgrep_rules.sh bundle hashing.
func shellBundle(dir string) (string, error) {
	// find . -type f | sort | xargs sha256sum | sha256sum
	find := exec.Command("find", ".", "-type", "f")
	find.Dir = dir
	list, err := find.Output()
	if err != nil {
		return "", err
	}
	names := strings.Fields(string(list))
	if len(names) == 0 {
		return "", nil
	}
	// sort is byte-wise under C locale for ASCII paths.
	sortStrings(names)
	xargs := exec.Command("xargs", "sha256sum")
	xargs.Dir = dir
	xargs.Stdin = strings.NewReader(strings.Join(names, "\n") + "\n")
	sums, err := xargs.Output()
	if err != nil {
		return "", err
	}
	final := exec.Command("sha256sum")
	final.Stdin = strings.NewReader(string(sums))
	finalSum, err := final.Output()
	if err != nil {
		return "", err
	}
	return strings.Fields(string(finalSum))[0], nil
}
