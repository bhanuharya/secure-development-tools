package endpoints

import (
	"os"
	"path/filepath"
	"strings"
)

// Python source is scanned line by line for route decorators (T31), so it must
// know which lines are code. A triple-quoted string or docstring can contain
// text that looks exactly like a decorator and a handler; those are examples,
// not registrations (T36). The mask marks every byte that belongs to a string
// literal or comment, and the scanner skips lines that start inside one.

// pyQuoteMask marks string-literal and comment bytes in src.
func pyQuoteMask(src string) []bool {
	masked := make([]bool, len(src))
	for i := 0; i < len(src); {
		switch src[i] {
		case '#':
			for i < len(src) && src[i] != '\n' {
				masked[i] = true
				i++
			}
		case '\'', '"':
			i = pyMaskString(src, i, masked)
		default:
			i++
		}
	}
	return masked
}

// pyMaskString masks one quoted literal and returns the offset after it.
func pyMaskString(src string, i int, masked []bool) int {
	quote := src[i]
	triple := i+2 < len(src) && src[i+1] == quote && src[i+2] == quote
	if triple {
		masked[i], masked[i+1], masked[i+2] = true, true, true
		i += 3
		for i < len(src) {
			if src[i] == '\\' && i+1 < len(src) {
				masked[i], masked[i+1] = true, true
				i += 2
				continue
			}
			if i+2 < len(src) && src[i] == quote && src[i+1] == quote && src[i+2] == quote {
				masked[i], masked[i+1], masked[i+2] = true, true, true
				return i + 3
			}
			masked[i] = true
			i++
		}
		return i
	}
	masked[i] = true
	i++
	for i < len(src) {
		if src[i] == '\\' && i+1 < len(src) {
			masked[i], masked[i+1] = true, true
			i += 2
			continue
		}
		masked[i] = true
		if src[i] == quote || src[i] == '\n' {
			return i + 1
		}
		i++
	}
	return i
}

// pyLineOffsets returns the byte offset at which each source line starts.
func pyLineOffsets(lines []string) []int {
	offsets := make([]int, len(lines))
	for i := 1; i < len(lines); i++ {
		offsets[i] = offsets[i-1] + len(lines[i-1]) + 1
	}
	return offsets
}

// pyCodeLine reports whether the first non-blank character of a line is code,
// not part of a string or comment. Blank and out-of-range lines are code-so-far
// and simply carry no decorator or def.
func pyCodeLine(masked []bool, offsets []int, lines []string, i int) bool {
	if i < 0 || i >= len(lines) {
		return false
	}
	j := 0
	for j < len(lines[i]) && (lines[i][j] == ' ' || lines[i][j] == '\t' || lines[i][j] == '\r') {
		j++
	}
	if j >= len(lines[i]) {
		return true
	}
	at := offsets[i] + j
	return at >= len(masked) || !masked[at]
}

// pyDropQuotedRouteDecorators drops engine facts whose line is inside a string
// or comment. The fact rule is a regex, so it also matches an example decorator
// in a docstring; the source scan below uses the same mask to skip those lines.
func pyDropQuotedRouteDecorators(root, file string, facts []Fact) []Fact {
	src, err := os.ReadFile(filepath.Join(root, file))
	if err != nil {
		return facts
	}
	lines := strings.Split(string(src), "\n")
	masked := pyQuoteMask(string(src))
	offsets := pyLineOffsets(lines)
	kept := facts[:0]
	for _, f := range facts {
		if pyCodeLine(masked, offsets, lines, f.Line-1) {
			kept = append(kept, f)
		}
	}
	return kept
}
