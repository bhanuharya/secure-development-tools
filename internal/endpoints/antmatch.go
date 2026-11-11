package endpoints

import (
	"regexp"
	"strings"
)

// antMatch reports whether a Spring Ant pattern matches a concrete route path
// (SPEC §5, Spring bullet). `**` matches zero or more path segments, `*`
// matches zero or more characters inside one segment, `?` matches one
// character and `{name}` matches one segment. Matching is case-sensitive; a
// trailing slash is insignificant.
func antMatch(pattern, path string) bool {
	p, s := antSegments(pattern), antSegments(path)
	// memo: 0 unknown, 1 no, 2 yes. Chains can backtrack a lot on `**`.
	memo := make([][]int8, len(p)+1)
	for i := range memo {
		memo[i] = make([]int8, len(s)+1)
	}
	var match func(i, j int) bool
	match = func(i, j int) bool {
		if memo[i][j] != 0 {
			return memo[i][j] == 2
		}
		ok := antMatchAt(p, s, i, j, match)
		if ok {
			memo[i][j] = 2
		} else {
			memo[i][j] = 1
		}
		return ok
	}
	return match(0, 0)
}

func antMatchAt(p, s []string, i, j int, match func(int, int) bool) bool {
	if i == len(p) {
		return j == len(s)
	}
	if p[i] == "**" {
		// `**` may consume zero segments or one more.
		return match(i+1, j) || (j < len(s) && match(i, j+1))
	}
	if j == len(s) {
		return false
	}
	return antSegmentMatch(p[i], s[j]) && match(i+1, j+1)
}

func antSegments(p string) []string {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

var (
	braceSegmentRe = regexp.MustCompile(`^\{[^{}]+\}$`)
	braceVarRe     = regexp.MustCompile(`\{[^{}/]+\}`)
)

func antSegmentMatch(pattern, segment string) bool {
	if pattern == segment {
		return true
	}
	if braceSegmentRe.MatchString(pattern) {
		return segment != "" // {id} is one whole segment, never several
	}
	// An embedded variable (report-{id}.pdf) behaves like `*` in its segment.
	return wildcardSegment(braceVarRe.ReplaceAllString(pattern, "*"), segment)
}

// wildcardSegment matches `*` and `?` inside a single path segment. The
// two-pointer loop keeps the last `*` as a backtrack point.
func wildcardSegment(pattern, segment string) bool {
	p, s := []rune(pattern), []rune(segment)
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
