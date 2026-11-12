package endpoints

import (
	"regexp"
	"strings"
)

// antResult is a three-valued match: an Ant constraint may use a regexp Go
// cannot compile, and then the honest answer is "cannot decide", not "no".
type antResult int8

const (
	antUnknown antResult = iota
	antNo
	antYes
)

// antMatch reports whether a Spring Ant pattern matches a concrete route path
// (SPEC §5, Spring bullet). `**` matches zero or more path segments, `*`
// matches zero or more characters inside one segment, `?` matches one
// character and `{name}` matches one segment. A `{name:regex}` segment matches
// only when the anchored regex accepts it. Matching is case-sensitive; a
// trailing slash is insignificant.
func antMatch(pattern, path string) bool {
	return antMatchResult(pattern, path) == antYes
}

// antMatchResult is antMatch with the "constraint cannot be compiled" case
// kept separate from a definite mismatch.
func antMatchResult(pattern, path string) antResult {
	p, s := antSegments(pattern), antSegments(path)
	// memo: 0 unvisited, 1 no, 2 yes, 3 unknown. Chains can backtrack a lot.
	memo := make([][]antResult, len(p)+1)
	for i := range memo {
		memo[i] = make([]antResult, len(s)+1)
	}
	var match func(i, j int) antResult
	match = func(i, j int) antResult {
		if memo[i][j] != 0 {
			return memo[i][j]
		}
		ok := antMatchAt(p, s, i, j, match)
		memo[i][j] = ok
		return ok
	}
	return match(0, 0)
}

func antMatchAt(p, s []string, i, j int, match func(int, int) antResult) antResult {
	if i == len(p) {
		if j == len(s) {
			return antYes
		}
		return antNo
	}
	if p[i] == "**" {
		// `**` may consume zero segments or one more.
		zero := match(i+1, j)
		if zero == antYes || j == len(s) {
			return zero
		}
		one := match(i, j+1)
		return antOr(zero, one)
	}
	if j == len(s) {
		return antNo
	}
	return antAnd(antSegmentMatch(p[i], s[j]), match(i+1, j+1))
}

func antOr(a, b antResult) antResult {
	if a == antYes || b == antYes {
		return antYes
	}
	if a == antNo && b == antNo {
		return antNo
	}
	return antUnknown
}

func antAnd(a, b antResult) antResult {
	if a == antNo || b == antNo {
		return antNo
	}
	if a == antYes && b == antYes {
		return antYes
	}
	return antUnknown
}

func antSegments(p string) []string {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

var braceSegmentRe = regexp.MustCompile(`^\{[^{}]+\}$`)

func antSegmentMatch(pattern, segment string) antResult {
	if pattern == segment {
		return antYes
	}
	if braceSegmentRe.MatchString(pattern) || strings.Contains(pattern, "{") {
		return constrainedSegmentMatch(pattern, segment)
	}
	if wildcardSegment(pattern, segment) {
		return antYes
	}
	return antNo
}

// constrainedSegmentMatch turns `{name}` into one segment and `{name:regex}`
// into the regexp the developer wrote, anchored to the whole segment. A
// regexp Go rejects makes the whole segment undecidable.
func constrainedSegmentMatch(pattern, segment string) antResult {
	expr, ok := antSegmentRegexp(pattern)
	if !ok {
		return antUnknown
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return antUnknown
	}
	if re.MatchString(segment) {
		return antYes
	}
	return antNo
}

// antSegmentRegexp builds an anchored regexp for a segment that contains one
// or more `{...}` variables. Braces nested inside a constraint (a `{2}`
// quantifier) are balanced, so the closing brace is the matching one.
func antSegmentRegexp(pattern string) (string, bool) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); {
		switch pattern[i] {
		case '*':
			b.WriteString(".*")
			i++
		case '?':
			b.WriteString(".")
			i++
		case '{':
			end := matchingBrace(pattern, i)
			if end < 0 {
				return "", false
			}
			inner := pattern[i+1 : end]
			if colon := strings.IndexByte(inner, ':'); colon >= 0 {
				b.WriteString("(?:" + inner[colon+1:] + ")")
			} else {
				b.WriteString("[^/]+")
			}
			i = end + 1
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
			i++
		}
	}
	b.WriteString("$")
	return b.String(), true
}

func matchingBrace(s string, start int) int {
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
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
