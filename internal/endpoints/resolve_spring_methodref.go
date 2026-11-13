package endpoints

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// A chain scope can be a method of the configuration class:
// http.requestMatcher(this::isProtectedEndpoint), or the lambda
// request -> isProtectedEndpoint(request). The scope is then the union of the
// AntPathRequestMatcher patterns that method builds, provided its only return
// says whether any of them matches. Anything else that could change the
// decision (a negation, allMatch or noneMatch, a second return, another matcher
// type, a pattern that is not a literal) leaves the scope unevaluated, as before.

var (
	springMethodRefRe  = regexp.MustCompile(`^(?:this|[A-Z][\w$]*)::([A-Za-z_$][\w$]*)$`)
	springLambdaCallRe = regexp.MustCompile(`^\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*->\s*(?:this\.)?([A-Za-z_$][\w$]*)\(\s*([A-Za-z_$][\w$]*)\s*\)$`)
	springReturnRe     = regexp.MustCompile(`\breturn\b([^;]*);`)
	springAntNewRe     = regexp.MustCompile(`\bnew\s+(?:[\w.]+\.)?AntPathRequestMatcher\s*\(`)
	springOtherNewRe   = regexp.MustCompile(`\bnew\s+(?:[\w.]+\.)?(\w*(?:RequestMatcher|WebExchangeMatcher))\s*\(`)
	springForEachRe    = regexp.MustCompile(`\bfor\s*\(\s*(?:final\s+)?String\s+([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$.]*(?:\s*\(\s*\))?)\s*\)`)
	springAnyMatchRe   = regexp.MustCompile(`^[A-Za-z_$][\w$.]*\s*\.\s*stream\s*\(\s*\)\s*\.\s*anyMatch\s*\(\s*(?:\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*->\s*([A-Za-z_$][\w$]*)\s*\.\s*matches\s*\(\s*[A-Za-z_$][\w$]*\s*\)|[A-Za-z_$][\w$.]*::matches)\s*\)$`)
	springOrMatchesRe  = regexp.MustCompile(`^[A-Za-z_$][\w$]*\s*\.\s*matches\s*\(\s*[A-Za-z_$][\w$]*\s*\)$`)
)

// springMethodRefName returns the method a scope argument delegates to.
func springMethodRefName(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if m := springMethodRefRe.FindStringSubmatch(raw); m != nil {
		return m[1], true
	}
	if m := springLambdaCallRe.FindStringSubmatch(raw); m != nil && m[1] == m[3] {
		return m[2], true
	}
	return "", false
}

// methodScope reads the scope a boolean method of file decides.
func (b *springBuild) methodScope(name, file string) (springScope, bool) {
	raw, err := os.ReadFile(filepath.Join(b.root, file))
	if err != nil {
		return springScope{}, false
	}
	src := stripComments(string(raw))
	body, ok := javaMethodBody(src, `boolean`, name)
	if !ok {
		return springScope{}, false
	}
	returns := springReturnRe.FindAllStringSubmatch(body, -1)
	if len(returns) != 1 || !springReturnIsUnion(strings.TrimSpace(returns[0][1])) {
		return springScope{}, false
	}
	for _, m := range springOtherNewRe.FindAllStringSubmatch(body, -1) {
		if m[1] != "AntPathRequestMatcher" {
			return springScope{}, false
		}
	}
	loops := map[string]string{}
	for _, m := range springForEachRe.FindAllStringSubmatch(body, -1) {
		loops[m[1]] = m[2]
	}
	scope := springScope{}
	for _, idx := range springAntNewRe.FindAllStringIndex(body, -1) {
		args, ok := callArgsAt([]byte(body), idx[1]-1)
		if !ok || len(args) == 0 || len(args) > 2 {
			return springScope{}, false
		}
		method := ""
		if len(args) == 2 {
			if method, ok = springMatcherMethod(args[1]); !ok {
				return springScope{}, false
			}
		}
		var patterns []string
		arg := strings.TrimSpace(args[0])
		if source, isLoop := loops[arg]; isLoop {
			if patterns, ok = b.stringList(src, source, file); !ok {
				return springScope{}, false
			}
		} else if pattern, ok := b.resolvePattern(arg, file); ok {
			patterns = []string{pattern}
		} else {
			return springScope{}, false
		}
		for _, p := range patterns {
			scope.children = append(scope.children, springScope{patterns: []string{p}, method: method})
		}
	}
	return scope, len(scope.children) > 0
}

// springReturnIsUnion accepts `list.stream().anyMatch(m -> m.matches(request))`
// and `a.matches(request) || b.matches(request)`.
func springReturnIsUnion(expr string) bool {
	if strings.ContainsAny(expr, "!&") || strings.Contains(expr, "noneMatch") || strings.Contains(expr, "allMatch") {
		return false
	}
	if m := springAnyMatchRe.FindStringSubmatch(expr); m != nil {
		return m[1] == "" || m[1] == m[2]
	}
	for _, part := range strings.Split(expr, "||") {
		if !springOrMatchesRe.MatchString(strings.TrimSpace(part)) {
			return false
		}
	}
	return true
}

// springMatcherMethod reads the second AntPathRequestMatcher argument.
func springMatcherMethod(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if m, ok := springLiteralMethod(raw); ok {
		return m, true
	}
	if strings.HasPrefix(raw, "HttpMethod.valueOf(") {
		return springLiteralMethod(strings.TrimSuffix(strings.TrimPrefix(raw, "HttpMethod.valueOf("), ")"))
	}
	if strings.HasPrefix(raw, "HttpMethod.") {
		// HttpMethod.POST, HttpMethod.POST.name(), HttpMethod.POST.toString()
		name := strings.TrimPrefix(raw, "HttpMethod.")
		name = strings.TrimSuffix(strings.TrimSuffix(name, ".name()"), ".toString()")
		if javaIdentRe.MatchString(name) {
			return springLiteralMethod(`"` + name + `"`)
		}
	}
	return "", false
}

var (
	springArrayMethodRe = regexp.MustCompile(`^([A-Za-z_$][\w$]*)\s*\(\s*\)$`)
	springListLiteralRe = regexp.MustCompile(`^(?:new\s+String\s*\[\s*\]\s*)?\{([\s\S]*)\}$|^(?:List\.of|Arrays\.asList|Set\.of|Stream\.of)\s*\(([\s\S]*)\)$`)
)

// stringList reads the strings a for-each loop iterates: a method of the same
// class that returns a literal array or list, or a field initialised with one.
func (b *springBuild) stringList(src, source, file string) ([]string, bool) {
	var expr string
	if m := springArrayMethodRe.FindStringSubmatch(source); m != nil {
		body, ok := javaMethodBody(src, `(?:String\s*\[\s*\]|List\s*<\s*String\s*>|Collection\s*<\s*String\s*>)`, m[1])
		if !ok {
			return nil, false
		}
		returns := springReturnRe.FindAllStringSubmatch(body, -1)
		if len(returns) != 1 {
			return nil, false
		}
		expr = returns[0][1]
	} else if javaIdentRe.MatchString(source) {
		field := regexp.MustCompile(`\b(?:String\s*\[\s*\]|List\s*<\s*String\s*>)\s+` + regexp.QuoteMeta(source) + `\s*=\s*([^;]*);`)
		m := field.FindStringSubmatch(src)
		if m == nil {
			return nil, false
		}
		expr = m[1]
	} else {
		return nil, false
	}
	m := springListLiteralRe.FindStringSubmatch(strings.TrimSpace(expr))
	if m == nil {
		return nil, false
	}
	inner := m[1] + m[2]
	parts, ok := springArgumentParts(inner)
	if !ok {
		return nil, false
	}
	var out []string
	for _, part := range parts {
		value, ok := b.resolvePattern(part, file)
		if !ok {
			return nil, false
		}
		out = append(out, value)
	}
	return out, len(out) > 0
}

var javaIdentRe = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)

// javaMethodBody returns the body of the method `<returnType> name(...)` in a
// comment-free source. Overloads with that name and return type are ambiguous.
func javaMethodBody(src, returnType, name string) (string, bool) {
	re := regexp.MustCompile(`\b` + returnType + `\s+` + regexp.QuoteMeta(name) + `\s*\(`)
	locs := re.FindAllStringIndex(src, -1)
	if len(locs) != 1 {
		return "", false
	}
	open := locs[0][1] - 1
	close := javaMatching(src, open, '(', ')')
	if close < 0 {
		return "", false
	}
	brace := strings.IndexByte(src[close:], '{')
	if brace < 0 || strings.ContainsAny(src[close+1:close+brace], ";=") {
		return "", false
	}
	start := close + brace
	end := javaMatching(src, start, '{', '}')
	if end < 0 {
		return "", false
	}
	return src[start+1 : end], true
}

// javaMatching returns the index of the bracket closing the one at open,
// skipping string and character literals.
func javaMatching(src string, open int, left, right byte) int {
	depth := 0
	for i := open; i < len(src); i++ {
		switch c := src[i]; c {
		case '"', '\'':
			for i++; i < len(src) && src[i] != c; i++ {
				if src[i] == '\\' {
					i++
				}
			}
		case left:
			depth++
		case right:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
