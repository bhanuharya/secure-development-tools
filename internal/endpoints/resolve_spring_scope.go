package endpoints

import (
	"strconv"
	"strings"
)

// springUncertainty limits an unsupported construct to the requests its visible
// paths and methods can affect. Without paths it may affect every request.
type springUncertainty struct {
	bounds springScope
	note   string
}

func (u springUncertainty) affects(path, method string) bool {
	if !u.bounds.hasPatterns() {
		return u.bounds.method == "" || u.bounds.method == method
	}
	return u.bounds.match(method, path) != antNo
}

// scopeExpression preserves the union before negating it. Flattening an Or
// loses the method on an OPTIONS-only child and would exclude ordinary API calls.
func (b *springBuild) scopeExpression(raw, file string) (springScope, bool) {
	name, inner, call := springMatcherCall(raw)
	if !call {
		return b.scopePaths(raw, file)
	}
	switch name {
	case "NegatedRequestMatcher", "NegatedServerWebExchangeMatcher":
		child, ok := b.scopeExpression(inner, file)
		return springScope{children: []springScope{child}, negated: true}, ok
	case "OrRequestMatcher", "OrServerWebExchangeMatcher":
		parts, ok := springArgumentParts(inner)
		if !ok || len(parts) == 0 {
			return springScope{}, false
		}
		var children []springScope
		for _, part := range parts {
			child, ok := b.scopeExpression(part, file)
			if !ok {
				return springScope{}, false
			}
			children = append(children, child)
		}
		return springScope{children: children}, true
	case "AntPathRequestMatcher":
		parts, ok := springArgumentParts(inner)
		if !ok {
			return springScope{}, false
		}
		if len(parts) == 2 {
			if method, ok := springLiteralMethod(parts[1]); ok {
				scope, ok := b.scopePaths(parts[0], file)
				scope.method = method
				return scope, ok
			}
		}
		return b.scopePaths(inner, file)
	case "pathMatchers", "PathPatternParserServerWebExchangeMatcher", "MvcRequestMatcher":
		return b.scopePaths(inner, file)
	}
	return springScope{}, false
}

func (b *springBuild) scopePaths(raw, file string) (springScope, bool) {
	values, method, ok := springArgumentValues(raw)
	if !ok {
		return springScope{}, false
	}
	scope := springScope{method: method}
	for _, value := range values {
		pattern, ok := value.value, value.literal
		if !ok {
			pattern, ok = b.resolvePattern(value.value, file)
		}
		if !ok {
			return springScope{}, false
		}
		scope.patterns = append(scope.patterns, pattern)
	}
	return scope, true
}

func springMatcherCall(raw string) (string, string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || s[0] == '"' {
		return "", "", false
	}
	parts, ok := springArgumentParts(s)
	if !ok || len(parts) != 1 {
		return "", "", false
	}
	open := strings.IndexByte(s, '(')
	if open < 0 || !strings.HasSuffix(s, ")") {
		return "", "", false
	}
	name := strings.TrimSpace(strings.TrimPrefix(s[:open], "new "))
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		name = name[dot+1:]
	}
	return name, s[open+1 : len(s)-1], true
}

func springLiteralMethod(raw string) (string, bool) {
	value, err := strconv.Unquote(raw)
	if err != nil {
		return "", false
	}
	switch value {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE":
		return value, true
	}
	return "", false
}

// springVisibleScope reads only path literals from unsupported expressions.
// It preserves local methods but assumes no semantics for unknown wrappers.
func springVisibleScope(raw string) springScope {
	if _, inner, call := springMatcherCall(raw); call {
		return springVisibleScope(inner)
	}
	parts, ok := springArgumentParts(raw)
	if !ok {
		return springScope{}
	}
	scope := springScope{}
	for _, part := range parts {
		if m := springMethodArgRe.FindStringSubmatch(part); m != nil {
			scope.method = normalizeMethod(m[1])
		} else if value, next, ok := readSpelString(part, 0); ok && next == len(part) && strings.HasPrefix(value, "/") {
			scope.patterns = append(scope.patterns, value)
		} else if _, _, call := springMatcherCall(part); call {
			child := springVisibleScope(part)
			if child.hasPatterns() {
				scope.children = append(scope.children, child)
			}
		}
	}
	if len(parts) == 2 && len(scope.patterns) > 0 {
		if method, ok := springLiteralMethod(parts[1]); ok {
			scope.method = method
		}
	}
	return scope
}

func (s springScope) hasPatterns() bool {
	return len(s.patterns) > 0 || len(s.children) > 0
}

func (s springScope) allPatterns() []string {
	out := append([]string{}, s.patterns...)
	for _, child := range s.children {
		out = append(out, child.allPatterns()...)
	}
	return out
}

// ignoredPaths enumerates a positive union without leaking one child's method
// into the next ignored path. Negated ignores remain unsupported.
func (s springScope) ignoredPaths(source springIgnored) ([]springIgnored, bool) {
	if s.negated {
		return nil, false
	}
	var out []springIgnored
	for _, pattern := range s.patterns {
		ignored := source
		ignored.pattern, ignored.method = pattern, s.method
		out = append(out, ignored)
	}
	for _, child := range s.children {
		paths, ok := child.ignoredPaths(source)
		if !ok {
			return nil, false
		}
		out = append(out, paths...)
	}
	return out, true
}
