package endpoints

import "strings"

// Spring configuration arguments arrive as one raw string: the engine joins
// variadic arguments without a separator and resolves nothing for us. These
// helpers read the constructs the resolver models and reject the rest, so an
// unreadable matcher, scope or ignored path becomes unknown (T35).

// springArgValue is one path argument: a quoted literal or a simple name the
// resolver may substitute from a static final String declaration.
type springArgValue struct {
	value   string
	literal bool
}

// springWrapperPrefixes are the matcher constructors whose path strings the
// resolver can read. Any other constructor stays unmodelled.
var springWrapperPrefixes = []string{
	"new AntPathRequestMatcher(",
	"new PathPatternParserServerWebExchangeMatcher(",
	"new MvcRequestMatcher(",
	"new OrRequestMatcher(",
	"ServerWebExchangeMatchers.pathMatchers(",
}

// springArgumentValues parses the raw argument list of a scope or ignored
// matcher. It returns the values, an optional HttpMethod, and whether the form
// is understood. A literal may need no substitution; a name does.
func springArgumentValues(raw string) ([]springArgValue, string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, "", false // requestMatchers() is a builder, not a scope
	}
	method := ""
	if m := springMethodArgRe.FindStringSubmatch(s); m != nil {
		method = normalizeMethod(m[1])
		s = strings.TrimSpace(s[len(m[0]):])
	}
	if s == "" {
		return nil, method, false
	}
	if values, ok := springQuotedSequence(s); ok {
		return namedArgs(values), method, true
	}
	if springIdentRe.MatchString(s) {
		return []springArgValue{{value: s}}, method, true
	}
	if values, ok := springWrapperLiterals(s); ok {
		return namedArgs(values), method, true
	}
	return nil, method, false
}

func namedArgs(values []string) []springArgValue {
	out := make([]springArgValue, len(values))
	for i, value := range values {
		out[i] = springArgValue{value: value, literal: true}
	}
	return out
}

// springQuotedSequence reads one or more adjacent Java string literals, the
// shape a variadic literal argument list takes after the engine strips commas.
func springQuotedSequence(s string) ([]string, bool) {
	var out []string
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return out, len(out) > 0
		}
		if s[0] != '"' {
			return nil, false
		}
		value, next, ok := readSpelString(s, 0)
		if !ok {
			return nil, false
		}
		out = append(out, value)
		s = s[next:]
	}
}

// springWrapperLiterals reads the path literals inside the matcher wrappers the
// resolver models. Everything outside those wrappers must be syntax only.
func springWrapperLiterals(s string) ([]string, bool) {
	rest := s
	var values []string
	for {
		i := strings.IndexByte(rest, '"')
		if i < 0 {
			break
		}
		value, next, ok := readSpelString(rest, i)
		if !ok {
			return nil, false
		}
		values = append(values, value)
		rest = rest[:i] + rest[next:]
	}
	if len(values) == 0 {
		return nil, false
	}
	for _, prefix := range springWrapperPrefixes {
		rest = strings.ReplaceAll(rest, prefix, "")
	}
	rest = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ",", "", ")", "").Replace(rest)
	if rest != "" {
		return nil, false // an unknown constructor, identifier or operator
	}
	return values, true
}

// resolvePattern substitutes one simple constant name. Literal values pass
// through. A name is accepted only when it resolves unambiguously.
func (b *springBuild) resolvePattern(raw, file string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if raw[0] == '"' {
		value, next, ok := readSpelString(raw, 0)
		if ok && next == len(raw) {
			return value, true
		}
		return "", false
	}
	if !springIdentRe.MatchString(raw) {
		return "", false
	}
	class, name := "", raw
	if dot := strings.LastIndexByte(raw, '.'); dot >= 0 {
		class, name = raw[:dot], raw[dot+1:]
	}
	value, matches := "", 0
	for _, c := range b.constants {
		if !springConstantMatches(c, file, class, name) {
			continue
		}
		value, matches = c.value, matches+1
	}
	return value, matches == 1
}

// springConstantMatches prefers a declaration in the same file; a qualified
// name must also name the declaring class.
func springConstantMatches(c springConstant, file, class, name string) bool {
	if c.name != name {
		return false
	}
	if class != "" {
		return c.class == class || strings.HasSuffix(class, "."+c.class)
	}
	return c.file == file
}
