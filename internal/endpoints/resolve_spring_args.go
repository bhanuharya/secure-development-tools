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

// springArgumentValues reads a literal/constant path list and its optional
// method. Both source commas and the engine's adjacent arguments are accepted.
func springArgumentValues(raw string) ([]springArgValue, string, bool) {
	parts, ok := springArgumentParts(raw)
	if !ok || len(parts) == 0 {
		return nil, "", false
	}
	method := ""
	if m := springMethodArgRe.FindStringSubmatch(parts[0]); m != nil && len(m[0]) == len(parts[0]) {
		method = normalizeMethod(m[1])
		parts = parts[1:]
	}
	var values []springArgValue
	for _, part := range parts {
		if value, next, ok := readSpelString(part, 0); ok && next == len(part) {
			values = append(values, springArgValue{value: value, literal: true})
		} else if springIdentRe.MatchString(part) {
			values = append(values, springArgValue{value: part})
		} else {
			return nil, method, false
		}
	}
	return values, method, len(values) > 0
}

// springArgumentParts splits balanced Java arguments, including the comma-less
// lists emitted by the fact engine. Quotes protect commas and parentheses.
func springArgumentParts(raw string) ([]string, bool) {
	var out []string
	for s := strings.TrimSpace(raw); s != ""; {
		s = strings.TrimLeft(s, " ,\t\r\n")
		if s == "" {
			break
		}
		depth, end := 0, len(s)
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '\'', '"':
				if depth == 0 && i > 0 {
					end = i
					break
				}
				_, next, ok := readSpelString(s, i)
				if !ok {
					return nil, false
				}
				i = next - 1
				if depth == 0 {
					end = next
				}
			case '(':
				depth++
			case ')':
				depth--
				if depth < 0 {
					return nil, false
				}
				if depth == 0 {
					end = i + 1
				}
			case ',':
				if depth == 0 {
					end = i
				}
			}
			if end < len(s) {
				break
			}
		}
		if depth != 0 || end == 0 {
			return nil, false
		}
		out = append(out, strings.TrimSpace(s[:end]))
		s = strings.TrimSpace(s[end:])
	}
	return out, true
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
