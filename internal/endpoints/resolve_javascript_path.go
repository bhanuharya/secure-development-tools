package endpoints

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Express paths are often template literals. Opengrep's constant folding
// keeps only the first folded fragment (`${base}/x` came back as the quoted
// value of base), so the resolver reads the call's first argument from the
// same file and expands it. Interpolations that are not same-file string
// constants become {name} placeholders, like a route parameter.

var (
	jsConstRe     = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?(?:const|let|var)[ \t]+([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*=[ \t]*['"]([^'"\r\n]*)['"]`)
	jsIdentRe     = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	jsIdentTailRe = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*$`)
)

// routePath returns the literal path of a route fact. Expressions that are
// not a string, a same-file string constant, a concatenation of those, or a
// template literal are errors: guessing would put code in the path column.
func (js *jsResolver) routePath(f Fact) (string, error) {
	raw := strings.TrimSpace(f.Metavars["$PATH"])
	if raw == "" {
		return "", fmt.Errorf("route path could not be resolved")
	}
	if strings.HasPrefix(raw, "`") {
		lit, ok := js.templateAt(f)
		if !ok {
			return "", fmt.Errorf("route path template at line %d could not be read", f.Line)
		}
		return cleanPath(expandTemplate(lit, js.stringConstants())), nil
	}
	var consts map[string]string
	if !isJSQuoted(raw) {
		consts = js.stringConstants()
	}
	value, ok := evalJSString(raw, consts)
	if !ok {
		return "", fmt.Errorf("route path %q could not be resolved", raw)
	}
	return cleanPath(value), nil
}

// stringConstants reads the simple `const NAME = '...'` declarations of the
// file. Constant folding cannot be relied on: an identifier path stays an
// identifier and a template keeps only one fragment.
func (js *jsResolver) stringConstants() map[string]string {
	src, err := os.ReadFile(filepath.Join(js.root, js.file))
	if err != nil {
		return nil
	}
	consts := map[string]string{}
	for _, m := range jsConstRe.FindAllStringSubmatch(string(src), -1) {
		if _, seen := consts[m[1]]; !seen {
			consts[m[1]] = m[2]
		}
	}
	return consts
}

func isJSQuoted(expr string) bool {
	if len(expr) < 2 {
		return false
	}
	return (expr[0] == '\'' || expr[0] == '"') && expr[len(expr)-1] == expr[0]
}

// evalJSString evaluates literals, same-file constants and top-level `+`
// concatenations; anything else stays unresolved.
func evalJSString(expr string, consts map[string]string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if isJSQuoted(expr) {
		return expr[1 : len(expr)-1], true
	}
	if jsIdentRe.MatchString(expr) {
		value, ok := consts[expr]
		return value, ok
	}
	parts := splitJSConcat(expr)
	if len(parts) < 2 {
		return "", false
	}
	var out strings.Builder
	for _, part := range parts {
		value, ok := evalJSString(part, consts)
		if !ok {
			return "", false
		}
		out.WriteString(value)
	}
	return out.String(), true
}

// splitJSConcat splits on top-level plus signs only, so a plus inside a string
// or an argument list stays in its part.
func splitJSConcat(expr string) []string {
	var parts []string
	depth, start := 0, 0
	quote := byte(0)
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '+':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(expr[start:i]))
				start = i + 1
			}
		}
	}
	if len(parts) == 0 {
		return []string{expr}
	}
	return append(parts, strings.TrimSpace(expr[start:]))
}

// templateAt reads the raw template literal in the first argument of the call
// that starts at the fact's line and column.
func (js *jsResolver) templateAt(f Fact) (string, bool) {
	src, err := os.ReadFile(filepath.Join(js.root, js.file))
	if err != nil {
		return "", false
	}
	open := jsCallParen(src, jsOffset(src, f.Line, f.Column), f.Metavars["$METHOD"])
	if open < 0 {
		return "", false
	}
	start := skipJSSpace(src, open+1)
	if start >= len(src) || src[start] != '`' {
		return "", false
	}
	end := scanTemplateEnd(src, start)
	if end < 0 {
		return "", false
	}
	return string(src[start:end]), true
}

// jsCallParen finds the `(` of `.<method>(` at or after offset.
func jsCallParen(src []byte, offset int, method string) int {
	if offset < 0 || offset >= len(src) || method == "" {
		return -1
	}
	token := "." + method
	for offset < len(src) {
		rel := strings.Index(string(src[offset:]), token)
		if rel < 0 {
			return -1
		}
		open := skipJSSpace(src, offset+rel+len(token))
		if open < len(src) && src[open] == '(' {
			return open
		}
		offset += rel + len(token)
	}
	return -1
}

func jsOffset(src []byte, line, col int) int {
	offset := 0
	for l := 1; l < line; l++ {
		next := bytes.IndexByte(src[offset:], '\n')
		if next < 0 {
			return len(src)
		}
		offset += next + 1
	}
	if col > 1 {
		offset += col - 1
	}
	if offset > len(src) {
		return len(src)
	}
	return offset
}

func skipJSSpace(src []byte, pos int) int {
	for pos < len(src) {
		switch src[pos] {
		case ' ', '\t', '\r', '\n':
			pos++
		default:
			return pos
		}
	}
	return pos
}

func scanTemplateEnd(src []byte, start int) int {
	for i := start + 1; i < len(src); i++ {
		switch src[i] {
		case '\\':
			i++
		case '`':
			return i + 1
		case '$':
			if i+1 < len(src) && src[i+1] == '{' {
				end := scanBraceEnd(src, i+2)
				if end < 0 {
					return -1
				}
				i = end - 1
			}
		}
	}
	return -1
}

// scanBraceEnd returns the index just after the `}` that closes an
// interpolation; nested objects, strings and templates are skipped.
func scanBraceEnd(src []byte, start int) int {
	depth := 1
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '\'', '"':
			i = skipJSString(src, i, src[i])
		case '`':
			end := scanTemplateEnd(src, i)
			if end < 0 {
				return -1
			}
			i = end - 1
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

func skipJSString(src []byte, start int, quote byte) int {
	for i := start + 1; i < len(src); i++ {
		if src[i] == '\\' {
			i++
			continue
		}
		if src[i] == quote {
			return i
		}
	}
	return len(src) - 1
}

func expandTemplate(lit string, consts map[string]string) string {
	if len(lit) < 2 || lit[0] != '`' || lit[len(lit)-1] != '`' {
		return lit
	}
	body := lit[1 : len(lit)-1]
	var out strings.Builder
	for i := 0; i < len(body); {
		if body[i] == '\\' && i+1 < len(body) {
			out.WriteByte(body[i+1])
			i += 2
			continue
		}
		if body[i] == '$' && i+1 < len(body) && body[i+1] == '{' {
			end := scanBraceEnd([]byte(body), i+2)
			if end < 0 {
				out.WriteString("{param}")
				break
			}
			expr := body[i+2 : end-1]
			if value, ok := evalJSString(expr, consts); ok {
				out.WriteString(value)
			} else {
				out.WriteString("{" + jsParamName(expr) + "}")
			}
			i = end
			continue
		}
		out.WriteByte(body[i])
		i++
	}
	return out.String()
}

// jsParamName names an unknown interpolation after its last identifier:
// `${req.params.id}` becomes {id}.
func jsParamName(expr string) string {
	if name := jsIdentTailRe.FindString(strings.TrimSpace(expr)); name != "" {
		return name
	}
	return "param"
}

// cleanPath enforces the inventory's path invariant. A quote or backtick in a
// path means a code fragment leaked through; never let it reach the report.
func cleanPath(p string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\'', '"', '`':
			return -1
		}
		return r
	}, p)
}
