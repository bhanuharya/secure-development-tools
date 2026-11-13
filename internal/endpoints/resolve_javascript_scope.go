package endpoints

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// This file is the same-file scope model behind the Express resolver (T36).
// Two functions may each declare `const app = express()` or their own router;
// a use() or route on one declaration must never inherit the other's
// middleware. Bindings live from their declaration to the end of the
// function or block that declares them, like the Go model in
// resolve_go_scope.go.

// jsBinding is one application or router declaration and the source range in
// which its name refers to it.
type jsBinding struct {
	name   string
	line   int // the declaration
	start  int
	end    int // jsTopLevelEnd for a declaration at the top of the file
	engine bool
	router bool
}

// jsTopLevelEnd marks a declaration visible in the whole file.
const jsTopLevelEnd = math.MaxInt

// jsBindings indexes the engine/router facts a file declares. A router_fn
// only counts when the file imports express, the same condition that makes it
// a server router in newJSResolver.
func jsBindings(root, file string, facts []Fact, expressImport bool) []jsBinding {
	scopes := jsFileScopes(filepath.Join(root, file))
	var out []jsBinding
	seen := map[string]bool{}
	for _, f := range facts {
		b := jsBinding{name: f.Metavars["$R"], line: f.Line}
		switch f.Kind {
		case "engine":
			b.engine = true
		case "router":
			b.router = true
		case "router_fn":
			if !expressImport {
				continue
			}
			b.router = true
		default:
			continue
		}
		key := b.name + ":" + strconv.Itoa(f.Line)
		if b.name == "" || seen[key] {
			continue
		}
		seen[key] = true
		b.start, b.end = jsDeclRange(scopes, f.Line)
		out = append(out, b)
	}
	return out
}

// jsDeclRange is the visibility range of a declaration: from its line to the
// end of the innermost function or block. Top-level declarations are visible
// throughout the file.
func jsDeclRange(scopes []lineScope, line int) (int, int) {
	if scope, ok := innermostScope(scopes, line); ok {
		return line, scope.end
	}
	return 0, jsTopLevelEnd
}

// bindingAt returns the innermost binding of name visible at line.
func (js *jsResolver) bindingAt(name string, line int) *jsBinding {
	var best *jsBinding
	for i := range js.bindings {
		b := &js.bindings[i]
		if b.name != name || line < b.start || line > b.end {
			continue
		}
		if best == nil || b.start > best.start || (b.start == best.start && b.end < best.end) {
			best = b
		}
	}
	return best
}

// jsFileScopes reads the braces that open a function or plain block. Strings,
// template literals and comments are skipped, so their punctuation is inert.
// Object literals are not scopes: the character before the brace says whether
// it opens a block.
func jsFileScopes(path string) []lineScope {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := string(src)
	var scopes []lineScope
	// Every brace is tracked so an object literal's closing brace closes the
	// object, not the enclosing function; only block braces become scopes.
	type brace struct {
		line  int
		block bool
	}
	var open []brace
	line := 1
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == '/' && i+1 < len(text) && text[i+1] == '/':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(text) && text[i+1] == '*':
			i += 2
			for i < len(text) {
				if text[i] == '\n' {
					line++
				}
				if text[i] == '*' && i+1 < len(text) && text[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
		case c == '\'' || c == '"' || c == '`':
			i, line = jsSkipString(text, i, line)
		case c == '{':
			open = append(open, brace{line: line, block: jsOpensBlock(text, i)})
			i++
		case c == '}':
			if n := len(open); n > 0 {
				if open[n-1].block {
					scopes = append(scopes, lineScope{start: open[n-1].line, end: line})
				}
				open = open[:n-1]
			}
			i++
		default:
			i++
		}
	}
	return scopes
}

// jsSkipString returns the offset after a quoted string or template literal.
func jsSkipString(src string, i, line int) (int, int) {
	quote := src[i]
	i++
	for i < len(src) {
		if src[i] == '\\' {
			if i+1 < len(src) && src[i+1] == '\n' {
				line++
			}
			i += 2
			continue
		}
		if src[i] == '\n' {
			line++
		}
		if src[i] == quote {
			return i + 1, line
		}
		i++
	}
	return i, line
}

// jsOpensBlock tells a block brace from an object-literal brace by what comes
// before it: a parameter list, a statement end or an arrow opens a block; an
// assignment, argument list or property value opens an object.
func jsOpensBlock(src string, i int) bool {
	j := i - 1
	for j >= 0 && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n' || src[j] == '\r') {
		j--
	}
	if j < 0 {
		return true
	}
	switch src[j] {
	case ')', ';', '{', '}':
		return true
	case '>':
		if j > 0 && src[j-1] == '=' {
			return true
		}
		return jsAfterReturnType(src, j)
	}
	end := j + 1
	for j >= 0 && jsWordByte(src[j]) {
		j--
	}
	switch src[j+1 : end] {
	case "else", "try", "finally", "do":
		return true
	}
	return jsAfterReturnType(src, j)
}

// jsAfterReturnType reports whether src[..j] ends with a TypeScript return
// type after a parameter list, as in `): Router {` or `): Promise<Router> {`.
func jsAfterReturnType(src string, j int) bool {
	for j >= 0 && (jsWordByte(src[j]) || strings.IndexByte(" \t\r\n.<>[]|&,", src[j]) >= 0) {
		j--
	}
	if j < 0 || src[j] != ':' {
		return false
	}
	for j--; j >= 0 && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n' || src[j] == '\r'); j-- {
	}
	return j >= 0 && src[j] == ')'
}

func jsWordByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}
