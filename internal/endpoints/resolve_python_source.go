package endpoints

import (
	"os"
	"path/filepath"
	"strings"
)

// This file enumerates route decorators from the Python source. A fact rule
// cannot follow a decorator stack through an async handler or an argument list
// continued across lines, and its regex lookahead misses the decorators above
// such a list (T31). Balancing parentheses can, and it is the same file the
// facts came from.

var pyRouteVerbs = map[string]bool{
	"route": true, "get": true, "post": true, "put": true, "patch": true, "delete": true,
}

// pySourceRoutes returns one route_decorator fact per route decorator that has
// a def or async def below its stack.
func pySourceRoutes(root, file string) []Fact {
	src, err := os.ReadFile(filepath.Join(root, file))
	if err != nil {
		return nil
	}
	lines := strings.Split(string(src), "\n")
	var out []Fact
	for i := 0; i < len(lines); i++ {
		dec, ok := pyDecoratorAt(lines, i)
		if !ok {
			continue
		}
		handler, defLine, ok := pyHandlerAfter(lines, dec.end+1)
		if !ok {
			continue
		}
		out = append(out, Fact{
			Kind: "route_decorator", File: file, Line: i + 1, Column: 1,
			Metavars: map[string]string{
				"$X": dec.receiver, "$VERB": dec.verb, "$ARGS": dec.args, "$H": handler,
			},
			MetavarLines: map[string]int{"$PATH": i + 1, "$H": defLine + 1},
		})
	}
	return out
}

type pyDecorator struct {
	receiver string
	verb     string
	args     string
	end      int // index of the line that closes the call
}

// pyDecoratorAt parses @receiver.verb(...) starting on line i.
func pyDecoratorAt(lines []string, i int) (pyDecorator, bool) {
	line := strings.TrimLeft(lines[i], " \t")
	if !strings.HasPrefix(line, "@") {
		return pyDecorator{}, false
	}
	rest := line[1:]
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 || !pyIdent(rest[:dot]) {
		return pyDecorator{}, false
	}
	receiver := rest[:dot]
	rest = rest[dot+1:]
	end := 0
	for end < len(rest) && pyIdentByte(rest[end]) {
		end++
	}
	verb := rest[:end]
	if !pyRouteVerbs[verb] {
		return pyDecorator{}, false
	}
	for end < len(rest) && (rest[end] == ' ' || rest[end] == '\t') {
		end++
	}
	if end >= len(rest) || rest[end] != '(' {
		return pyDecorator{}, false
	}
	// rest starts after the '@'; shift the opening parenthesis back onto the
	// line and start reading just past it.
	indent := len(lines[i]) - len(line)
	open := indent + dot + end + 3
	args, closing, ok := pyBalancedArgs(lines, i, open)
	if !ok {
		return pyDecorator{}, false
	}
	return pyDecorator{receiver: receiver, verb: verb, args: args, end: closing}, true
}

// pyHandlerAfter finds the def below a decorator stack. Gate decorators between
// the route decorator and the def are skipped, including multi-line ones.
func pyHandlerAfter(lines []string, from int) (string, int, bool) {
	for i := from; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "@") {
			i = pyDecoratorEnd(lines, i)
			continue
		}
		if name, ok := pyDefName(trimmed); ok {
			return name, i, true
		}
		return "", 0, false
	}
	return "", 0, false
}

// pyDecoratorEnd is the last line of a decorator, balancing a call that runs
// over several lines. A bare @name is a single line.
func pyDecoratorEnd(lines []string, i int) int {
	line := strings.TrimLeft(lines[i], " \t")
	open := strings.IndexByte(line, '(')
	if open < 0 {
		return i
	}
	indent := len(lines[i]) - len(line)
	if _, end, ok := pyBalancedArgs(lines, i, indent+open+1); ok {
		return end
	}
	return i
}

// pyDefName reads the function name of a def line, with or without async.
func pyDefName(line string) (string, bool) {
	fields := strings.Fields(line)
	i := 0
	if len(fields) > 0 && fields[0] == "async" {
		i = 1
	}
	if i >= len(fields) || fields[i] != "def" || i+1 >= len(fields) {
		return "", false
	}
	name := fields[i+1]
	end := 0
	for end < len(name) && pyIdentByte(name[end]) {
		end++
	}
	if end == 0 {
		return "", false
	}
	return name[:end], true
}

// pyBalancedArgs reads the argument text of a call that opens at col on line
// lineIdx and may continue for several lines. Parentheses, brackets and braces
// nest; strings and # comments are skipped so their punctuation is inert.
func pyBalancedArgs(lines []string, lineIdx, col int) (string, int, bool) {
	var b strings.Builder
	depth := 1
	quote := byte(0)
	for i := lineIdx; i < len(lines); i++ {
		line := lines[i]
		start := 0
		if i == lineIdx {
			start = col
		}
		for j := start; j < len(line); j++ {
			c := line[j]
			if quote != 0 {
				b.WriteByte(c)
				if c == '\\' && j+1 < len(line) {
					j++
					b.WriteByte(line[j])
				} else if c == quote {
					quote = 0
				}
				continue
			}
			switch c {
			case '\'', '"':
				quote = c
				b.WriteByte(c)
			case '#':
				j = len(line) // comment to the end of the line
			case '(', '[', '{':
				depth++
				b.WriteByte(c)
			case ')', ']', '}':
				depth--
				if depth == 0 {
					return b.String(), i, true
				}
				b.WriteByte(c)
			default:
				b.WriteByte(c)
			}
		}
		b.WriteByte('\n')
	}
	return "", lineIdx, false
}

func pyIdent(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !pyIdentByte(s[i]) {
			return false
		}
	}
	return true
}

func pyIdentByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}
