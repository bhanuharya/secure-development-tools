package endpoints

import (
	"os"
	"path/filepath"
)

// routeCallMethods are the callable names that register a route. Source
// extraction starts at the fact and stops at the first top-level call with one
// of these names, so a receiver such as r.Group("/api") is skipped.
var routeCallMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
	"Any": true, "All": true,
	"Get": true, "Post": true, "Put": true, "Patch": true, "Delete": true,
	"get": true, "post": true, "put": true, "patch": true, "delete": true, "all": true,
	"Handle": true, "HandleFunc": true,
}

// routeArgs returns the handler and middleware arguments of a route fact. The
// engine's variadic tail cannot be split back into arguments, so the call is
// read from the source at the fact's line and column. lead is the number of
// fixed arguments before them (the path, and the verb for Handle).
func routeArgs(f Fact, root string, lead int) []string {
	if args, ok := sourceCallArgs(root, f); ok && len(args) > lead {
		return args[lead:]
	}
	return factArgs(f)
}

// sourceCallArgs reads the top-level arguments of the route call that starts at
// the fact's position. A missing or unreadable file falls back to the
// metavariables, which exact-arity rules still provide.
func sourceCallArgs(root string, f Fact) ([]string, bool) {
	src, err := os.ReadFile(filepath.Join(root, f.File))
	if err != nil {
		return nil, false
	}
	open := routeCallOpen(src, jsOffset(src, f.Line, f.Column))
	if open < 0 {
		return nil, false
	}
	return callArgsAt(src, open)
}

// routeCallOpen finds the call parenthesis of the route registration, skipping
// receiver calls first (r.Group("/api").GET("/x", h)).
func routeCallOpen(src []byte, start int) int {
	depth := 0
	quote := byte(0)
	for i := start; i < len(src); i++ {
		c := src[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '(':
			if depth == 0 && routeCallMethods[identifierBefore(src, i)] {
				return i
			}
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
	}
	return -1
}

// identifierBefore returns the identifier that ends just before open.
func identifierBefore(src []byte, open int) string {
	i := open - 1
	for i >= 0 && (src[i] == ' ' || src[i] == '\t') {
		i--
	}
	end := i + 1
	for i >= 0 {
		c := src[i]
		if c != '_' && c != '$' &&
			(c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			break
		}
		i--
	}
	return string(src[i+1 : end])
}

// callArgsAt splits the arguments between open and its matching close.
func callArgsAt(src []byte, open int) ([]string, bool) {
	depth := 0
	quote := byte(0)
	for i := open; i < len(src); i++ {
		c := src[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return splitArgs(string(src[open+1 : i])), true
			}
		}
	}
	return nil, false
}
