package endpoints

import (
	"regexp"
	"strings"
)

// defaultGateRegex is the SPEC §5 gate list: a middleware, guard or dependency
// whose name matches it is treated as authentication.
const defaultGateRegex = `(?i)(auth|jwt|bearer|token|protect|guard|session|login|verify|permission|rbac|acl|role|admin|require)`

// gateMatcher matches names against the default gate regex plus the literal
// names configured in endpoints.authGates (SPEC §7).
type gateMatcher struct{ re *regexp.Regexp }

// defaultGates is shared: the compiled regex is immutable.
var defaultGates = &gateMatcher{re: regexp.MustCompile(defaultGateRegex)}

func newGateMatcher(names []string) *gateMatcher {
	expr, added := defaultGateRegex, false
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue // an empty alternative would match every middleware
		}
		expr += "|" + regexp.QuoteMeta(name)
		added = true
	}
	if !added {
		return defaultGates
	}
	return &gateMatcher{re: regexp.MustCompile(expr)}
}
