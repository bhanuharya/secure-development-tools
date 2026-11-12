package endpoints

import (
	"regexp"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/report"
)

// redactText is shared with the final report writer so both artifact paths cover whole blocks.
func redactText(text string) string {
	return report.Redact(text)
}

// omitCallArguments preserves callable names and source locations, never configuration values.
// An incomplete call consumes the rest of the excerpt rather than exposing its arguments.
// The bracket must follow the name directly: "on router (does not match the gate list)" is prose.
var evidenceCall = regexp.MustCompile(`[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\(`)

func omitCallArguments(text string) string {
	var out strings.Builder
	for offset := 0; offset < len(text); {
		loc := evidenceCall.FindStringIndex(text[offset:])
		if loc == nil {
			out.WriteString(text[offset:])
			break
		}
		open := offset + loc[1] - 1
		close := report.ClosingBracket(text, open)
		out.WriteString(text[offset:open])
		out.WriteString("(...)")
		offset = close + 1
	}
	return out.String()
}

func sanitizeRoutes(routes []Route) []Route {
	for i := range routes {
		routes[i] = sanitizeRoute(routes[i])
	}
	return routes
}

func sanitizeStrings(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}
	clean := make([]string, len(lines))
	for i, line := range lines {
		clean[i] = redactText(line)
	}
	return clean
}

// sanitizeInventory returns a copy safe to serialize. BuildInventory sanitizes too; this guard
// keeps hand-built inventories (tests, imports, adapters) from writing a credential.
func sanitizeInventory(inv *Inventory) *Inventory {
	if inv == nil {
		return nil
	}
	clean := *inv
	clean.Routes = make([]Route, len(inv.Routes))
	for i, route := range inv.Routes {
		clean.Routes[i] = sanitizeRoute(route)
	}
	if len(inv.Unresolved) > 0 {
		clean.Unresolved = sanitizeStrings(inv.Unresolved)
	}
	return &clean
}

func sanitizeRoute(route Route) Route {
	route.Handler = redactText(route.Handler)
	if len(route.Evidence) > 0 {
		// Spring evidence is matcher paths, roles and access expressions, never middleware
		// arguments, and the template logic finds the deciding matcher by its quoted pattern.
		// It is still redacted; everything else also loses its call arguments.
		keepArguments := strings.HasPrefix(route.Framework, "spring")
		evidence := make([]string, len(route.Evidence))
		for i, line := range route.Evidence {
			if !keepArguments {
				line = omitCallArguments(line)
			}
			evidence[i] = redactText(line)
		}
		route.Evidence = evidence
	}
	return route
}
