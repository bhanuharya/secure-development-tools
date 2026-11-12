package endpoints

import (
	"regexp"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/report"
)

// secretKeyNames is the key vocabulary the rule pack treats as a secret (T11/T17 and
// common/secrets.yaml). It must stay in step with the hardcoded-secret rules: a name those
// rules report must never be copied into evidence, findings or a prompt.
const secretKeyNames = `password|passwd|pwd|passphrase|secret|token|salt|credentials?|apikey|` +
	`(?:api|app|auth|access|aes|cookie|encryption|hmac|jwt|master|private|secret|session|signing)[_-]?key`

var (
	secretAssignment = regexp.MustCompile(`(?i)((?:` + secretKeyNames + `)["']?\s*[:=]\s*)` +
		`(?:"[^"]*"|'[^']*'|` + "`[^`]*`" + `)`)
	// Credential containers found in middleware calls: gin.Accounts{...}, BasicAuth(...),
	// a Credentials(...) helper. Their arguments are values, not names worth keeping. The
	// bracket must follow the name: "accounts.controller.ts" is a path, not a container.
	credentialContainer = regexp.MustCompile(`(?i)\b(?:accounts|basicauth|credentials?)\s*[({]`)
)

// redactText removes credential-like values from captured source text. Rule evidence quotes
// middleware arguments, and those arguments can be the only place a credential appears.
func redactText(text string) string {
	if text == "" {
		return text
	}
	text = redactCredentialContainers(text)
	text = secretAssignment.ReplaceAllString(text, `${1}[REDACTED]`)
	return report.Redact(text)
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
		evidence := make([]string, len(route.Evidence))
		for i, line := range route.Evidence {
			evidence[i] = redactText(line)
		}
		route.Evidence = evidence
	}
	return route
}

// redactCredentialContainers replaces the quoted arguments of a credential container. Only a
// bracket directly after the name counts, so a path such as accounts.controller.ts stays.
func redactCredentialContainers(text string) string {
	for offset := 0; offset < len(text); {
		loc := credentialContainer.FindStringIndex(text[offset:])
		if loc == nil {
			return text
		}
		open := offset + loc[1] - 1
		close := matchingBracket(text, open)
		if close < 0 {
			return text
		}
		inner := redactQuoted(text[open+1 : close])
		text = text[:open+1] + inner + text[close:]
		offset = open + 1 + len(inner) + 1
	}
	return text
}

// matchingBracket returns the index of the bracket closing the one at open, ignoring
// brackets inside string literals.
func matchingBracket(text string, open int) int {
	depth, quote := 0, byte(0)
	for i := open; i < len(text); i++ {
		c := text[i]
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
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func redactQuoted(text string) string {
	var out strings.Builder
	for i := 0; i < len(text); {
		quote := text[i]
		if quote != '"' && quote != '\'' && quote != '`' {
			out.WriteByte(quote)
			i++
			continue
		}
		j := i + 1
		for j < len(text) {
			if text[j] == '\\' {
				j += 2
				continue
			}
			if text[j] == quote {
				break
			}
			j++
		}
		if j >= len(text) {
			out.WriteString(text[i:])
			break
		}
		out.WriteString("[REDACTED]")
		i = j + 1
	}
	return out.String()
}
