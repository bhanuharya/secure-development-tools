package report

import (
	"regexp"
	"strings"
)

// Keep the vocabulary aligned with the hardcoded-secret rules, including signing keys.
const secretKeyNames = `password|passwd|pwd|passphrase|secret|token|salt|credentials?|apikey|` +
	`(?:api|app|auth|access|aes|cookie|encryption|hmac|jwt|master|private|secret|session|signing)[._-]?key`

var secretAssignment = regexp.MustCompile(`(?i)(?:` + secretKeyNames + `)["']?\s*[:=]\s*["'` + "`" + `]`)
var credentialContainer = regexp.MustCompile(`(?i)\b(?:(?:accounts|basicauth|credentials?)\s*[({]|` +
	`basicauth\.(?:New|Config)\s*[({]|["']?(?:users|accounts|credentials?)["']?\s*[:=]\s*(?:map\[[^\]]+\][\w]+\s*|dict\s*)?[({])`)

// QuotedEnd also accepts incomplete excerpts: an unclosed literal extends to EOF.
func QuotedEnd(text string, open int) int {
	for i := open + 1; i < len(text); i++ {
		if text[i] == '\\' {
			i++
		} else if text[i] == text[open] {
			return i
		}
	}
	return len(text)
}

// ClosingBracket ignores quoted brackets and returns EOF for a cut-off excerpt.
func ClosingBracket(text string, open int) int {
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '"', '\'', '`':
			i = QuotedEnd(text, i)
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(text)
}

func rememberLiteral(value string, withheld map[string]struct{}) string {
	if withheld != nil && value != "" && value != "[REDACTED]" {
		withheld[value] = struct{}{}
	}
	// Keeping line breaks lets callers redact a whole file before selecting numbered lines.
	return "[REDACTED]" + strings.Repeat("\n", strings.Count(value, "\n"))
}

func redactQuoted(text string, withheld map[string]struct{}) string {
	var out strings.Builder
	for i := 0; i < len(text); i++ {
		out.WriteByte(text[i])
		if text[i] != '"' && text[i] != '\'' && text[i] != '`' {
			continue
		}
		end := QuotedEnd(text, i)
		out.WriteString(rememberLiteral(text[i+1:end], withheld))
		if end < len(text) {
			out.WriteByte(text[end])
		}
		i = end
	}
	return out.String()
}

func redactSource(text string, withheld map[string]struct{}) string {
	for offset := 0; offset < len(text); {
		loc := credentialContainer.FindStringIndex(text[offset:])
		if loc == nil {
			break
		}
		open := offset + loc[1] - 1
		close := ClosingBracket(text, open)
		inner := redactQuoted(text[open+1:close], withheld)
		text = text[:open+1] + inner + text[close:]
		offset = open + 1 + len(inner)
		if close < len(text) {
			offset++
		}
	}
	for offset := 0; offset < len(text); {
		loc := secretAssignment.FindStringIndex(text[offset:])
		if loc == nil {
			break
		}
		open := offset + loc[1] - 1
		end := QuotedEnd(text, open)
		value := rememberLiteral(text[open+1:end], withheld)
		text = text[:open+1] + value + text[end:]
		offset = open + 1 + len(value)
		if offset < len(text) {
			offset++
		}
	}
	return text
}
