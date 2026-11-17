// Package report renders console/JSON/SARIF/manifest outputs with mandatory redaction.
package report

import (
	"regexp"
	"strings"
)

var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,255}\b`),
	regexp.MustCompile(`\bxox[bapose]-[A-Za-z0-9-]{10,}\b`),
	regexp.MustCompile(`\b[sp]k_(?:live|test)_[0-9A-Za-z]{16,}\b`),
	regexp.MustCompile(`\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}\b`),
	regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,}\b`),
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}`),
	regexp.MustCompile(`(?i)\b[\w-]*(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|authorization|key)[\w-]*\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{8,})`),
}

// Redact replaces credential-like values and exact secret tokens.
func Redact(text string, secrets ...string) string {
	out := redactSource(text, nil)
	for _, s := range secrets {
		if len(s) >= 4 && strings.Contains(out, s) {
			out = strings.ReplaceAll(out, s, "[REDACTED]")
		}
	}
	for _, re := range credentialPatterns {
		out = re.ReplaceAllString(out, "[REDACTED]")
	}
	for _, re := range credentialValues {
		out = redactGroup(re, out)
	}
	return out
}

// credentialValues hide only their "v" group, so the key, call or host around the value stays
// readable. They cover shapes of the shared corpus (testdata/redaction/corpus.json) the
// patterns above miss.
var credentialValues = []*regexp.Regexp{
	// scheme://user:password@host
	regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@"']+:(?P<v>[^@\s/"'\[]+)@`),
	// setPassword("..."), withApiKey('...'), put_secret("...")
	regexp.MustCompile("(?i)\\b(?:set|with|put)?_?(?:password|passwd|pwd|passphrase|secret|token|api_?key|credentials?|" +
		"(?:signing|private|access|secret|encryption|master)_?key)\\w*\\s*\\(\\s*[\"'`](?P<v>[^\"'`\\[]+)[\"'`]"),
	// SetBasicAuth("user", "..."), request.auth('user', '...')
	regexp.MustCompile("(?i)\\b(?:set_?basic_?auth|basic_?auth|with_?basic_?auth|auth)\\s*\\(\\s*[\"'`][^\"'`]*[\"'`]\\s*,\\s*" +
		"[\"'`](?P<v>[^\"'`\\[]+)[\"'`]"),
	// YAML "secret-key: |" (or >) with the value on the following, deeper lines
	regexp.MustCompile(`(?im)^[ \t]*[\w.-]*(?:password|passwd|secret|token|key)[\w.-]*[ \t]*:[ \t]*[|>][-+]?[ \t]*\n[ \t]+(?P<v>\S[^\n]*)`),
}

func redactGroup(re *regexp.Regexp, text string) string {
	group := re.SubexpIndex("v")
	var out strings.Builder
	last := 0
	for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
		start, end := m[2*group], m[2*group+1]
		if start < 0 || text[start:end] == "[REDACTED]" {
			continue
		}
		out.WriteString(text[last:start])
		out.WriteString("[REDACTED]")
		last = end
	}
	out.WriteString(text[last:])
	return out.String()
}
