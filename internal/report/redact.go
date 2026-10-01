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
	out := text
	for _, s := range secrets {
		if len(s) >= 4 && strings.Contains(out, s) {
			out = strings.ReplaceAll(out, s, "[REDACTED]")
		}
	}
	for _, re := range credentialPatterns {
		out = re.ReplaceAllString(out, "[REDACTED]")
	}
	return out
}
