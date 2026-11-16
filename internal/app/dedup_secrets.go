package app

import (
	"fmt"
	"slices"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// collapseCrossScannerSecrets keeps one finding per hard-coded secret. A code
// rule for hard-coded credentials (CWE-798: a private key block, an AWS key
// id, a literal password in a production profile) and the secret scanner
// often match the same line; on 20 measured services 41 of 83 such code-rule
// findings were a second copy of a secret-scanner finding. The secret
// scanner's finding is kept: it carries the commit history and the secret
// handling (always blocking, never shown in full). A code-rule finding on a
// line no secret-scanner finding names is kept as it is.
func collapseCrossScannerSecrets(findings []*finding.Finding) ([]*finding.Finding, int) {
	secretLines := map[string]bool{}
	for _, f := range findings {
		if f.Category == finding.CatSecret && f.Location != nil && f.Location.StartLine != nil {
			secretLines[lineKey(f.Location)] = true
		}
	}
	if len(secretLines) == 0 {
		return findings, 0
	}
	kept := make([]*finding.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Category != finding.CatSecret && slices.Contains(f.Rule.CWE, "CWE-798") &&
			f.Location != nil && f.Location.StartLine != nil && secretLines[lineKey(f.Location)] {
			continue
		}
		kept = append(kept, f)
	}
	return kept, len(findings) - len(kept)
}

func lineKey(l *finding.Location) string {
	return fmt.Sprintf("%s:%d", l.Path, *l.StartLine)
}
