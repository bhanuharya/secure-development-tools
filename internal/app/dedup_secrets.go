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
// line no secret-scanner finding names is kept as it is. The secret
// scanner's finding records the identity of the code-rule finding it
// replaced, so a baseline built from this scan still knows the code-rule
// finding when a later scan reports only that (a pull request scan reads
// only the new commits for secrets, but every changed file for code rules).
func collapseCrossScannerSecrets(findings []*finding.Finding) ([]*finding.Finding, int) {
	secretLines := map[string]*finding.Finding{}
	for _, f := range findings {
		if f.Category == finding.CatSecret && f.Location != nil && f.Location.StartLine != nil {
			if _, ok := secretLines[lineKey(f.Location)]; !ok {
				secretLines[lineKey(f.Location)] = f
			}
		}
	}
	if len(secretLines) == 0 {
		return findings, 0
	}
	kept := make([]*finding.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Category != finding.CatSecret && slices.Contains(f.Rule.CWE, "CWE-798") &&
			f.Location != nil && f.Location.StartLine != nil && secretLines[lineKey(f.Location)] != nil {
			if f.Fingerprint.Value != "" {
				into := secretLines[lineKey(f.Location)]
				into.Fingerprint.Collapsed = append(into.Fingerprint.Collapsed,
					finding.Fingerprint{Algorithm: f.Fingerprint.Algorithm, Value: f.Fingerprint.Value, Content: f.Fingerprint.Content})
			}
			continue
		}
		kept = append(kept, f)
	}
	return kept, len(findings) - len(kept)
}

func lineKey(l *finding.Location) string {
	return fmt.Sprintf("%s:%d", l.Path, *l.StartLine)
}
