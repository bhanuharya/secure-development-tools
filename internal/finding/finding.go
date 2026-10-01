// Package finding implements the canonical finding model (PRD FIND-001/003)
// with severity mapping (FIND-002 semantics) and versioned fingerprints.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	SchemaVersion      = "secure-dev/finding/v1alpha1"
	FingerprintVersion = "sdt-v2"
)

// Categories.
const (
	CatSAST      = "sast"
	CatSecret    = "secret"
	CatDepVuln   = "dependency-vulnerability"
	CatImgVuln   = "image-vulnerability"
	CatMisconfig = "misconfiguration"
)

// Canonical severities.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevInfo     = "info"
	SevUnknown  = "unknown"
)

// Baseline states.
const (
	StateNew      = "new"
	StateExisting = "existing"
	StateResolved = "resolved-reference"
	StateUnknown  = "unknown"
)

// Finding is the canonical scanner-neutral representation.
type Finding struct {
	SchemaVersion string       `json:"schemaVersion"`
	ID            string       `json:"id"`
	Fingerprint   Fingerprint  `json:"fingerprint"`
	Scanner       ScannerID    `json:"scanner"`
	Category      string       `json:"category"`
	Rule          Rule         `json:"rule"`
	Severity      Severity     `json:"severity"`
	Confidence    string       `json:"confidence,omitempty"`
	Message       string       `json:"message"`
	Location      *Location    `json:"location,omitempty"`
	Artifact      *Artifact    `json:"artifact,omitempty"`
	Evidence      *Evidence    `json:"evidence,omitempty"`
	Remediation   *Remediation `json:"remediation,omitempty"`
	BaselineState string       `json:"baselineState"`
	Suppression   *Suppression `json:"suppression,omitempty"`
	// Reachability records whether a vulnerable package is imported by
	// first-party source. Set only for dependency/image vulnerabilities;
	// nil means not analyzed. See internal/reachability for the soundness
	// contract: unknown never demotes.
	Reachability *Reachability  `json:"reachability,omitempty"`
	Redaction    Redaction      `json:"redaction"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// Reachability states: "reachable" | "unreachable" | "unknown".
type Reachability struct {
	State    string `json:"state"`
	Reason   string `json:"reason"`
	Evidence string `json:"evidence,omitempty"`
}

type Fingerprint struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type ScannerID struct {
	Adapter string `json:"adapter"`
	Tool    string `json:"tool"`
	Version string `json:"version,omitempty"`
}

type Rule struct {
	ID         string   `json:"id"`
	Name       string   `json:"name,omitempty"`
	Help       string   `json:"help,omitempty"`
	CWE        []string `json:"cwe,omitempty"`
	OWASP      []string `json:"owasp,omitempty"`
	References []string `json:"references,omitempty"`
}

type Severity struct {
	Canonical string `json:"canonical"`
	Original  string `json:"original,omitempty"`
}

type Location struct {
	Path      string `json:"path"`
	StartLine *int   `json:"startLine,omitempty"`
	EndLine   *int   `json:"endLine,omitempty"`
	StartCol  *int   `json:"startCol,omitempty"`
	EndCol    *int   `json:"endCol,omitempty"`
}

type Artifact struct {
	Package          string `json:"package,omitempty"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
	Target           string `json:"target,omitempty"`
	Image            string `json:"image,omitempty"`
	Resource         string `json:"resource,omitempty"`
}

type Evidence struct {
	Text string `json:"text,omitempty"`
}

type Remediation struct {
	FixedVersion string `json:"fixedVersion,omitempty"`
	Guidance     string `json:"guidance,omitempty"`
}

type Suppression struct {
	ExceptionID string `json:"exceptionId"`
	Reason      string `json:"reason,omitempty"`
}

type Redaction struct {
	Applied bool `json:"applied"`
}

// MapSeverity maps a native severity to canonical, retaining the original.
// Unknown values map to "unknown" (never silently low).
func MapSeverity(native string) Severity {
	orig := strings.TrimSpace(native)
	v := strings.ToLower(orig)
	switch v {
	case "critical", "crit", "fatal":
		return Severity{Canonical: SevCritical, Original: orig}
	case "high", "error":
		return Severity{Canonical: SevHigh, Original: orig}
	case "medium", "moderate", "warning", "warn":
		return Severity{Canonical: SevMedium, Original: orig}
	case "low":
		return Severity{Canonical: SevLow, Original: orig}
	case "info", "informational", "note":
		return Severity{Canonical: SevInfo, Original: orig}
	case "":
		return Severity{Canonical: SevUnknown, Original: orig}
	default:
		return Severity{Canonical: SevUnknown, Original: orig}
	}
}

// FingerprintValue computes the stable fingerprint (FingerprintVersion).
// Inputs: category | adapter/clean-rule | normalized rel path |
// semantic context (content when the tool provides it, plus the start line
// as a last-resort disambiguator for true duplicates) or artifact identity.
// Line number is never the primary identity component.
func FingerprintValue(category, adapter, ruleID, relPath, semanticContext string) string {
	path := normalizePath(relPath)
	ctx := normalizeContext(semanticContext)
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		FingerprintVersion, category, adapter+"/"+ruleID, path, ctx, "")
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = filepath.ToSlash(p)
	p = strings.TrimPrefix(p, "./")
	return p
}

func normalizeContext(s string) string {
	// Collapse whitespace; bound length so huge blobs don't dominate.
	fields := strings.Fields(s)
	joined := strings.Join(fields, " ")
	if len(joined) > 512 {
		joined = joined[:512]
	}
	return joined
}
