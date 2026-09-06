// Package version reports CLI/schema/adapter identities.
package version

// These are stamped at release time via -ldflags.
var (
	CLI      = "0.1.0-dev"
	Schema   = "secure-dev/v1alpha1"
	Finding  = "secure-dev/finding/v1alpha1"
	Manifest = "secure-dev/manifest/v1alpha1"
)

// Adapters lists built-in adapter IDs.
func Adapters() []string {
	return []string{"opengrep", "gitleaks", "trivy-fs", "trivy-image"}
}
