package scanner

import (
	"os"
	"testing"
)

// skipWithoutGitleaks skips a test that needs the gitleaks binary. CI installs the
// pinned gitleaks and sets SDT_TEST_REQUIRE_GITLEAKS=1, so there a missing binary
// fails the test instead of letting it pass by being skipped.
func skipWithoutGitleaks(t *testing.T, err error) {
	t.Helper()
	if os.Getenv("SDT_TEST_REQUIRE_GITLEAKS") == "1" {
		t.Fatalf("gitleaks is required (SDT_TEST_REQUIRE_GITLEAKS=1) but not usable: %v", err)
	}
	skipWithoutGitleaks(t, err)
}
