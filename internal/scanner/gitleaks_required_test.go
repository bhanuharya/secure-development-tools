package scanner

import (
	"errors"
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
	t.Skipf("gitleaks not installed: %v", err)
}

// Without the binary and without SDT_TEST_REQUIRE_GITLEAKS the helper skips (it once called itself).
func TestSkipWithoutGitleaksSkips(t *testing.T) {
	t.Setenv("SDT_TEST_REQUIRE_GITLEAKS", "")
	var inner *testing.T
	t.Run("gitleaks missing", func(t *testing.T) {
		inner = t
		skipWithoutGitleaks(t, errors.New("executable file not found"))
	})
	if !inner.Skipped() {
		t.Fatal("expected the test to be skipped")
	}
}
