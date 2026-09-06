package scanner

import "testing"

// Test fixtures must never be passed as --config: a multi-doc test target
// fails the whole engine run (exit 7). Regression test for the Wave 2
// outage where *.test.yaml fixtures broke every scan.
func TestIsRuleFile(t *testing.T) {
	for _, f := range []string{"security.yaml", "args-os.yml"} {
		if !isRuleFile(f) {
			t.Fatalf("%s must be a rule file", f)
		}
	}
	for _, f := range []string{
		"hostnetwork-pod.test.yaml",
		"allow-privilege-escalation.fixed.test.yaml",
		"security.test.py",
		"foo.json",
	} {
		if isRuleFile(f) {
			t.Fatalf("%s must not be a rule file", f)
		}
	}
}
