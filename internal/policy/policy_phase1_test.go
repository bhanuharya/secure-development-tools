package policy

import (
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
)

// Policy digest must cover complete inputs: match-clause edits alter it.
func TestDigestSensitiveToMatchDetails(t *testing.T) {
	mk := func(reachable []string) *config.ScanConfiguration {
		cfg := config.Defaults()
		cfg.Policy.Rules = []config.PolicyRule{{
			ID:     "r",
			Match:  config.PolicyMatch{Categories: []string{"dependency-vulnerability"}, Reachable: reachable},
			Action: "fail",
		}}
		return cfg
	}
	a := Digest(mk([]string{"reachable"}))
	b := Digest(mk([]string{"unreachable"}))
	if a == b {
		t.Fatal("reachable change must alter policy digest")
	}
	c := Digest(mk([]string{"reachable"}))
	if a != c {
		t.Fatal("identical policies must digest identically")
	}
	d := config.Defaults()
	d.Policy.DefaultAction = "warn"
	if Digest(config.Defaults()) == Digest(d) {
		t.Fatal("defaultAction change must alter policy digest")
	}
}
