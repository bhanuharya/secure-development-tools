package endpoints_test

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bhanuharya/secure-development-tools/internal/scanner"
)

// Pin extraction separately from the resolver: every ignoring builder call is
// a fact, and a following matcher must never become an unknown access rule.
func TestSpringIgnoringChainFactRules(t *testing.T) {
	binary := scanner.OpengrepBinary()
	if binary == "" {
		t.Skip("opengrep not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rules := filepath.Join("..", "..", "rules", "endpoint-facts", "java.yaml")
	fixture := filepath.Join("..", "..", "testdata", "endpoints", "spring-ignoring-chain")
	raw, err := exec.CommandContext(ctx, binary, "--config", rules, "--json", "--quiet", fixture).Output()
	if err != nil {
		t.Fatalf("extract ignoring facts: %v", err)
	}
	var output struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Extra   struct {
				Metavars map[string]struct {
					Content string `json:"abstract_content"`
				} `json:"metavars"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &output); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, fact := range output.Results {
		if strings.HasSuffix(fact.CheckID, ".security_matcher_unmodelled") {
			t.Errorf("ignoring chain produced an authorization rule: %s", fact.CheckID)
		}
		if strings.HasSuffix(fact.CheckID, ".security_ignored") {
			counts[fact.Extra.Metavars["$IGNORE"].Content]++
		}
	}
	for name, want := range map[string]int{"antMatchers": 6, "requestMatchers": 1, "mvcMatchers": 1} {
		if counts[name] != want {
			t.Errorf("%s ignore facts = %d, want %d", name, counts[name], want)
		}
	}
}
