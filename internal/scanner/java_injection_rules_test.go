package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The rules in java/injection.yaml repeat one list of sources (an anchor would
// make every scan load the rule files one by one). A getter added to one rule
// and not to the others is a weakness class that silently misses that input,
// so the lists must stay the same text.
func TestJavaInjectionRulesShareTheirSources(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "rules", "opengrep-rules", "java", "injection.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Rules []struct {
			ID      string    `yaml:"id"`
			Sources yaml.Node `yaml:"pattern-sources"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	first := map[string]string{}
	sources := map[string]string{}
	counts := map[string]int{}
	for _, rule := range file.Rules {
		kind := "request"
		if strings.HasSuffix(rule.ID, "-from-argument") {
			kind = "argument"
		}
		text, err := yaml.Marshal(&rule.Sources)
		if err != nil {
			t.Fatal(err)
		}
		counts[kind]++
		if _, seen := sources[kind]; !seen {
			first[kind], sources[kind] = rule.ID, string(text)
			continue
		}
		if string(text) != sources[kind] {
			t.Errorf("%s and %s follow different sources", first[kind], rule.ID)
		}
	}
	if counts["request"] != 7 || counts["argument"] != 2 {
		t.Fatalf("want 7 rules for request data and 2 for arguments, got %d and %d", counts["request"], counts["argument"])
	}
}
