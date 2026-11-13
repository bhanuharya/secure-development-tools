package scanner

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// detectionCase is one planted weakness in testdata/detection: a small file with
// one well-known flaw, the CWE numbers a correct report may carry, and who is
// expected to find it. "rules" means the shipped rule pack must; "sonarqube"
// means the pipeline leaves it to SonarQube's own analyser and it is not
// checked here.
type detectionCase struct {
	path, weakness, by string
	cwes               map[int]bool
}

func detectionCases(t *testing.T, table string) []detectionCase {
	t.Helper()
	file, err := os.Open(table)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var cases []detectionCase
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		line := strings.TrimSpace(lines.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "path\t") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("%s: want 4 tab-separated fields, got %q", table, line)
		}
		c := detectionCase{path: fields[0], weakness: fields[1], by: fields[3], cwes: map[int]bool{}}
		for _, number := range strings.Split(fields[2], ",") {
			n, err := strconv.Atoi(strings.TrimSpace(number))
			if err != nil {
				t.Fatalf("%s: bad CWE %q for %s", table, number, c.path)
			}
			c.cwes[n] = true
		}
		if c.by != "rules" && c.by != "sonarqube" && c.by != "none" {
			t.Fatalf("%s: %s is found by %q, want rules, sonarqube or none", table, c.path, c.by)
		}
		cases = append(cases, c)
	}
	return cases
}

// Every planted weakness that the rule pack is responsible for is reported, by
// a rule of the right weakness class: a sample that is only flagged for some
// other reason does not count. This is the floor detection may not fall below;
// raise it by adding a rule and changing "sonarqube" to "rules" in the table.
func TestRulePackFindsThePlantedWeaknesses(t *testing.T) {
	bin := whichBin(envOr("SDT_OPENGREP_BIN", "opengrep"))
	if bin == "" || strings.Contains(filepath.Base(bin), "semgrep") {
		t.Skip("opengrep binary not installed")
	}
	withRulePack(t)
	root, err := filepath.EvalSymlinks(filepath.Join(repoRoot(t), "testdata", "detection"))
	if err != nil {
		t.Fatal(err)
	}
	cases := detectionCases(t, filepath.Join(root, "expected.tsv"))
	ctx := testCtx()
	ctx.CacheRoot = t.TempDir()
	adapter := &OpengrepAdapter{}
	task, err := adapter.Plan(ctx, config.Defaults(), root)
	if err != nil {
		t.Fatal(err)
	}
	args := task.Args
	if task.ExecArgs != nil {
		args = task.ExecArgs
	}
	cmd := exec.Command(task.Executable, args...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		t.Fatalf("opengrep failed: %v", err)
	}
	var probe struct {
		Errors []any `json:"errors"`
	}
	if err := json.Unmarshal(out, &probe); err != nil || len(probe.Errors) > 0 {
		t.Fatalf("opengrep output unusable (%v) or with errors: %v", err, probe.Errors)
	}
	parsed := adapter.Parse("test", root, out, "", 0)
	reported := map[string]map[int]bool{}
	recordCWEs(reported, parsed.Findings)

	// The inventory is a second detection gate: its convention findings must
	// catch the planted route and stay silent on the safe look-alike (§8).
	t.Setenv("SDT_HOME", repoRoot(t))
	inventory := &EndpointsAdapter{}
	inventoryTask, err := inventory.Plan(ctx, config.Defaults(), root)
	if err != nil {
		t.Fatalf("endpoints plan: %v", err)
	}
	inventoryParsed := inventory.Parse("test", root, inventoryTask.Stdout, "", 0)
	if inventoryParsed.Health != HealthCompleted {
		t.Fatalf("endpoints parse: %v", inventoryParsed.Diagnostics)
	}
	inventoryReported := map[string]map[int]bool{}
	recordCWEs(inventoryReported, inventoryParsed.Findings)

	required, found, lookalikes, clean := 0, 0, 0, 0
	for _, c := range cases {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(c.path))); err != nil {
			t.Errorf("%s is in the table but not in testdata/detection", c.path)
			continue
		}
		if c.by == "none" {
			// A look-alike: code that resembles the weakness but is safe. Reporting it under
			// one of its CWEs is the false positive this row guards against.
			lookalikes++
			wrong := []int{}
			for cwe := range c.cwes {
				if reported[c.path][cwe] {
					wrong = append(wrong, cwe)
				}
			}
			if len(wrong) == 0 {
				clean++
			} else {
				t.Errorf("%s (%s) is reported as CWE %v, but it is a safe look-alike", c.path, c.weakness, wrong)
			}
			continue
		}
		if c.by != "rules" {
			continue
		}
		required++
		hit := false
		for cwe := range c.cwes {
			hit = hit || reported[c.path][cwe]
		}
		if hit {
			found++
		} else {
			t.Errorf("%s (%s) is not reported by a rule of its weakness class", c.path, c.weakness)
		}
	}

	// Endpoint samples are judged on what the inventory reported by itself:
	// the rule pack result above must not mask a missed convention finding.
	inventoryRequired, inventoryFound, inventoryLookalikes, inventoryClean := 0, 0, 0, 0
	for _, c := range cases {
		if !strings.HasPrefix(c.path, "endpoints/") || c.by == "sonarqube" {
			continue
		}
		if c.by == "none" {
			inventoryLookalikes++
			if len(inventoryReported[c.path]) == 0 {
				inventoryClean++
			} else {
				t.Errorf("%s (%s) is reported by the endpoints adapter, but it is a safe look-alike", c.path, c.weakness)
			}
			continue
		}
		inventoryRequired++
		hit := false
		for cwe := range c.cwes {
			hit = hit || inventoryReported[c.path][cwe]
		}
		if hit {
			inventoryFound++
		} else {
			t.Errorf("%s (%s) is not reported by the endpoints adapter", c.path, c.weakness)
		}
	}
	t.Logf("%d of %d planted weaknesses the rule pack is responsible for are found; %d more are left to SonarQube; %d of %d safe look-alikes are not reported; endpoints adapter: %d of %d inventory samples reported, %d of %d inventory look-alikes not reported",
		found, required, len(cases)-required-lookalikes, clean, lookalikes,
		inventoryFound, inventoryRequired, inventoryClean, inventoryLookalikes)
}

// recordCWEs indexes findings by file and CWE number so a table row can ask
// whether a weakness class was reported for its path.
func recordCWEs(reported map[string]map[int]bool, findings []*finding.Finding) {
	number := regexp.MustCompile(`\d+`)
	for _, f := range findings {
		if f.Location == nil {
			continue
		}
		if reported[f.Location.Path] == nil {
			reported[f.Location.Path] = map[int]bool{}
		}
		for _, cwe := range f.Rule.CWE {
			if n, err := strconv.Atoi(number.FindString(cwe)); err == nil {
				reported[f.Location.Path][n] = true
			}
		}
	}
}
