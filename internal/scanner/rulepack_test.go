package scanner

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/bhanuharya/secure-development-tools/internal/config"
)

const firstPartyRule = `# comment that the merged file does not need
rules:
  - id: scp.javascript.injection.eval
    languages: [javascript]
    severity: ERROR
    message: "eval of $X: never"
    metadata:
      cwe: "CWE-95: Eval Injection"
      added: 2024-05-01
      confidence: HIGH
    patterns:
      - pattern: eval($X)
      - pattern-not: |
          eval("...")
`

const vendoredRule = `rules:
- id: no-string-eqeq
  languages: [java]
  severity: WARNING
  message: >-
    Strings should be compared
    with equals
  pattern: $X == "..."
`

func rulePack(t *testing.T) (pack string, files []string) {
	t.Helper()
	pack = filepath.Join(t.TempDir(), "sdt", "rules", "opengrep-rules")
	files = []string{filepath.Join(pack, "javascript", "injection.yaml"), filepath.Join(pack, "vendor", "semgrep", "java", "lang", "correctness", "eqeq.yaml")}
	writeSource(t, pack, "javascript/injection.yaml", firstPartyRule)
	writeSource(t, pack, "vendor/semgrep/java/lang/correctness/eqeq.yaml", vendoredRule)
	return pack, files
}

func rulesOfFile(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []map[string]any `yaml:"rules"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not readable YAML: %v", path, err)
	}
	return doc.Rules
}

// One file holds every rule, unchanged except for its id, and the id is the one
// a scan reports today once the engine's own clean-up has run.
func TestMergedRulesKeepEachRuleAndTheIdItIsReportedWith(t *testing.T) {
	_, files := rulePack(t)
	merged, err := mergedRules(files, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rules := rulesOfFile(t, merged)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	var ids []string
	for i, rule := range rules {
		ids = append(ids, cleanRuleID(rule["id"].(string)))
		original := rulesOfFile(t, files[i])[0]
		original["id"] = rule["id"]
		if !reflect.DeepEqual(rule, original) {
			t.Errorf("rule %s changed in the merged file:\n got %v\nwant %v", ids[i], rule, original)
		}
	}
	if want := []string{"scp.javascript.injection.eval", "vendor.semgrep.java.lang.correctness.no-string-eqeq"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids after clean-up = %v, want %v", ids, want)
	}
}

// The prefix follows the engine's command line: the rule file's directory,
// relative to the scan root when the rules are inside it (a self-scan).
func TestRuleIDPrefixFollowsTheEngine(t *testing.T) {
	root := filepath.FromSlash("/work/repo")
	for file, want := range map[string]string{
		"/opt/sdt/rules/opengrep-rules/javascript/x.yaml":          "opt.sdt.rules.opengrep-rules.javascript.",
		"/work/repo/rules/opengrep-rules/vendor/semgrep/go/x.yaml": "rules.opengrep-rules.vendor.semgrep.go.",
		"/work/repo/x.yaml":             "",
		"/work/repository/rules/x.yaml": "work.repository.rules.",
	} {
		if got := ruleIDPrefix(filepath.FromSlash(file), root); got != want {
			t.Errorf("ruleIDPrefix(%s) = %q, want %q", file, got, want)
		}
	}
}

// A rule file the merge cannot carry over safely is not merged at all: the
// scan then loads the files one by one, as it always did.
func TestRulesThatCannotBeMergedAreLoadedFileByFile(t *testing.T) {
	cases := map[string]string{
		"an anchor":             "rules:\n  - id: a\n    languages: &langs [java]\n    severity: ERROR\n    message: m\n    pattern: f()\n  - id: b\n    languages: *langs\n    severity: ERROR\n    message: m\n    pattern: g()\n",
		"a second document":     vendoredRule + "---\n" + vendoredRule,
		"another top-level key": "version: 1\n" + vendoredRule,
		"the same id twice":     vendoredRule + strings.TrimPrefix(vendoredRule, "rules:\n"),
		"no rules":              "rules: []\n",
	}
	for name, content := range cases {
		pack := filepath.Join(t.TempDir(), "opengrep-rules")
		writeSource(t, pack, "java/rule.yaml", content)
		if merged, err := mergedRules([]string{filepath.Join(pack, "java", "rule.yaml")}, t.TempDir(), t.TempDir()); err == nil {
			t.Errorf("%s: merged into %s, want an error", name, merged)
		}
	}
}

// The plan still names every rule file; what runs is the merged file, unless
// the setting or a non-OpenGrep engine says otherwise.
func TestOpengrepRunsTheMergedRulesAndPlansTheFiles(t *testing.T) {
	withRulePack(t)
	fakeOpengrep(t)
	ctx := testCtx()
	ctx.CacheRoot = t.TempDir()
	root := t.TempDir()
	writeSource(t, root, "app.js", "eval(x)\n")
	task, err := (&OpengrepAdapter{}).Plan(ctx, config.Defaults(), root)
	if err != nil {
		t.Fatal(err)
	}
	count := func(args []string, flag string) (n int) {
		for _, arg := range args {
			if arg == flag {
				n++
			}
		}
		return n
	}
	if count(task.Args, "--config") < 2 || count(task.Args, "--no-rewrite-rule-ids") != 0 {
		t.Fatalf("the plan must list the rule files, got: %v", task.Args)
	}
	if count(task.ExecArgs, "--config") != 1 || count(task.ExecArgs, "--no-rewrite-rule-ids") != 1 {
		t.Fatalf("what runs must load one merged rule file, got: %v", task.ExecArgs)
	}
	withoutRules := func(args []string) (rest []string) {
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--config":
				i++
			case "--no-rewrite-rule-ids":
			default:
				rest = append(rest, args[i])
			}
		}
		return rest
	}
	if !reflect.DeepEqual(withoutRules(task.Args), withoutRules(task.ExecArgs)) {
		t.Fatalf("both command lines must differ in the rules only:\n%v\n%v", withoutRules(task.Args), withoutRules(task.ExecArgs))
	}
	merged := len(rulesOfFile(t, filepath.Join(ctx.CacheRoot, "native", "opengrep-rules.yaml")))
	if files := count(task.Args, "--config"); merged < files {
		t.Fatalf("%d rule files merged into %d rules", files, merged)
	}

	t.Setenv("SDT_OPENGREP_MERGE_RULES", "0")
	if task, err = (&OpengrepAdapter{}).Plan(ctx, config.Defaults(), root); err != nil || task.ExecArgs != nil {
		t.Fatalf("SDT_OPENGREP_MERGE_RULES=0 must run the planned command line, got %v (%v)", task.ExecArgs, err)
	}
}

// End to end with the real engine and the real rule pack: the merged rule file
// gives exactly the output the rule files give, raw rule ids included.
func TestRealEngineReportsTheSameWithMergedRules(t *testing.T) {
	bin := whichBin(envOr("SDT_OPENGREP_BIN", "opengrep"))
	if bin == "" || strings.Contains(filepath.Base(bin), "semgrep") {
		t.Skip("opengrep binary not installed")
	}
	withRulePack(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeSource(t, root, "web/app.js", "function run(input, el) {\n  el.innerHTML = input;\n  return eval(input);\n}\n")
	writeSource(t, root, "src/A.java", "class A {\n  boolean same(String a) {\n    return a == \"x\";\n  }\n}\n")
	writeSource(t, root, "tool.py", "import subprocess, sys\nsubprocess.call(sys.argv[1], shell=True)\nprint(eval(sys.argv[2]))\n")
	ctx := testCtx()
	ctx.CacheRoot = t.TempDir()
	task, err := (&OpengrepAdapter{}).Plan(ctx, config.Defaults(), root)
	if err != nil {
		t.Fatal(err)
	}
	if task.ExecArgs == nil {
		t.Fatal("the real rule pack must be mergeable")
	}
	results := func(args []string) []string {
		t.Helper()
		cmd := exec.Command(task.Executable, args...)
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil && len(out) == 0 {
			t.Fatalf("opengrep failed: %v", err)
		}
		var data struct {
			Results []map[string]any `json:"results"`
			Errors  []any            `json:"errors"`
		}
		if err := json.Unmarshal(out, &data); err != nil {
			t.Fatalf("invalid opengrep JSON: %v", err)
		}
		if len(data.Errors) > 0 {
			t.Fatalf("opengrep reported errors: %v", data.Errors)
		}
		var lines []string
		for _, result := range data.Results {
			line, _ := json.Marshal(result)
			lines = append(lines, string(line))
		}
		sort.Strings(lines)
		return lines
	}
	planned, merged := results(task.Args), results(task.ExecArgs)
	if len(planned) < 4 {
		t.Fatalf("the samples must trigger first-party and vendored rules, got %d results", len(planned))
	}
	if !reflect.DeepEqual(planned, merged) {
		t.Fatalf("merged rules changed the output:\nfiles:  %v\nmerged: %v", planned, merged)
	}
}
