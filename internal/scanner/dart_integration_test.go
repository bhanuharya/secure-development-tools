package scanner

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
	"github.com/bhanuharya/secure-development-tools/internal/report"
)

// Exercise the production rule selection, engine output, normalization, and
// report conversion with a Dart-only repository. Individual rule fixtures
// cannot catch failures at these boundaries.
func TestDartRuleScanAndReports(t *testing.T) {
	if OpengrepBinary() == "" {
		t.Skip("opengrep not installed")
	}
	withRulePack(t)
	root := t.TempDir()
	source := `import 'dart:io';
import 'package:encrypt/encrypt.dart';
import 'package:sqlite3/sqlite3.dart';
import 'package:webview_flutter/webview_flutter.dart';

void check(HttpRequest request, dynamic db, dynamic text, WebViewController webview) {
  final input = request.uri.queryParameters['id'];
  db.select('SELECT * FROM users WHERE id = $input');
  webview.runJavaScript('show("${text.text}")');
  AES(Key.allZerosOfLength(32), mode: AESMode.ecb);
}
`
	if err := os.WriteFile(filepath.Join(root, "main.dart"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	// Matching method names in another file must not inherit package imports.
	unrelated := `void check(dynamic request, dynamic db, dynamic text, dynamic webview) {
  final input = request.uri.queryParameters['id'];
  db.select('SELECT $input');
  webview.runJavaScript('show("${text.text}")');
  AES(Key.allZerosOfLength(32), mode: AESMode.ecb);
}
`
	if err := os.WriteFile(filepath.Join(root, "unrelated.dart"), []byte(unrelated), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &OpengrepAdapter{}
	if got := a.Detect(root, detectLanguages(root)); got.State != "applicable" {
		t.Fatalf("dart rules not selected: %+v", got)
	}
	task, err := a.Plan(testCtx(), config.Defaults(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(task.Args, " "), "dart/security.yaml") {
		t.Fatalf("dart rule pack missing from plan: %v", task.Args)
	}
	cmd := exec.Command(task.Executable, task.Args...)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("opengrep scan: %v", err)
	}
	parsed := a.Parse("test", root, output, "", 0)
	if parsed.Health != HealthCompleted {
		t.Fatalf("health=%s diagnostics=%v", parsed.Health, parsed.Diagnostics)
	}
	want := map[string]bool{
		"scp.dart.crypto.aes-ecb":           false,
		"scp.dart.crypto.zero-key":          false,
		"scp.dart.injection.sql":            false,
		"scp.dart.webview.untrusted-script": false,
	}
	for _, f := range parsed.Findings {
		if _, ok := want[f.Rule.ID]; !ok {
			continue
		}
		want[f.Rule.ID] = true
		if f.Severity.Canonical != "medium" || f.Location == nil || f.Location.Path != "main.dart" {
			t.Fatalf("bad Dart finding: %+v", f)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("missing finding %s", id)
		}
	}
	outcome := policy.Evaluate(config.Defaults(), parsed.Findings)
	if outcome.Status != "passed" || len(outcome.Blockers) != 0 {
		t.Fatalf("new Dart findings unexpectedly block: %+v", outcome)
	}
	canonical := report.CanonicalReport{SchemaVersion: "secure-dev/report/v1alpha1", Findings: parsed.Findings, Policy: outcome}
	rawJSON, err := json.Marshal(canonical)
	if err != nil {
		t.Fatalf("JSON report: %v", err)
	}
	var decoded report.CanonicalReport
	if err := json.Unmarshal(rawJSON, &decoded); err != nil || len(decoded.Findings) != len(parsed.Findings) {
		t.Fatalf("JSON report lost findings: %v", err)
	}
	var sarif struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(report.ToSARIF(parsed.Findings), &sarif); err != nil {
		t.Fatalf("SARIF report: %v", err)
	}
	if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) < len(want) {
		t.Fatalf("SARIF dropped Dart findings: %+v", sarif)
	}
	seenSARIF := map[string]bool{}
	for _, r := range sarif.Runs[0].Results {
		seenSARIF[r.RuleID] = true
	}
	for id := range want {
		if !seenSARIF[id] {
			t.Errorf("SARIF missing %s", id)
		}
	}
}
