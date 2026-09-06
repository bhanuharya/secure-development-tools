package reachability

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func write(t *testing.T, root, name, content string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func depFinding(pkg, target string) *finding.Finding {
	return &finding.Finding{
		ID: "x", Category: finding.CatDepVuln, Rule: finding.Rule{ID: "CVE-1"},
		Severity: finding.Severity{Canonical: "critical"},
		Artifact: &finding.Artifact{Package: pkg, InstalledVersion: "1.0", Target: target},
	}
}

func TestGoReachableAndUnreachable(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module example.com/demo\n\ngo 1.24\n")
	write(t, root, "main.go", "package main\n\nimport (\n\t\"fmt\"\n\t\"github.com/sirupsen/logrus\"\n)\n\nfunc main() { fmt.Println(logrus.InfoLevel) }\n")
	fs := []*finding.Finding{
		depFinding("github.com/sirupsen/logrus", "go.mod"),
		depFinding("github.com/unused/dep", "go.mod"),
	}
	Annotate(root, fs)
	if fs[0].Reachability == nil || fs[0].Reachability.State != Reachable {
		t.Fatalf("logrus must be reachable: %+v", fs[0].Reachability)
	}
	if fs[0].Reachability.Evidence != "main.go" {
		t.Fatalf("evidence must name the importer, got %q", fs[0].Reachability.Evidence)
	}
	if fs[1].Reachability == nil || fs[1].Reachability.State != Unreachable {
		t.Fatalf("unused dep must be unreachable: %+v", fs[1].Reachability)
	}
}

func TestGoVersionSuffixAndBlankImport(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.go", "package a\n\nimport (\n\t_ \"github.com/lib/pq\"\n\t\"gopkg.in/yaml.v3\"\n)\n")
	fs := []*finding.Finding{
		depFinding("github.com/lib/pq", "go.mod"),
		depFinding("gopkg.in/yaml.v2", "go.mod"), // wrong major: must NOT match v3 import
	}
	Annotate(root, fs)
	if fs[0].Reachability.State != Reachable {
		t.Fatalf("blank import is still reachable: %+v", fs[0].Reachability)
	}
	if fs[1].Reachability.State != Unreachable {
		t.Fatalf("v2 must not match a v3 import: %+v", fs[1].Reachability)
	}
}

func TestPythonReachableAliasAndDynamic(t *testing.T) {
	root := t.TempDir()
	write(t, root, "app.py", "import flask\nimport numpy as np\nfrom requests import get\n")
	write(t, root, "dyn.py", "mod = __import__(name)\n")
	fs := []*finding.Finding{
		depFinding("flask", "requirements.txt"),
		depFinding("numpy", "requirements.txt"),
		depFinding("requests", "requirements.txt"),
		depFinding("PyYAML", "requirements.txt"),
	}
	Annotate(root, fs)
	for i, want := range []string{Reachable, Reachable, Reachable} {
		if fs[i].Reachability.State != want {
			t.Fatalf("finding %d: got %v", i, fs[i].Reachability)
		}
	}
	// Dynamic constructs exist in-repo: absence can no longer be proven.
	if fs[3].Reachability.State != Unknown {
		t.Fatalf("pyyaml must be unknown with dynamic imports around, got %+v", fs[3].Reachability)
	}
}

func TestPythonUnreachableWithoutDynamic(t *testing.T) {
	root := t.TempDir()
	write(t, root, "app.py", "import flask\n")
	fs := []*finding.Finding{depFinding("django", "requirements.txt")}
	Annotate(root, fs)
	if fs[0].Reachability.State != Unreachable {
		t.Fatalf("got %+v", fs[0].Reachability)
	}
}

func TestJSReachableScopedAndDynamic(t *testing.T) {
	root := t.TempDir()
	write(t, root, "index.js", "import express from 'express';\nconst _ = require('lodash');\nimport x from '@scope/pkg/sub';\n")
	write(t, root, "lazy.js", "const m = await import(name);\n")
	fs := []*finding.Finding{
		depFinding("express", "package-lock.json"),
		depFinding("lodash", "package-lock.json"),
		depFinding("@scope/pkg", "package-lock.json"),
		depFinding("leftpad", "package-lock.json"),
	}
	Annotate(root, fs)
	for i := 0; i < 3; i++ {
		if fs[i].Reachability.State != Reachable {
			t.Fatalf("finding %d: got %+v", i, fs[i].Reachability)
		}
	}
	if fs[3].Reachability.State != Unknown {
		t.Fatalf("leftpad must be unknown with dynamic import() around, got %+v", fs[3].Reachability)
	}
}

// A package imported only via a literal dynamic import is genuinely
// reachable: absence must not be claimed.
func TestJSLiteralDynamicImportIsReachable(t *testing.T) {
	root := t.TempDir()
	write(t, root, "index.js", "const m = await import('leftpad');\n")
	fs := []*finding.Finding{depFinding("leftpad", "package-lock.json")}
	Annotate(root, fs)
	if fs[0].Reachability.State != Reachable {
		t.Fatalf("literal dynamic import must be reachable, got %+v", fs[0].Reachability)
	}
}

// A re-export (`export ... from`) reaches the dependency just like an import.
func TestJSReExportIsReachable(t *testing.T) {
	root := t.TempDir()
	write(t, root, "index.js", "export { noop } from 'leftpad';\nexport * from 'star';\n")
	fs := []*finding.Finding{depFinding("leftpad", "package-lock.json"), depFinding("star", "package-lock.json")}
	Annotate(root, fs)
	for i, name := range []string{"leftpad", "star"} {
		if fs[i].Reachability.State != Reachable {
			t.Fatalf("%s re-export must be reachable, got %+v", name, fs[i].Reachability)
		}
	}
}

func TestNonDepFindingsUntouched(t *testing.T) {
	root := t.TempDir()
	f := &finding.Finding{ID: "s", Category: finding.CatSAST}
	Annotate(root, []*finding.Finding{f})
	if f.Reachability != nil {
		t.Fatal("non-dependency findings must stay unannotated")
	}
}

func TestUnknownEcosystem(t *testing.T) {
	root := t.TempDir()
	f := depFinding("log4j", "pom.xml")
	Annotate(root, []*finding.Finding{f})
	if f.Reachability.State != Unknown {
		t.Fatalf("jvm must be unknown (unsupported), got %+v", f.Reachability)
	}
}
