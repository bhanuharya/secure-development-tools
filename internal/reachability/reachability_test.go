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
	write(t, root, "go.mod", "module example.com/demo\n\ngo 1.24\n\nrequire (\n\tgithub.com/sirupsen/logrus v1.9.0\n\tgithub.com/unused/dep v1.0.0\n)\n")
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
	write(t, root, "go.mod", "module example.com/demo\n\nrequire gopkg.in/yaml.v2 v2.4.0\n")
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
	write(t, root, "pyproject.toml", "[project]\ndependencies = [\n  \"flask>=2\",\n  \"Django_Extra==4.2\",\n]\n")
	fs := []*finding.Finding{
		depFinding("django-extra", "requirements.txt"), // declared direct, never imported
		depFinding("urllib3", "requirements.txt"),      // pinned only: may be transitive
		depFinding("django", "requirements.txt"),       // a prefix of a declared name is not a declaration
	}
	Annotate(root, fs)
	for i, want := range []string{Unreachable, Unknown, Unknown} {
		if fs[i].Reachability.State != want {
			t.Fatalf("finding %d: want %s, got %+v", i, want, fs[i].Reachability)
		}
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

// An indirect module is used through another module, so a missing import
// proves nothing: it must not be called unreachable.
func TestGoIndirectAndUnlistedAreUnknown(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module example.com/demo\n\nrequire (\n\tgithub.com/direct/unused v1.0.0\n\tgolang.org/x/net v0.1.0 // indirect\n)\n\nreplace (\n\tgithub.com/replaced/only v1.0.0 => ../local\n)\n")
	write(t, root, "main.go", "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println() }\n")
	fs := []*finding.Finding{
		depFinding("github.com/direct/unused", "go.mod"),
		depFinding("golang.org/x/net", "go.mod"),
		depFinding("github.com/replaced/only", "go.mod"),
	}
	Annotate(root, fs)
	for i, want := range []string{Unreachable, Unknown, Unknown} {
		if fs[i].Reachability.State != want {
			t.Fatalf("finding %d: want %s, got %+v", i, want, fs[i].Reachability)
		}
	}
}

// npm lock file with: express (imported) -> qs; jest (dev tool, not imported)
// -> minimatch; lodash direct and unused; a nested copy of qs under jest.
const npmLock = `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"express": "^4", "lodash": "^4"}, "devDependencies": {"jest": "^29"}},
    "node_modules/express": {"dependencies": {"qs": "^6", "body-parser": "^1"}},
    "node_modules/body-parser": {"dependencies": {"raw-body": "^2"}},
    "node_modules/raw-body": {},
    "node_modules/qs": {},
    "node_modules/lodash": {},
    "node_modules/jest": {"dependencies": {"minimatch": "^3", "@jest/core": "^29"}},
    "node_modules/@jest/core": {"dependencies": {"micromatch": "^4"}},
    "node_modules/jest/node_modules/micromatch": {},
    "node_modules/minimatch": {}
  }
}`

func TestJSTransitiveFollowsLockGraph(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package-lock.json", npmLock)
	write(t, root, "src/index.ts", "import express from 'express';\n")
	cases := []struct{ pkg, want string }{
		{"express", Reachable},
		{"qs", Reachable},       // through express
		{"raw-body", Reachable}, // two levels below express
		{"lodash", Unreachable}, // direct, never imported
		{"jest", Unreachable},
		{"minimatch", Unreachable}, // only under jest, which nothing imports
		{"micromatch", Unknown},    // @jest/core cannot resolve it: not in the graph
		{"left-pad", Unknown},      // not in the lock file at all
	}
	var fs []*finding.Finding
	for _, c := range cases {
		fs = append(fs, depFinding(c.pkg, "package-lock.json"))
	}
	Annotate(root, fs)
	for i, c := range cases {
		if fs[i].Reachability.State != c.want {
			t.Fatalf("%s: want %s, got %+v", c.pkg, c.want, fs[i].Reachability)
		}
	}
	if r := fs[1].Reachability; r.Evidence != "src/index.ts" || r.Reason != "transitive dependency of imported package express" {
		t.Fatalf("transitive finding must name the imported parent: %+v", r)
	}
}

// Without a dependency graph a missing import cannot rule a package out.
func TestJSLockWithoutGraphIsUnknown(t *testing.T) {
	root := t.TempDir()
	// A version 1 lock file without its package.json has no first-party dependency list.
	write(t, root, "package-lock.json", `{"lockfileVersion": 1, "dependencies": {"qs": {"version": "6.0.0"}}}`)
	write(t, root, "yarn.lock", "qs@^6:\n  version \"6.0.0\"\n")
	write(t, root, "index.js", "import express from 'express';\n")
	fs := []*finding.Finding{depFinding("qs", "package-lock.json"), depFinding("qs", "yarn.lock")}
	Annotate(root, fs)
	for i := range fs {
		if fs[i].Reachability.State != Unknown {
			t.Fatalf("finding %d must be unknown, got %+v", i, fs[i].Reachability)
		}
	}
}

// Workspace packages are first-party: their dependencies count as direct, and
// a lock file in a subdirectory is read from there.
func TestJSWorkspaceDependenciesAreDirect(t *testing.T) {
	root := t.TempDir()
	write(t, root, "web/package-lock.json", `{"lockfileVersion": 3, "packages": {
	  "": {"workspaces": ["packages/*"]},
	  "node_modules/@app/ui": {"link": true, "resolved": "packages/ui"},
	  "packages/ui": {"dependencies": {"react": "^18", "moment": "^2"}},
	  "node_modules/react": {"dependencies": {"scheduler": "^0.23"}},
	  "node_modules/scheduler": {},
	  "node_modules/moment": {}
	}}`)
	write(t, root, "web/packages/ui/index.tsx", "import React from 'react';\n")
	fs := []*finding.Finding{depFinding("scheduler", "web/package-lock.json"), depFinding("moment", "web/package-lock.json")}
	Annotate(root, fs)
	if fs[0].Reachability.State != Reachable || fs[1].Reachability.State != Unreachable {
		t.Fatalf("got %+v and %+v", fs[0].Reachability, fs[1].Reachability)
	}
}

// A framework is started from a script and its modules are named in
// configuration; neither is imported. Their dependencies still run.
func TestJSFrameworkRunByScriptOrNamedInConfigIsReachable(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"scripts": {"dev": "nuxt dev", "lint": "eslint ."}}`)
	write(t, root, "package-lock.json", `{"lockfileVersion": 3, "packages": {
	  "": {"dependencies": {"nuxt": "^3", "@nuxtjs/i18n": "^8", "dayjs": "^1", "left-over": "^1"}, "devDependencies": {"eslint": "^9"}},
	  "node_modules/nuxt": {"bin": {"nuxi": "bin/nuxt.mjs", "nuxt": "bin/nuxt.mjs"}, "dependencies": {"seroval": "^1"}},
	  "node_modules/seroval": {},
	  "node_modules/@nuxtjs/i18n": {"dependencies": {"vue-i18n": "^9"}},
	  "node_modules/vue-i18n": {},
	  "node_modules/dayjs": {},
	  "node_modules/eslint": {"bin": {"eslint": "bin/eslint.js"}, "dependencies": {"minimatch": "^3"}},
	  "node_modules/minimatch": {},
	  "node_modules/left-over": {"dependencies": {"left-pad": "^1"}},
	  "node_modules/left-pad": {}
	}}`)
	write(t, root, "nuxt.config.ts", "export default defineNuxtConfig({ modules: ['@nuxtjs/i18n'] })\n")
	write(t, root, "app/pages/index.vue", "<script setup lang=\"ts\">\nimport dayjs from 'dayjs'\n</script>\n")
	cases := []struct{ pkg, want string }{
		{"nuxt", Reachable},         // run by the dev script
		{"seroval", Reachable},      // below nuxt
		{"@nuxtjs/i18n", Reachable}, // named in nuxt.config.ts
		{"vue-i18n", Reachable},
		{"dayjs", Reachable},     // imported in a .vue file
		{"minimatch", Reachable}, // below eslint, run by the lint script
		{"left-over", Unreachable},
		{"left-pad", Unreachable},
	}
	var fs []*finding.Finding
	for _, c := range cases {
		fs = append(fs, depFinding(c.pkg, "package-lock.json"))
	}
	Annotate(root, fs)
	for i, c := range cases {
		if fs[i].Reachability.State != c.want {
			t.Fatalf("%s: want %s, got %+v", c.pkg, c.want, fs[i].Reachability)
		}
	}
}

// lockfileVersion 1 nests packages and keeps the direct dependencies in package.json.
func TestJSLockVersion1FollowsRequires(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"name": "app", "bin": "cli.js", "dependencies": {"express": "^4", "lodash": "^4"}, "devDependencies": {"jest": "^26"}}`)
	write(t, root, "package-lock.json", `{"lockfileVersion": 1, "dependencies": {
	  "express": {"version": "4.0.0", "requires": {"qs": "^6"}},
	  "qs": {"version": "6.0.0"},
	  "lodash": {"version": "4.0.0"},
	  "jest": {"version": "26.0.0", "requires": {"micromatch": "^4"}, "dependencies": {"micromatch": {"version": "4.0.0", "requires": {"braces": "^3"}}}},
	  "braces": {"version": "3.0.0"}
	}}`)
	write(t, root, "index.js", "const express = require('express')\n")
	cases := []struct{ pkg, want string }{
		{"qs", Reachable}, {"lodash", Unreachable}, {"micromatch", Unreachable}, {"braces", Unreachable},
	}
	var fs []*finding.Finding
	for _, c := range cases {
		fs = append(fs, depFinding(c.pkg, "package-lock.json"))
	}
	Annotate(root, fs)
	for i, c := range cases {
		if fs[i].Reachability.State != c.want {
			t.Fatalf("%s: want %s, got %+v", c.pkg, c.want, fs[i].Reachability)
		}
	}
}
