package endpoints

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestRouteArgsIgnoresComments pins T31: a commented-out middleware call is
// not an argument, and punctuation inside a comment must not close the call.
func TestRouteArgsIgnoresComments(t *testing.T) {
	cases := []struct {
		name string
		file string
		src  string
		line int
		want []string
	}{
		{
			name: "go line comment",
			file: "main.go",
			src:  "package main\nfunc f() {\n\tr.POST(\"/transfer\",\n\t\t// AuthMiddleware(),\n\t\tLogger(),\n\t\thandle)\n}\n",
			line: 3,
			want: []string{"Logger()", "handle"},
		},
		{
			name: "go block comment",
			file: "main.go",
			src:  "package main\nfunc f() {\n\tr.POST(\"/transfer\", /* AuthMiddleware(foo), */ Logger(), handle)\n}\n",
			line: 3,
			want: []string{"Logger()", "handle"},
		},
		{
			name: "js line comment",
			file: "app.js",
			src:  "const app = express();\napp.post('/transfer',\n  // requireAuth,\n  logger,\n  handle);\n",
			line: 2,
			want: []string{"logger", "handle"},
		},
		{
			name: "comment marker in a string",
			file: "main.go",
			src:  "package main\nfunc f() {\n\tr.POST(\"/transfer\", client(\"https://example.com\"), handle)\n}\n",
			line: 3,
			want: []string{`client("https://example.com")`, "handle"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.src), 0o644); err != nil {
				t.Fatal(err)
			}
			got := routeArgs(Fact{Kind: "route", File: tc.file, Line: tc.line, Column: 1}, dir, 1)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("route args = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRouteArgsReadsAnyArityAtTheFactPosition keeps the receiver-call form and
// a handler list of any length working from the fact's position.
func TestRouteArgsReadsAnyArityAtTheFactPosition(t *testing.T) {
	dir := t.TempDir()
	src := "package main\nfunc f() {\n\tr.Group(\"/api\").POST(\"/orders\", a, b, c, d, e, handle)\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	f := Fact{Kind: "route", File: "main.go", Line: 3, Column: 2}
	got := routeArgs(f, dir, 1)
	want := []string{"a", "b", "c", "d", "e", "handle"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("route args = %v, want %v", got, want)
	}
}
