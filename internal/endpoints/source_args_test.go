package endpoints

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Route arguments are read from the source at the fact's position. The
// receiver may itself be a call, and the handler list may have any length.
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
