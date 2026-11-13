package endpoints

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSpringBasePathShapes(t *testing.T) {
	cases := []struct {
		name      string
		files     map[string]string
		mvc, flux string
		note      string // substring expected in a note ("" = no note)
	}{
		{"yaml nested", map[string]string{"src/main/resources/application.yml": "server:\n  servlet:\n    context-path: /orders\n"}, "/orders", "", ""},
		{"yaml dotted", map[string]string{"src/main/resources/application.yaml": "server.servlet.context-path: /orders/\n"}, "/orders", "", ""},
		{"boot 1 properties", map[string]string{"src/main/resources/application.properties": "server.context-path=/legacy\n"}, "/legacy", "", ""},
		{"servlet path joins", map[string]string{"src/main/resources/application.properties": "server.servlet.context-path=/ctx\nspring.mvc.servlet.path=/mvc\n"}, "/ctx/mvc", "", ""},
		{"placeholder default", map[string]string{"src/main/resources/application.yml": "server:\n  servlet:\n    context-path: ${CONTEXT_PATH:/api}\n"}, "/api", "", ""},
		{"placeholder without default", map[string]string{"src/main/resources/application.yml": "server:\n  servlet:\n    context-path: ${CONTEXT_PATH}\n"}, "", "", "served paths are not shown"},
		{"root is no prefix", map[string]string{"src/main/resources/application.yml": "server:\n  servlet:\n    context-path: /\n"}, "", "", ""},
		{"webflux base path", map[string]string{"src/main/resources/application.yml": "spring:\n  webflux:\n    base-path: /gw\n"}, "", "/gw", ""},
		{"profile document skipped", map[string]string{"src/main/resources/application.yml": "server:\n  servlet:\n    context-path: /base\n---\nspring:\n  config:\n    activate:\n      on-profile: prod\nserver:\n  servlet:\n    context-path: /prod\n"}, "/base", "", ""},
		{"profile file differs", map[string]string{"src/main/resources/application.yml": "server:\n  servlet:\n    context-path: /base\n",
			"src/main/resources/application-prod.yml": "server:\n  servlet:\n    context-path: /prod\n"}, "/base", "", `profile "prod" serves the routes under "/prod"`},
		{"test resources ignored", map[string]string{"src/test/resources/application.yml": "server:\n  servlet:\n    context-path: /test\n"}, "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := readSpringBase(writeFiles(t, c.files), ".")
			if got.mvc != c.mvc || got.webflux != c.flux {
				t.Fatalf("mvc %q webflux %q, want %q %q (notes %v)", got.mvc, got.webflux, c.mvc, c.flux, got.notes)
			}
			joined := strings.Join(got.notes, "\n")
			if c.note == "" && joined != "" || c.note != "" && !strings.Contains(joined, c.note) {
				t.Fatalf("notes %q, want %q", joined, c.note)
			}
		})
	}
}

func TestApplyBasePathsOnlyTouchesSpringRoutes(t *testing.T) {
	root := writeFiles(t, map[string]string{"svc/src/main/resources/application.yml": "server:\n  servlet:\n    context-path: /orders\n"})
	routes := []Route{
		{Service: "svc", Framework: "spring-mvc", Method: "GET", Path: "/api/items"},
		{Service: "svc", Framework: "gin", Method: "GET", Path: "/api/items"},
		{Service: "other", Framework: "spring-mvc", Method: "GET", Path: "/x"},
	}
	got, _ := applyBasePaths(root, routes)
	if got[0].ExternalPath != "/orders/api/items" || got[0].Path != "/api/items" {
		t.Fatalf("spring route = %+v", got[0])
	}
	if got[1].ExternalPath != "" || got[2].ExternalPath != "" {
		t.Fatalf("non-spring or unconfigured routes changed: %+v %+v", got[1], got[2])
	}
	if got[0].shownPath() != "/orders/api/items" || got[1].shownPath() != "/api/items" {
		t.Fatal("shownPath")
	}
}
