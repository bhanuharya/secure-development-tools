package endpoints

import (
	"reflect"
	"testing"
)

func TestSpringMethodRefName(t *testing.T) {
	cases := map[string]string{
		"this::isProtected":                      "isProtected",
		"SecurityConfig::isProtected":            "isProtected",
		"request -> isProtected(request)":        "isProtected",
		"(req) -> this.isProtected(req)":         "isProtected",
		"request -> isProtected(other)":          "",
		"new AntPathRequestMatcher(\"/api/**\")": "",
		"matcher::matches":                       "",
	}
	for raw, want := range cases {
		got, ok := springMethodRefName(raw)
		if got != want || ok != (want != "") {
			t.Errorf("springMethodRefName(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
}

// TestSpringReturnIsUnion: only "any of these matchers matches" is a union of
// patterns; anything that negates or intersects is not.
func TestSpringReturnIsUnion(t *testing.T) {
	cases := map[string]bool{
		"matchers.stream().anyMatch(m -> m.matches(request))":            true,
		"this.matchers.stream().anyMatch(matcher -> matcher.matches(r))": true,
		"matchers.stream().anyMatch(RequestMatcher::matches)":            true,
		"a.matches(request) || b.matches(request)":                       true,
		"!matchers.stream().anyMatch(m -> m.matches(request))":           false,
		"matchers.stream().noneMatch(m -> m.matches(request))":           false,
		"matchers.stream().allMatch(m -> m.matches(request))":            false,
		"a.matches(request) && b.matches(request)":                       false,
		"matchers.stream().anyMatch(m -> other.matches(request))":        false,
		"path.startsWith(\"/api\")":                                      false,
	}
	for expr, want := range cases {
		if got := springReturnIsUnion(expr); got != want {
			t.Errorf("springReturnIsUnion(%q) = %v, want %v", expr, got, want)
		}
	}
}

func TestSpringMethodScopeShapes(t *testing.T) {
	root := writeTree(t, map[string]string{"Security.java": `class Security {
    private static final String[] PUBLIC_DOCS = {"/docs/a", "/docs/b"};
    private boolean fieldList(HttpServletRequest request) {
        List<RequestMatcher> m = new ArrayList<>();
        for (String p : PUBLIC_DOCS) { m.add(new AntPathRequestMatcher(p)); }
        return m.stream().anyMatch(x -> x.matches(request));
    }
    private boolean orChain(HttpServletRequest request) {
        RequestMatcher a = new AntPathRequestMatcher("/a/**");
        RequestMatcher b = new AntPathRequestMatcher("/b/**", "DELETE");
        return a.matches(request) || b.matches(request);
    }
    private boolean twoReturns(HttpServletRequest request) {
        if (request.getRequestURI().startsWith("/x")) return false;
        return new AntPathRequestMatcher("/c/**").matches(request);
    }
    private boolean regex(HttpServletRequest request) {
        return new RegexRequestMatcher("/d/.*", null).matches(request);
    }
    private boolean computed(HttpServletRequest request) {
        return new AntPathRequestMatcher(prefix + "/**").matches(request);
    }
}
`})
	b := &springBuild{root: root}
	scope, ok := b.methodScope("fieldList", "Security.java")
	if !ok || !reflect.DeepEqual(scope.allPatterns(), []string{"/docs/a", "/docs/b"}) {
		t.Errorf("fieldList = %v, %v", scope.allPatterns(), ok)
	}
	scope, ok = b.methodScope("orChain", "Security.java")
	if !ok || len(scope.children) != 2 || scope.children[1].method != "DELETE" {
		t.Errorf("orChain = %+v, %v", scope, ok)
	}
	for _, name := range []string{"twoReturns", "regex", "computed", "missing"} {
		if _, ok := b.methodScope(name, "Security.java"); ok {
			t.Errorf("%s was evaluated; it must stay unknown", name)
		}
	}
}

// TestSpringSentenceSurvivesRedaction: a handler named getToken or
// resetPassword must not turn the rest of its sentence into a redacted value.
func TestSpringSentenceSurvivesRedaction(t *testing.T) {
	sentence := "src/main/java/AaiResource.java:20 AaiResource.getToken - src/main/java/SecurityConfiguration.java:44 requestMatcher(this::isProtectedEndpoint) cannot be evaluated"
	if got := sanitizeStrings([]string{sentence})[0]; got != sentence {
		t.Errorf("sentence changed by redaction:\n got %s\nwant %s", got, sentence)
	}
}
