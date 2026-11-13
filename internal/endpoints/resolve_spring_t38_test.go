package endpoints

import (
	"strings"
	"testing"
)

func TestSpringIgnoringChainKeepsEachMethod(t *testing.T) {
	b := &springBuild{chains: []*springChain{{file: "Security.java", line: 20, endLine: 30}},
		matchers: []springMatcher{{file: "Security.java", line: 25, name: "anyRequest", pattern: "/**", access: "authenticated"}}}
	for i, raw := range []string{`HttpMethod.OPTIONS"/**"`, `"/app/**/*.{js,html}"`, `"/i18n/**"`, `"/content/**"`, `"/test/**"`, `"/h2-console/**"`} {
		b.ignored = append(b.ignored, springIgnored{file: "Security.java", line: i + 3, name: "antMatchers", raw: raw})
	}
	cfg := b.finish()
	if len(cfg.ignored) != 6 {
		t.Fatalf("ignored = %v, want six independent patterns", cfg.ignored)
	}
	for _, method := range []string{"GET", "POST", "OPTIONS"} {
		want := ProtAuthenticated
		if method == "OPTIONS" {
			want = ProtPublic
		}
		if got, _, _, _ := cfg.decide("/api/orders/{id}", method); got != want {
			t.Errorf("%s API template = %s, want %s", method, got, want)
		}
	}
	if got, _, evidence, _ := cfg.decide("/h2-console/status", "GET"); got != ProtPublic || !strings.Contains(evidence[0], "/h2-console/**") {
		t.Errorf("last ignore = %s %v, want public naming last matcher", got, evidence)
	}
}

func TestSpringNegatedOrKeepsMethods(t *testing.T) {
	for _, raw := range []string{
		`new NegatedServerWebExchangeMatcher(new OrServerWebExchangeMatcher(pathMatchers("/app/**", "/i18n/**", "/content/**", "/swagger-ui/**", "/v3/api-docs", "/test/**"), pathMatchers(HttpMethod.OPTIONS, "/**")))`,
		`new NegatedServerWebExchangeMatcher(new OrServerWebExchangeMatcher(ServerWebExchangeMatchers.pathMatchers("/app/**""/i18n/**")ServerWebExchangeMatchers.pathMatchers(HttpMethod.OPTIONS"/**")))`,
		`new NegatedRequestMatcher(new OrRequestMatcher(new AntPathRequestMatcher("/app/**"), new AntPathRequestMatcher("/i18n/**"), new AntPathRequestMatcher("/**", "OPTIONS")))`,
	} {
		t.Run(raw, func(t *testing.T) {
			cfg := t38ScopeConfig(raw)
			for _, tc := range []struct {
				path, method string
				want         Protection
			}{
				{"/api/orders", "GET", ProtAuthenticated},
				{"/api/orders/{id}", "POST", ProtAuthenticated},
				{"/api/orders", "OPTIONS", ProtPublic},
				{"/api/orders/{id}", "OPTIONS", ProtPublic},
				{"/app/index", "GET", ProtPublic},
				{"/i18n/messages", "POST", ProtPublic},
			} {
				if got, _, _, _ := cfg.decide(tc.path, tc.method); got != tc.want {
					t.Errorf("%s %s = %s, want %s", tc.method, tc.path, got, tc.want)
				}
			}
		})
	}
}

func t38ScopeConfig(raw string) *springConfig {
	b := &springBuild{chains: []*springChain{{file: "Security.java", line: 3, endLine: 9, http: "http"}},
		scopes:   []springScopeCall{{file: "Security.java", line: 4, owner: "http", name: "securityMatcher", args: raw}},
		matchers: []springMatcher{{file: "Security.java", line: 7, name: "anyRequest", pattern: "/**", access: "authenticated"}}}
	return b.finish()
}

func TestSpringUnknownConstructBounds(t *testing.T) {
	for _, kind := range []string{"ignore", "scope", "orphan scope", "orphan matcher", "matcher"} {
		t.Run(kind, func(t *testing.T) {
			cfg := t38UnknownConfig(kind, `new CustomMatcher(HttpMethod.OPTIONS, "/legacy/export")`)
			for _, tc := range []struct {
				path, method string
				want         Protection
			}{
				{"/api/orders", "OPTIONS", ProtAuthenticated},
				{"/api/orders/{id}", "OPTIONS", ProtAuthenticated},
				{"/legacy/export", "GET", ProtAuthenticated},
				{"/legacy/{operation}", "GET", ProtAuthenticated},
				{"/legacy/export", "OPTIONS", ProtUnknown},
				{"/legacy/{operation}", "OPTIONS", ProtUnknown},
			} {
				got, _, _, _, note := cfg.decideWithNote(tc.path, tc.method)
				if got != tc.want {
					t.Errorf("%s %s = %s, want %s", tc.method, tc.path, got, tc.want)
				}
				wantNote := "CustomMatcher"
				if kind == "orphan scope" {
					wantNote = "requestMatcher"
				}
				if got == ProtUnknown && !strings.Contains(note, wantNote) {
					t.Errorf("unknown note = %q, want %s", note, wantNote)
				}
			}
			cfg = t38UnknownConfig(kind, "this::customMethod")
			if got, _, _, _ := cfg.decide("/api/orders/{id}", "GET"); got != ProtUnknown {
				t.Errorf("no visible paths = %s, want unknown", got)
			}
		})
	}
}

func t38UnknownConfig(kind, raw string) *springConfig {
	b := &springBuild{chains: []*springChain{{file: "Security.java", line: 10, endLine: 30, http: "http"}},
		matchers: []springMatcher{{file: "Security.java", line: 25, name: "anyRequest", pattern: "/**", access: "authenticated"}}}
	switch kind {
	case "ignore":
		b.ignored = []springIgnored{{file: "Security.java", line: 3, name: "requestMatchers", raw: raw}}
	case "scope", "orphan scope":
		line := 12
		if kind == "orphan scope" {
			line = 3
		}
		b.scopes = []springScopeCall{{file: "Security.java", line: line, name: "requestMatcher", owner: "http", args: raw}}
	case "orphan matcher", "matcher":
		line := 12
		if kind == "orphan matcher" {
			line = 3
		}
		b.matchers = append([]springMatcher{{file: "Security.java", line: line, name: "requestMatchers", pattern: raw, raw: raw, access: "permitAll"}}, b.matchers...)
	}
	return b.finish()
}
