package endpoints

import (
	"reflect"
	"strings"
	"testing"
)

func TestSpringConfigDecide(t *testing.T) {
	cfg := &springConfig{matchers: []springMatcher{
		{file: "SecurityConfig.java", line: 10, name: "antMatchers", pattern: "/api/register", method: "POST", access: "permitAll"},
		{file: "SecurityConfig.java", line: 11, name: "antMatchers", pattern: "/api/**", access: "authenticated"},
	}}
	tests := []struct {
		name         string
		path         string
		method       string
		wantProt     Protection
		wantRoles    []string
		wantConf     string
		wantEvidence string // prefix, or the exact fallback sentence
	}{
		{"first matcher wins", "/api/register", "POST", ProtPublic, nil, "high", "SecurityConfig.java:10"},
		{"method mismatch falls through", "/api/register", "GET", ProtAuthenticated, nil, "high", "SecurityConfig.java:11"},
		{"any method on a method-less matcher", "/api/orders", "DELETE", ProtAuthenticated, nil, "high", "SecurityConfig.java:11"},
		{"ANY route uses the weakest method", "/api/register", "ANY", ProtPublic, nil, "high", "SecurityConfig.java:10"},
		{"no matcher and no default", "/legacy/report", "GET", ProtPublic, nil, "low", "no matcher; Spring permits"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protection, roles, evidence, confidence := cfg.decide(tt.path, tt.method)
			if protection != tt.wantProt {
				t.Errorf("protection = %q, want %q", protection, tt.wantProt)
			}
			if !reflect.DeepEqual(roles, tt.wantRoles) {
				t.Errorf("roles = %v, want %v", roles, tt.wantRoles)
			}
			if confidence != tt.wantConf {
				t.Errorf("confidence = %q, want %q", confidence, tt.wantConf)
			}
			if len(evidence) != 1 || !strings.HasPrefix(evidence[0], tt.wantEvidence) {
				t.Errorf("evidence = %v, want one entry starting %q", evidence, tt.wantEvidence)
			}
		})
	}
}

func TestSpringMatcherDecision(t *testing.T) {
	tests := []struct {
		name      string
		m         springMatcher
		wantProt  Protection
		wantRoles []string
		wantConf  string
	}{
		{"permitAll", springMatcher{access: "permitAll"}, ProtPublic, nil, "high"},
		{"authenticated", springMatcher{access: "authenticated"}, ProtAuthenticated, nil, "high"},
		{"fullyAuthenticated", springMatcher{access: "fullyAuthenticated"}, ProtAuthenticated, nil, "high"},
		{"denyAll", springMatcher{access: "denyAll"}, ProtDenied, nil, "high"},
		{"hasAuthority", springMatcher{access: "hasAuthority", args: `"admin:write"`}, ProtRole, []string{"admin:write"}, "high"},
		{"hasAnyRole", springMatcher{access: "hasAnyRole", args: `'ADMIN', 'SUPPORT'`}, ProtRole, []string{"ADMIN", "SUPPORT"}, "high"},
		{"access role", springMatcher{access: "access", args: `"hasRole('ADMIN')"`}, ProtRole, []string{"ADMIN"}, "high"},
		{"access authenticated", springMatcher{access: "access", args: `"isAuthenticated()"`}, ProtAuthenticated, nil, "high"},
		{"access unknown SpEL", springMatcher{access: "access", args: `"#oauth2.hasScope('read')"`}, ProtAuthenticated, nil, "medium"},
		{"role without a literal", springMatcher{access: "hasRole", args: "ADMIN_ROLE"}, ProtAuthenticated, nil, "medium"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protection, roles, confidence := tt.m.decision()
			if protection != tt.wantProt {
				t.Errorf("protection = %q, want %q", protection, tt.wantProt)
			}
			if !reflect.DeepEqual(roles, tt.wantRoles) {
				t.Errorf("roles = %v, want %v", roles, tt.wantRoles)
			}
			if confidence != tt.wantConf {
				t.Errorf("confidence = %q, want %q", confidence, tt.wantConf)
			}
		})
	}
}

func TestSpringConfigsKeepSourceOrder(t *testing.T) {
	facts := []Fact{
		{Kind: "security_matcher", File: "SecurityConfig.java", Line: 7, Column: 43, Metavars: map[string]string{
			"$MATCHER": "antMatchers", "$PATTERN": "/second", "$ACCESS": "permitAll", "$...ARGS": "",
		}},
		{Kind: "security_matcher", File: "SecurityConfig.java", Line: 7, Column: 21, Metavars: map[string]string{
			"$MATCHER": "antMatchers", "$PATTERN": "/first", "$ACCESS": "authenticated", "$...ARGS": "",
		}},
		{Kind: "security_default", File: "SecurityConfig.java", Line: 8, Metavars: map[string]string{
			"$DEFAULT": "anyExchange", "$ACCESS": "authenticated", "$...ARGS": "",
		}},
	}
	cfg := springConfigs(facts, t.TempDir())["."]
	if cfg == nil {
		t.Fatal("no configuration collected")
	}
	if !cfg.webflux {
		t.Error("anyExchange should mark the service as WebFlux")
	}
	got := []string{cfg.matchers[0].pattern, cfg.matchers[1].pattern, cfg.matchers[2].name}
	want := []string{"/first", "/second", "anyExchange"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("matcher order = %v, want %v", got, want)
	}
	t.Run("ANY route uses the weakest method", testSpringAnyRouteUsesWeakestMethod)
}

// testSpringAnyRouteUsesWeakestMethod pins review finding 2: a GET-only
// authentication matcher must not make an unrestricted @RequestMapping
// authenticated when every other method falls through to permitAll.
func testSpringAnyRouteUsesWeakestMethod(t *testing.T) {
	cfg := &springConfig{matchers: []springMatcher{
		{file: "SecurityConfig.java", line: 10, name: "antMatchers", pattern: "/internal/change", method: "GET", access: "authenticated"},
		{file: "SecurityConfig.java", line: 11, name: "anyRequest", pattern: "/**", access: "permitAll"},
	}}
	protection, _, evidence, confidence := cfg.decide("/internal/change", "ANY")
	if protection != ProtPublic || confidence != "high" {
		t.Fatalf("decide = %q/%q, want public/high", protection, confidence)
	}
	if len(evidence) != 1 || !strings.Contains(evidence[0], "SecurityConfig.java:11") ||
		!strings.Contains(evidence[0], "weakest method POST") {
		t.Errorf("evidence = %v, want the permitAll matcher naming POST", evidence)
	}
}

// TestSpringChainsDecideByOrder pins review finding 1: a scoped chain must not
// protect paths outside its securityMatcher, and an undecidable chain order is
// unknown rather than a guess.
func TestSpringChainsDecideByOrder(t *testing.T) {
	facts := []Fact{
		{Kind: "security_chain", File: "Security.java", Line: 3, EndLine: 6, Metavars: map[string]string{"$HTTP": "http"}},
		{Kind: "security_order", File: "Security.java", Line: 3, Metavars: map[string]string{"$ORDER": "1"}},
		{Kind: "security_scope", File: "Security.java", Line: 4, Metavars: map[string]string{"$OWNER": "http", "$SCOPE": "securityMatcher", "$PATTERN": "/api/**"}},
		{Kind: "security_default", File: "Security.java", Line: 5, Metavars: map[string]string{"$DEFAULT": "anyRequest", "$ACCESS": "authenticated"}},
		{Kind: "security_chain", File: "Security.java", Line: 7, EndLine: 10, Metavars: map[string]string{"$HTTP": "http"}},
		{Kind: "security_order", File: "Security.java", Line: 7, Metavars: map[string]string{"$ORDER": "2"}},
		{Kind: "security_default", File: "Security.java", Line: 9, Metavars: map[string]string{"$DEFAULT": "anyRequest", "$ACCESS": "permitAll"}},
	}
	cfg := springConfigs(facts, t.TempDir())["."]
	if got, _, _, _ := cfg.decide("/transfer", "POST"); got != ProtPublic {
		t.Errorf("/transfer = %q, want public (outside the /api/** chain)", got)
	}
	if got, _, _, _ := cfg.decide("/api/orders", "POST"); got != ProtAuthenticated {
		t.Errorf("/api/orders = %q, want authenticated", got)
	}

	unordered := []Fact{
		{Kind: "security_chain", File: "Security.java", Line: 3, EndLine: 6, Metavars: map[string]string{"$HTTP": "http"}},
		{Kind: "security_default", File: "Security.java", Line: 5, Metavars: map[string]string{"$DEFAULT": "anyRequest", "$ACCESS": "authenticated"}},
		{Kind: "security_chain", File: "Security.java", Line: 7, EndLine: 10, Metavars: map[string]string{"$HTTP": "http"}},
		{Kind: "security_default", File: "Security.java", Line: 9, Metavars: map[string]string{"$DEFAULT": "anyRequest", "$ACCESS": "permitAll"}},
	}
	cfg = springConfigs(unordered, t.TempDir())["."]
	if got, _, _, _ := cfg.decide("/transfer", "POST"); got != ProtUnknown {
		t.Errorf("/transfer with unordered chains = %q, want unknown", got)
	}
}

// TestSpringChainWithoutRulesDoesNotCompete pins T29 point 1: a JWT-style
// configurer has a configure(HttpSecurity) method but no authorization rule,
// so it must not turn every route of the main chain into unknown.
func TestSpringChainWithoutRulesDoesNotCompete(t *testing.T) {
	facts := []Fact{
		{Kind: "security_chain", File: "JWTConfigurer.java", Line: 3, EndLine: 6, Metavars: map[string]string{"$HTTP": "http"}},
		{Kind: "security_chain", File: "SecurityConfig.java", Line: 10, EndLine: 16, Metavars: map[string]string{"$HTTP": "http"}},
		{Kind: "security_default", File: "SecurityConfig.java", Line: 14, Metavars: map[string]string{"$DEFAULT": "anyRequest", "$ACCESS": "authenticated"}},
	}
	cfg := springConfigs(facts, t.TempDir())["."]
	protection, _, evidence, confidence := cfg.decide("/api/orders", "POST")
	if protection != ProtAuthenticated || confidence != "high" {
		t.Fatalf("decide = %q/%q, want authenticated/high", protection, confidence)
	}
	if len(evidence) != 1 || !strings.Contains(evidence[0], "SecurityConfig.java:14") {
		t.Errorf("evidence = %v, want the main chain's anyRequest rule", evidence)
	}
}

// TestSpringSpelComposition pins review finding 3: boolean alternatives that
// admit anonymous requests make the route public; an unreadable alternative is
// unknown, while a lone unreadable term keeps the historical medium answer.
func TestSpringSpelComposition(t *testing.T) {
	tests := []struct {
		expr      string
		wantProt  Protection
		wantRoles []string
		wantConf  string
	}{
		{"hasRole('ADMIN') or permitAll()", ProtPublic, nil, "high"},
		{"hasRole('ADMIN') or isAnonymous()", ProtPublic, nil, "high"},
		{"hasRole('ADMIN') and isAuthenticated()", ProtRole, []string{"ADMIN"}, "high"},
		{"permitAll() and isAuthenticated()", ProtAuthenticated, nil, "high"},
		{"hasRole('ROLE_ADMIN')", ProtRole, []string{"ADMIN"}, "high"},
		{"!isAnonymous()", ProtAuthenticated, nil, "high"},
		{"!(hasRole('ADMIN') or isAnonymous())", ProtAuthenticated, nil, "high"},
		{"denyAll()", ProtDenied, nil, "high"},
		{"!denyAll()", ProtPublic, nil, "high"},
		{"true", ProtPublic, nil, "high"},
		{"false", ProtDenied, nil, "high"},
		{"#oauth2.hasScope('read')", ProtAuthenticated, nil, "medium"},
		{"hasRole('ADMIN') or #oauth2.hasScope('read')", ProtUnknown, nil, "medium"},
		{"permitAll() or #oauth2.hasScope('read')", ProtPublic, nil, "high"},
		{`"hasAnyAuthority(\""+AuthoritiesConstants.ADMIN+"\", \""+AuthoritiesConstants.CS+"\")"`, ProtRole,
			[]string{"AuthoritiesConstants.ADMIN", "AuthoritiesConstants.CS"}, "medium"},
		{`"hasAuthority(\""+AuthoritiesConstants.ADMIN+"\")"`, ProtRole,
			[]string{"AuthoritiesConstants.ADMIN"}, "medium"},
		{"hasRole(ADMIN_ROLE)", ProtRole, []string{"ADMIN_ROLE"}, "medium"},
		{"hasAuthority(getAdminRole())", ProtRole, nil, "medium"},
		{`"hasAnyAuthority(\""+AuthoritiesConstants.ADMIN+"\") or isAnonymous()"`, ProtPublic, nil, "high"},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			protection, roles, confidence := springAccessDecision(tt.expr)
			if protection != tt.wantProt || confidence != tt.wantConf {
				t.Errorf("decision = %q/%q, want %q/%q", protection, confidence, tt.wantProt, tt.wantConf)
			}
			if !reflect.DeepEqual(roles, tt.wantRoles) {
				t.Errorf("roles = %v, want %v", roles, tt.wantRoles)
			}
		})
	}
}

// TestSpringMethodGatesStayWithTheirOverload pins review finding 5: two
// handlers named update share "Class.method", but only the annotated
// declaration keeps its gate.
func TestSpringMethodGatesStayWithTheirOverload(t *testing.T) {
	facts := []Fact{
		{Kind: "method_gate", File: "Controller.java", Line: 3, EndLine: 5, MetavarLines: map[string]int{"$ANNOTATION": 3}, Metavars: map[string]string{
			"$ANNOTATION": "PreAuthorize", "$EXPR": `"isAuthenticated()"`, "$C": "Controller", "$M": "update",
		}},
		{Kind: "route", File: "Controller.java", Line: 3, EndLine: 5, Metavars: map[string]string{
			"$C": "Controller", "$M": "update", "$VERB": "PostMapping", "$PATH": "/private",
		}},
		{Kind: "route", File: "Controller.java", Line: 6, EndLine: 7, Metavars: map[string]string{
			"$C": "Controller", "$M": "update", "$VERB": "PostMapping", "$PATH": "/transfer",
		}},
	}
	cfg := &springConfig{matchers: []springMatcher{
		{file: "Security.java", line: 10, name: "anyRequest", pattern: "/**", access: "permitAll"},
	}}
	routes, _ := resolveSpringFile("Controller.java", facts, cfg, ".")
	got := map[string]Protection{}
	for _, route := range routes {
		got[route.Path] = route.Protection
	}
	want := map[string]Protection{"/private": ProtAuthenticated, "/transfer": ProtPublic}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("protections = %v, want %v", got, want)
	}
}
