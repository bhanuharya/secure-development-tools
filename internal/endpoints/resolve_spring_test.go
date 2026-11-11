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
		{"ANY route takes a method matcher", "/api/register", "ANY", ProtPublic, nil, "high", "SecurityConfig.java:10"},
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
}
