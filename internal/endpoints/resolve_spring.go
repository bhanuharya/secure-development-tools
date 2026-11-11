package endpoints

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// This file resolves Spring MVC controller annotations into routes (SPEC §5,
// Spring bullet). The controller supplies the class prefix, the method mapping
// and @PreAuthorize/@Secured/@RolesAllowed; a route without such a gate takes
// the access of the first matching rule of the service's Spring Security
// configuration.

var (
	springRoleCallRe   = regexp.MustCompile(`(?i)\b(hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\s*\(([^)]*)\)`)
	springRolePrefixRe = regexp.MustCompile(`(?i)^ROLE_`)
	springPathVarRe    = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\s*:[^{}]*\}`)
	springQuotedRe     = regexp.MustCompile(`["']([^"']*)["']`)
)

// springGate is one @PreAuthorize, @Secured or @RolesAllowed annotation.
type springGate struct {
	file       string
	line       int
	annotation string
	expr       string
	class      string
	method     string // empty for a class-level gate
}

// springMatcher is one authorization rule of a security configuration: a
// request matcher (or the anyRequest/anyExchange fallback) and its access.
type springMatcher struct {
	file    string
	line    int
	column  int
	name    string // antMatchers, mvcMatchers, requestMatchers, pathMatchers, anyRequest, anyExchange
	pattern string // path pattern; "/**" for the fallback
	method  string // HTTP method when the matcher names one, else ""
	access  string // permitAll, authenticated, hasRole, ...
	args    string // raw access arguments, e.g. "admin:write"
}

// springConfig holds the authorization rules of one service in source order.
type springConfig struct {
	matchers []springMatcher
	webflux  bool // pathMatchers/anyExchange: label routes spring-webflux
}

// resolveSpring resolves the Java facts. Kotlin is out of scope (SPEC §9);
// Spring WebFlux uses the same controller annotations, and its configuration
// names are what label the service reactive.
func resolveSpring(facts []Fact, root string) ([]Route, []string) {
	byFile := map[string][]Fact{}
	var files []string
	for _, f := range facts {
		if !strings.HasSuffix(f.File, ".java") {
			continue
		}
		if _, seen := byFile[f.File]; !seen {
			files = append(files, f.File)
		}
		byFile[f.File] = append(byFile[f.File], f)
	}
	sort.Strings(files)
	configs := springConfigs(facts, root)

	var routes []Route
	var unresolved []string
	for _, file := range files {
		fileRoutes, fileUnresolved := resolveSpringFile(file, byFile[file], configs[serviceOf(root, file)], root)
		routes = append(routes, fileRoutes...)
		unresolved = append(unresolved, fileUnresolved...)
	}
	return routes, unresolved
}

// resolveSpringFile indexes one controller file by class name and method, then
// turns its route facts into routes.
func resolveSpringFile(file string, facts []Fact, cfg *springConfig, root string) ([]Route, []string) {
	prefixes := map[string]string{}
	classGates := map[string][]springGate{}
	methodGates := map[string][]springGate{}
	var routeFacts []Fact
	for _, f := range facts {
		switch f.Kind {
		case "class_prefix":
			if class := f.Metavars["$C"]; class != "" {
				prefixes[class] = f.Metavars["$P"]
			}
		case "class_gate":
			class := f.Metavars["$C"]
			classGates[class] = append(classGates[class], springGateOf(f))
		case "method_gate":
			key := springMethodKey(f)
			methodGates[key] = append(methodGates[key], springGateOf(f))
		case "route":
			routeFacts = append(routeFacts, f)
		}
	}
	sort.Slice(routeFacts, func(i, j int) bool { return routeFacts[i].Line < routeFacts[j].Line })

	var routes []Route
	var unresolved []string
	for _, f := range routeFacts {
		route, sentence, err := springRoute(f, prefixes[classOf(f)], classGates, methodGates, cfg, root)
		if err != nil {
			unresolved = append(unresolved, fmt.Sprintf("%s:%d %v", file, f.Line, err))
			continue
		}
		routes = append(routes, route)
		if sentence != "" {
			unresolved = append(unresolved, sentence)
		}
	}
	return routes, unresolved
}

func springGateOf(f Fact) springGate {
	return springGate{
		file:       f.File,
		line:       f.Line,
		annotation: f.Metavars["$ANNOTATION"],
		expr:       f.Metavars["$EXPR"],
		class:      f.Metavars["$C"],
		method:     f.Metavars["$M"],
	}
}

func classOf(f Fact) string { return f.Metavars["$C"] }

func springMethodKey(f Fact) string { return classOf(f) + "." + f.Metavars["$M"] }

// springRoute builds one route. The returned sentence is the Unresolved note
// for routes whose protection cannot be decided from this service.
func springRoute(f Fact, prefix string, classGates, methodGates map[string][]springGate, cfg *springConfig, root string) (Route, string, error) {
	class, method := classOf(f), f.Metavars["$M"]
	if class == "" || method == "" {
		return Route{}, "", fmt.Errorf("controller class or handler method could not be resolved")
	}
	handler := class + "." + method
	verb := springVerb(f.Metavars["$VERB"])
	path := joinPaths([]string{prefix}, springPathVarRe.ReplaceAllString(f.Metavars["$PATH"], "{$1}"))
	protection, roles, evidence, confidence := springProtection(f, class, method, verb, path, classGates, methodGates, cfg)
	sentence := ""
	if protection == ProtUnknown && cfg == nil {
		sentence = fmt.Sprintf("%s:%d %s: no security configuration in the service; protection unknown", f.File, f.Line, handler)
	}
	return Route{
		Service:    serviceOf(root, f.File),
		Framework:  springFramework(cfg),
		Method:     verb,
		Path:       path,
		Handler:    handler,
		File:       f.File,
		Line:       f.Line,
		Protection: protection,
		Roles:      roles,
		Evidence:   evidence,
		Confidence: confidence,
	}, sentence, nil
}

// springProtection prefers the method's own gate; a method gate overrides the
// class gate (Spring Security applies the most specific annotation). Only a
// route without any gate is handed to the security configuration.
func springProtection(f Fact, class, method, verb, path string, classGates, methodGates map[string][]springGate, cfg *springConfig) (Protection, []string, []string, string) {
	gates := methodGates[class+"."+method]
	classLevel := false
	if len(gates) == 0 {
		gates = classGates[class]
		classLevel = len(gates) > 0
	}
	if len(gates) > 0 {
		return springGateDecision(gates, classLevel)
	}
	if cfg != nil {
		return cfg.decide(path, verb)
	}
	evidence := fmt.Sprintf("%s:%d no security configuration in the service", f.File, f.Line)
	return ProtUnknown, nil, []string{evidence}, "low"
}

// springGateDecision merges the (rare) multiple gates of one method. A denied
// gate wins, then a role gate, then plain authentication.
func springGateDecision(gates []springGate, classLevel bool) (Protection, []string, []string, string) {
	var evidence, roles []string
	authenticated, denied := false, false
	confidence := "high"
	for _, g := range gates {
		protection, gateRoles, known := springGateOutcome(g)
		if !known {
			confidence = "medium"
		}
		evidence = append(evidence, springGateEvidence(g, classLevel, gateRoles))
		switch protection {
		case ProtDenied:
			denied = true
		case ProtRole:
			roles = append(roles, gateRoles...)
		case ProtAuthenticated:
			authenticated = true
		}
	}
	switch {
	case denied:
		return ProtDenied, nil, evidence, confidence
	case len(roles) > 0:
		return ProtRole, dedupe(roles), evidence, confidence
	case authenticated:
		return ProtAuthenticated, nil, evidence, confidence
	default:
		return ProtPublic, nil, evidence, confidence // only @PreAuthorize("permitAll()")
	}
}

// springGateOutcome reads one annotation. An expression we cannot interpret
// still means "protected", so it degrades to authenticated with medium
// confidence instead of guessing public.
func springGateOutcome(g springGate) (Protection, []string, bool) {
	roles := springRoles(g.annotation, g.expr)
	if len(roles) > 0 {
		return ProtRole, roles, true
	}
	if g.annotation != "PreAuthorize" {
		return ProtAuthenticated, nil, false
	}
	expr := strings.ToLower(g.expr)
	switch {
	case strings.Contains(expr, "denyall()"):
		return ProtDenied, nil, true
	case strings.Contains(expr, "permitall()"):
		return ProtPublic, nil, true
	case strings.Contains(expr, "isauthenticated()"),
		strings.Contains(expr, "isfullyauthenticated()"),
		strings.Contains(expr, "isrememberme()"):
		return ProtAuthenticated, nil, true
	default:
		return ProtAuthenticated, nil, false
	}
}

// springRoles pulls role names out of an expression. @PreAuthorize roles sit
// inside hasRole/hasAnyRole/hasAuthority calls; @Secured and @RolesAllowed
// carry the names directly.
func springRoles(annotation, expr string) []string {
	var names []string
	if annotation == "PreAuthorize" {
		for _, m := range springRoleCallRe.FindAllStringSubmatch(expr, -1) {
			names = append(names, quotedValues(m[2])...)
		}
	} else {
		names = quotedValues(expr)
	}
	var out []string
	for _, name := range names {
		name = strings.TrimSpace(springRolePrefixRe.ReplaceAllString(strings.TrimSpace(name), ""))
		if name != "" {
			out = append(out, name)
		}
	}
	return dedupe(out)
}

func quotedValues(s string) []string {
	var out []string
	for _, m := range springQuotedRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// springGateEvidence names the annotation the way the source does, with roles
// normalised from hasRole('X') and @Secured({"ROLE_X"}).
func springGateEvidence(g springGate, classLevel bool, roles []string) string {
	where := "on " + g.method
	if classLevel {
		where = "on class " + g.class
	}
	return fmt.Sprintf("%s:%d %s %s", g.file, g.line, springAnnotationText(g, roles), where)
}

func springAnnotationText(g springGate, roles []string) string {
	switch g.annotation {
	case "PreAuthorize":
		expr := strings.TrimSpace(g.expr)
		if !strings.HasPrefix(expr, `"`) {
			expr = strconv.Quote(expr)
		}
		return "@PreAuthorize(" + expr + ")"
	case "Secured", "RolesAllowed":
		if len(roles) == 0 {
			return "@" + g.annotation + "(" + strings.TrimSpace(g.expr) + ")"
		}
		quoted := make([]string, len(roles))
		for i, role := range roles {
			quoted[i] = strconv.Quote("ROLE_" + role)
		}
		if len(quoted) == 1 {
			return "@" + g.annotation + "(" + quoted[0] + ")"
		}
		return "@" + g.annotation + "({" + strings.Join(quoted, ", ") + "})"
	}
	return "@" + g.annotation
}

// springConfigs collects the security rules of every service, in source order.
// The service of a configuration is the nearest module file above it, the same
// service the controllers resolve to (SPEC §4).
func springConfigs(facts []Fact, root string) map[string]*springConfig {
	configs := map[string]*springConfig{}
	for _, f := range facts {
		if !strings.HasSuffix(f.File, ".java") {
			continue
		}
		var m springMatcher
		switch f.Kind {
		case "security_matcher":
			m = springMatcher{
				file: f.File, line: f.Line, column: f.Column,
				name:    f.Metavars["$MATCHER"],
				pattern: f.Metavars["$PATTERN"],
				method:  normalizeOptionalMethod(f.Metavars["$METHOD"]),
				access:  f.Metavars["$ACCESS"],
				args:    f.Metavars["$...ARGS"],
			}
			if m.pattern == "" {
				continue
			}
		case "security_default":
			m = springMatcher{
				file: f.File, line: f.Line, column: f.Column,
				name:    f.Metavars["$DEFAULT"],
				pattern: "/**",
				access:  f.Metavars["$ACCESS"],
				args:    f.Metavars["$...ARGS"],
			}
		default:
			continue
		}
		if m.name == "" || m.access == "" {
			continue
		}
		service := serviceOf(root, f.File)
		cfg := configs[service]
		if cfg == nil {
			cfg = &springConfig{}
			configs[service] = cfg
		}
		if m.name == "pathMatchers" || m.name == "anyExchange" {
			cfg.webflux = true
		}
		cfg.matchers = append(cfg.matchers, m)
	}
	for _, cfg := range configs {
		sort.SliceStable(cfg.matchers, func(i, j int) bool {
			a, b := cfg.matchers[i], cfg.matchers[j]
			if a.file != b.file {
				return a.file < b.file
			}
			if a.line != b.line {
				return a.line < b.line
			}
			return a.column < b.column
		})
	}
	return configs
}

func normalizeOptionalMethod(method string) string {
	method = strings.TrimSpace(method)
	if method == "" {
		return ""
	}
	return normalizeMethod(method)
}

// springFramework labels a service reactive when its configuration uses the
// WebFlux matcher names; controller annotations are the same in both stacks.
func springFramework(cfg *springConfig) string {
	if cfg != nil && cfg.webflux {
		return "spring-webflux"
	}
	return "spring-mvc"
}

// decide applies the first matcher that matches the path and, when the matcher
// names one, the HTTP method. The fallback is the anyRequest/anyExchange rule,
// which is stored as a `/**` matcher. Without either Spring lets the request
// through, so the route is public with low confidence.
func (cfg *springConfig) decide(path, method string) (Protection, []string, []string, string) {
	for _, m := range cfg.matchers {
		if !m.matches(method, path) {
			continue
		}
		protection, roles, confidence := m.decision()
		return protection, roles, []string{m.evidence()}, confidence
	}
	return ProtPublic, nil, []string{"no matcher; Spring permits"}, "low"
}

func (m springMatcher) matches(method, path string) bool {
	if m.method != "" && method != "ANY" && m.method != method {
		return false
	}
	return antMatch(normalizePath(m.pattern), path)
}

// decision reads the access call. An unrecognised form never becomes public:
// the route stays protected but with medium confidence.
func (m springMatcher) decision() (Protection, []string, string) {
	switch m.access {
	case "permitAll":
		return ProtPublic, nil, "high"
	case "authenticated", "fullyAuthenticated":
		return ProtAuthenticated, nil, "high"
	case "denyAll":
		return ProtDenied, nil, "high"
	case "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority":
		roles := dedupe(quotedValues(m.args))
		if len(roles) == 0 {
			return ProtAuthenticated, nil, "medium"
		}
		return ProtRole, roles, "high"
	case "access":
		return springAccessDecision(m.args)
	default:
		return ProtAuthenticated, nil, "medium"
	}
}

// springAccessDecision interprets the SpEL of access("...") the same way a
// @PreAuthorize expression is interpreted, so both spell a role identically.
func springAccessDecision(args string) (Protection, []string, string) {
	expr := strings.TrimSpace(args)
	if len(expr) >= 2 && (expr[0] == '"' || expr[0] == '\'') && expr[len(expr)-1] == expr[0] {
		expr = expr[1 : len(expr)-1]
	}
	if expr == "" {
		return ProtAuthenticated, nil, "medium"
	}
	protection, roles, known := springGateOutcome(springGate{annotation: "PreAuthorize", expr: expr})
	confidence := "medium"
	if known {
		confidence = "high"
	}
	if protection == ProtRole {
		return ProtRole, roles, confidence
	}
	return protection, nil, confidence
}

// evidence rebuilds the matcher call as the developer wrote it.
func (m springMatcher) evidence() string {
	call := "." + m.name + "("
	if m.name != "anyRequest" && m.name != "anyExchange" {
		if m.method != "" {
			call += "HttpMethod." + m.method + ", "
		}
		call += strconv.Quote(m.pattern)
	}
	call += ")." + m.access + "(" + m.args + ")"
	return fmt.Sprintf("%s:%d %s", m.file, m.line, call)
}

func springVerb(verb string) string {
	verb = strings.TrimSpace(verb)
	if verb == "" {
		return "ANY" // @RequestMapping without method=
	}
	return normalizeMethod(strings.TrimSuffix(verb, "Mapping"))
}
