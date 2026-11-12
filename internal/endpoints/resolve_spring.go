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
// the access of the first filter chain, in @Order, whose scope matches the
// request, and of the first matcher in that chain.

var (
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

// springMatcher is one authorization rule of a security chain: a request
// matcher (or the anyRequest/anyExchange fallback) and its access.
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

// springScope restricts a chain to a request subset (securityMatcher,
// antMatcher, ...). An empty scope list matches every request.
type springScope struct {
	pattern string
	method  string
}

// springChain is one SecurityFilterChain bean or configure(HttpSecurity)
// method. Matchers belong to the chain whose source span contains them.
type springChain struct {
	file     string
	line     int
	endLine  int
	http     string // HttpSecurity parameter name, for scope ownership
	ordered  bool
	order    int
	scopes   []springScope
	matchers []springMatcher
}

// springConfig holds the authorization rules of one service.
type springConfig struct {
	matchers []springMatcher // flat list when no chain facts were found
	chains   []*springChain
	webflux  bool // pathMatchers/anyExchange: label routes spring-webflux
	// ownershipUnknown means a rule or order fact could not be tied to a
	// recognized chain, so applying any chain would guess its boundaries.
	ownershipUnknown bool
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

// resolveSpringFile indexes one controller file by class name and handler
// declaration, then turns its route facts into routes.
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
	line := f.Line
	if l := f.MetavarLines["$ANNOTATION"]; l > 0 {
		line = l
	}
	return springGate{
		file:       f.File,
		line:       line,
		annotation: f.Metavars["$ANNOTATION"],
		expr:       f.Metavars["$EXPR"],
		class:      f.Metavars["$C"],
		method:     f.Metavars["$M"],
	}
}

func classOf(f Fact) string { return f.Metavars["$C"] }

// springMethodKey identifies one handler declaration. Overloads share
// "Class.method", but a gate fact and its route fact both span the same body,
// so the end line (with the file and method name) never leaks a gate onto
// another overload.
func springMethodKey(f Fact) string {
	return f.File + ":" + strconv.Itoa(f.EndLine) + ":" + f.Metavars["$M"]
}

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
	if protection == ProtUnknown {
		if cfg == nil {
			sentence = fmt.Sprintf("%s:%d %s: no security configuration in the service; protection unknown", f.File, f.Line, handler)
		} else {
			sentence = fmt.Sprintf("%s:%d %s: protection cannot be decided", f.File, f.Line, handler)
		}
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
	gates := methodGates[springMethodKey(f)]
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

// springGateDecision merges the (rare) multiple gates of one method. All must
// pass, so the strongest requirement wins; an undecidable gate cannot be
// hidden by a public one. A denied gate wins, then a role gate, then plain
// authentication, then an unknown decision, then public.
func springGateDecision(gates []springGate, classLevel bool) (Protection, []string, []string, string) {
	var evidence, roles []string
	authenticated, denied, unknown := false, false, false
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
		case ProtUnknown:
			unknown = true
		}
	}
	switch {
	case denied:
		return ProtDenied, nil, evidence, confidence
	case len(roles) > 0:
		return ProtRole, dedupe(roles), evidence, confidence
	case authenticated:
		return ProtAuthenticated, nil, evidence, confidence
	case unknown:
		return ProtUnknown, nil, evidence, confidence
	default:
		return ProtPublic, nil, evidence, confidence // only @PreAuthorize("permitAll()")
	}
}

// springGateOutcome reads one annotation through the SpEL evaluator. A lone
// unreadable term still means "protected" (authenticated, medium confidence);
// an unreadable alternative inside a boolean formula is unknown instead.
func springGateOutcome(g springGate) (Protection, []string, bool) {
	if g.annotation == "PreAuthorize" {
		return springSpelDecision(evalSpel(g.expr))
	}
	roles := springRoles(g.expr)
	if len(roles) > 0 {
		return ProtRole, roles, true
	}
	return ProtAuthenticated, nil, false
}

// springRoles pulls role names out of @Secured and @RolesAllowed, which carry
// the names directly. @PreAuthorize roles come from the SpEL evaluator.
func springRoles(expr string) []string {
	var out []string
	for _, name := range quotedValues(expr) {
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

// springBuild is the per-service accumulator while facts are grouped into
// chains. Matchers and scopes are attached by source span in finish.
type springBuild struct {
	chains   []*springChain
	orders   []springOrderFact
	scopes   []springScopeFact
	matchers []springMatcher
	webflux  bool
}

type springOrderFact struct {
	file  string
	line  int
	order string
}

type springScopeFact struct {
	file  string
	line  int
	name  string
	owner string
	scope springScope
}

// springConfigs collects the security rules of every service. The service of
// a configuration is the nearest module file above it, the same service the
// controllers resolve to (SPEC §4).
func springConfigs(facts []Fact, root string) map[string]*springConfig {
	builds := map[string]*springBuild{}
	for _, f := range facts {
		if !strings.HasSuffix(f.File, ".java") {
			continue
		}
		switch f.Kind {
		case "security_chain", "security_order", "security_scope", "security_matcher", "security_default":
		default:
			continue
		}
		service := serviceOf(root, f.File)
		b := builds[service]
		if b == nil {
			b = &springBuild{}
			builds[service] = b
		}
		b.add(f)
	}
	configs := make(map[string]*springConfig, len(builds))
	for service, b := range builds {
		configs[service] = b.finish()
	}
	return configs
}

func (b *springBuild) add(f Fact) {
	switch f.Kind {
	case "security_chain":
		b.chains = append(b.chains, &springChain{
			file:    f.File,
			line:    f.Line,
			endLine: f.EndLine,
			http:    f.Metavars["$HTTP"],
		})
	case "security_order":
		b.orders = append(b.orders, springOrderFact{file: f.File, line: f.Line, order: f.Metavars["$ORDER"]})
	case "security_scope":
		if f.Metavars["$PATTERN"] == "" {
			return
		}
		b.scopes = append(b.scopes, springScopeFact{
			file: f.File, line: f.Line, name: f.Metavars["$SCOPE"], owner: f.Metavars["$OWNER"],
			scope: springScope{pattern: f.Metavars["$PATTERN"], method: normalizeOptionalMethod(f.Metavars["$METHOD"])},
		})
	case "security_matcher":
		m := springMatcher{
			file: f.File, line: f.Line, column: f.Column,
			name:    f.Metavars["$MATCHER"],
			pattern: f.Metavars["$PATTERN"],
			method:  normalizeOptionalMethod(f.Metavars["$METHOD"]),
			access:  f.Metavars["$ACCESS"],
			args:    f.Metavars["$...ARGS"],
		}
		if m.pattern != "" && m.name != "" && m.access != "" {
			b.matchers = append(b.matchers, m)
		}
	case "security_default":
		m := springMatcher{
			file: f.File, line: f.Line, column: f.Column,
			name:    f.Metavars["$DEFAULT"],
			pattern: "/**",
			access:  f.Metavars["$ACCESS"],
			args:    f.Metavars["$...ARGS"],
		}
		if m.name != "" && m.access != "" {
			b.matchers = append(b.matchers, m)
		}
	}
	if f.Kind == "security_matcher" {
		name := f.Metavars["$MATCHER"]
		if name == "pathMatchers" {
			b.webflux = true
		}
	}
	if f.Kind == "security_default" {
		name := f.Metavars["$DEFAULT"]
		if name == "anyExchange" {
			b.webflux = true
		}
	}
}

// finish assigns scopes and matchers to the chain whose span contains them,
// then orders the chains deterministically in source order.
func (b *springBuild) finish() *springConfig {
	if len(b.chains) == 0 && len(b.matchers) == 0 {
		return nil // a scope without a chain is not security configuration we can use
	}
	sort.SliceStable(b.chains, func(i, j int) bool {
		a, c := b.chains[i], b.chains[j]
		if a.file != c.file {
			return a.file < c.file
		}
		return a.line < c.line
	})
	cfg := &springConfig{webflux: b.webflux}
	// An @Order without a recognized chain usually means a chain signature
	// this resolver does not know; guessing a flat matcher list would erase
	// the chain boundaries the order exists to define.
	if len(b.chains) == 0 && len(b.orders) > 0 {
		cfg.ownershipUnknown = true
	}
	for _, order := range b.orders {
		chain := chainContaining(b.chains, order.file, order.line)
		if chain == nil || chain.ordered {
			continue
		}
		if value, err := strconv.Atoi(strings.TrimSpace(order.order)); err == nil {
			chain.ordered, chain.order = true, value
		}
	}
	for _, sc := range b.scopes {
		chain := chainContaining(b.chains, sc.file, sc.line)
		if chain == nil {
			if len(b.chains) > 0 && sc.name != "requestMatchers" {
				cfg.ownershipUnknown = true
			}
			continue
		}
		// requestMatchers() is also an authorization matcher inside a lambda;
		// the owner check keeps that from becoming a chain scope. The other
		// names only exist on HttpSecurity, so their owner is a formality.
		if chain.http == sc.owner || sc.name != "requestMatchers" {
			chain.scopes = append(chain.scopes, sc.scope)
		}
	}
	var leftover []springMatcher
	for _, m := range b.matchers {
		if c := chainFor(b.chains, m); c != nil {
			c.matchers = append(c.matchers, m)
		} else if len(b.chains) > 0 {
			// A matcher that no chain span owns cannot be assigned safely.
			cfg.ownershipUnknown = true
		} else {
			leftover = append(leftover, m)
		}
	}
	for _, c := range b.chains {
		sortSpringMatchers(c.matchers)
	}
	if len(b.chains) == 0 {
		sortSpringMatchers(leftover)
		cfg.matchers = leftover
		return cfg
	}
	cfg.chains = b.chains
	return cfg
}

func sortSpringMatchers(matchers []springMatcher) {
	sort.SliceStable(matchers, func(i, j int) bool {
		a, b := matchers[i], matchers[j]
		if a.file != b.file {
			return a.file < b.file
		}
		if a.line != b.line {
			return a.line < b.line
		}
		return a.column < b.column
	})
}

// chainFor returns the innermost chain whose source span contains the matcher.
func chainFor(chains []*springChain, m springMatcher) *springChain {
	return chainContaining(chains, m.file, m.line)
}

func chainContaining(chains []*springChain, file string, line int) *springChain {
	var best *springChain
	for _, c := range chains {
		if c.file != file || line < c.line || line > c.endLine {
			continue
		}
		if best == nil || c.endLine-c.line < best.endLine-best.line {
			best = c
		}
	}
	return best
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

// decide applies the first chain, by @Order, whose scope matches the request;
// inside that chain the first matcher for the method and path wins. A {param}
// route stands for several paths, so it is decided by the weakest one.
func (cfg *springConfig) decide(path, method string) (Protection, []string, []string, string) {
	if method == "ANY" {
		return cfg.decideAny(path)
	}
	if springTemplatePath(path) {
		return cfg.decideTemplate(path, method)
	}
	return cfg.decideConcrete(path, method)
}

// decideAny evaluates every method an unrestricted @RequestMapping accepts and
// reports the weakest protection, naming the method that is weaker.
func (cfg *springConfig) decideAny(path string) (Protection, []string, []string, string) {
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	var weakest Protection
	var roles, evidence []string
	weakestMethod := ""
	weakestConfidence := ""
	firstRank := -1
	varied := false
	for _, method := range methods {
		protection, methodRoles, methodEvidence, confidence := cfg.decide(path, method)
		if firstRank < 0 {
			firstRank = protectionRank(protection)
		} else if protectionRank(protection) != firstRank {
			varied = true
		}
		if weakestMethod == "" || protectionRank(protection) < protectionRank(weakest) {
			weakest, roles, evidence = protection, methodRoles, methodEvidence
			weakestMethod, weakestConfidence = method, confidence
		}
	}
	if varied {
		for i := range evidence {
			evidence[i] = fmt.Sprintf("%s (weakest method %s)", evidence[i], weakestMethod)
		}
	}
	return weakest, roles, evidence, weakestConfidence
}

func protectionRank(p Protection) int {
	switch p {
	case ProtPublic:
		return 0
	case ProtUnknown:
		return 1
	case ProtAuthenticated:
		return 2
	case ProtRole:
		return 3
	case ProtDenied:
		return 4
	}
	return 0
}

func (cfg *springConfig) decideChains(path, method string) (Protection, []string, []string, string) {
	var matching []*springChain
	for _, c := range cfg.chains {
		if len(c.matchers) == 0 {
			continue // a chain that declares no authorization rule cannot decide a route
		}
		switch c.scopeMatch(method, path) {
		case antNo:
			continue
		case antUnknown:
			return ProtUnknown, nil, []string{c.describe() + ": scope constraint cannot be evaluated"}, "low"
		default:
			matching = append(matching, c)
		}
	}
	if len(matching) == 0 {
		return ProtPublic, nil, []string{"no chain scope matches; Spring leaves the request unsecured"}, "low"
	}
	sort.SliceStable(matching, func(i, j int) bool { return chainBefore(matching[i], matching[j]) })
	if len(matching) > 1 && !chainOrderIsDecidable(matching[0], matching[1]) {
		return ProtUnknown, nil, []string{
			matching[0].describe(),
			matching[1].describe() + ": both chains match and their order is not determinable",
		}, "low"
	}
	return decideSpringMatchers(matching[0].matchers, path, method)
}

func (c *springChain) scopeMatch(method, path string) antResult {
	if len(c.scopes) == 0 {
		return antYes
	}
	result := antNo
	for _, scope := range c.scopes {
		if scope.method != "" && scope.method != method {
			continue
		}
		switch antMatchResult(normalizePath(scope.pattern), path) {
		case antYes:
			return antYes
		case antUnknown:
			result = antUnknown
		}
	}
	return result
}

func chainBefore(a, b *springChain) bool {
	if a.ordered != b.ordered {
		return a.ordered
	}
	if a.ordered && a.order != b.order {
		return a.order < b.order
	}
	if a.file != b.file {
		return a.file < b.file
	}
	return a.line < b.line
}

func chainOrderIsDecidable(a, b *springChain) bool {
	if a.ordered && b.ordered {
		return a.order != b.order
	}
	return a.ordered || b.ordered
}

func (c *springChain) describe() string {
	where := fmt.Sprintf("%s:%d security chain", c.file, c.line)
	if len(c.scopes) > 0 {
		where += " " + strconv.Quote(c.scopes[0].pattern)
	}
	return where
}

func decideSpringMatchers(matchers []springMatcher, path, method string) (Protection, []string, []string, string) {
	for _, m := range matchers {
		switch m.matchResult(method, path) {
		case antNo:
			continue
		case antUnknown:
			return ProtUnknown, nil, []string{m.evidence() + " (constraint cannot be evaluated)"}, "low"
		default:
			protection, roles, confidence := m.decision()
			return protection, roles, []string{m.evidence()}, confidence
		}
	}
	return ProtPublic, nil, []string{"no matcher; Spring permits"}, "low"
}

func (m springMatcher) matchResult(method, path string) antResult {
	if m.method != "" && m.method != method {
		return antNo
	}
	return antMatchResult(normalizePath(m.pattern), path)
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
			// A constant argument (AuthoritiesConstants.ADMIN) is still a
			// role check even though its value cannot be read here; downgrading
			// it to authenticated hides the missing role convention.
			return ProtRole, nil, "medium"
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
	if strings.TrimSpace(args) == "" {
		return ProtAuthenticated, nil, "medium"
	}
	protection, roles, known := springSpelDecision(evalSpel(args))
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
