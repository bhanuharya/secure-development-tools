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
	springIdentRe      = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)
	springMethodArgRe  = regexp.MustCompile(`^HttpMethod\.([A-Z]+)\b\s*`)
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
	pattern string // path pattern; "/**" for the fallback; empty when unresolved
	method  string // HTTP method when the matcher names one, else ""
	access  string // permitAll, authenticated, hasRole, ...
	args    string // raw access arguments, e.g. "admin:write"
	raw     string // source expression when it was a constant or call
	unknown bool   // the expression could not be resolved to a path
	// accessUnknown marks an access rule this resolver does not model.
	accessUnknown bool
}

// springScope restricts a chain to a request subset (securityMatcher,
// antMatcher, ...). An empty scope list matches every request. A negated scope
// matches every request none of its patterns or children match.
type springScope struct {
	patterns []string
	method   string
	negated  bool
	children []springScope // Or children retain their own HTTP methods
}

// springScopeCall is one chain-scope call before its argument list is parsed.
type springScopeCall struct {
	file  string
	line  int
	name  string
	owner string
	args  string
}

// springIgnored is one WebSecurityCustomizer path that bypasses the filters.
// An ignore with an HTTP method only bypasses that method (T37).
type springIgnored struct {
	file    string
	line    int
	name    string
	raw     string
	pattern string
	method  string
}

func (i springIgnored) evidence() string {
	args := i.raw
	if i.pattern != "" {
		args = strconv.Quote(i.pattern)
		if i.method != "" {
			args = "HttpMethod." + i.method + ", " + args
		}
	}
	return fmt.Sprintf("%s:%d web.ignoring().%s(%s)", i.file, i.line, i.name, args)
}

// springFilter is one authentication mechanism or filter of a chain.
type springFilter struct {
	file string
	line int
	name string
	args string
}

// springConstant is one static final String declaration.
type springConstant struct {
	file  string
	class string
	name  string
	value string
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
	filters  []springFilter
}

// springConfig holds the authorization rules of one service.
type springConfig struct {
	matchers []springMatcher // flat list when no chain facts were found
	chains   []*springChain
	ignored  []springIgnored
	webflux  bool // pathMatchers/anyExchange: label routes spring-webflux
	// ignoredUnknown and ownershipUnknown mean an unmodelled construct could
	// change the decision, so applying the visible rules would guess.
	ignoredUnknown   []springUncertainty
	ownershipUnknown []springUncertainty
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
	protection, roles, evidence, confidence, note := springProtection(f, class, method, verb, path, classGates, methodGates, cfg)
	sentence := ""
	if protection == ProtUnknown {
		switch {
		case note != "":
			sentence = fmt.Sprintf("%s:%d %s: %s", f.File, f.Line, handler, note)
		case cfg == nil:
			sentence = fmt.Sprintf("%s:%d %s: no security configuration in the service; protection unknown", f.File, f.Line, handler)
		default:
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
func springProtection(f Fact, class, method, verb, path string, classGates, methodGates map[string][]springGate, cfg *springConfig) (Protection, []string, []string, string, string) {
	gates := methodGates[springMethodKey(f)]
	classLevel := false
	if len(gates) == 0 {
		gates = classGates[class]
		classLevel = len(gates) > 0
	}
	if len(gates) > 0 {
		protection, roles, evidence, confidence := springGateDecision(gates, classLevel)
		return protection, roles, evidence, confidence, ""
	}
	if cfg != nil {
		return cfg.decideWithNote(path, verb)
	}
	evidence := fmt.Sprintf("%s:%d no security configuration in the service", f.File, f.Line)
	return ProtUnknown, nil, []string{evidence}, "low", ""
}

// springGateDecision merges the (rare) multiple gates of one method. All must
// pass, so the strongest requirement wins; an undecidable gate cannot be
// hidden by a public one. A denied gate wins, then a role gate, then plain
// authentication, then an unknown decision, then public.
func springGateDecision(gates []springGate, classLevel bool) (Protection, []string, []string, string) {
	var evidence, roles []string
	authenticated, denied, unknown, role := false, false, false, false
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
			role = true
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
	case role:
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
	// @Secured(Constants.ADMIN) and @RolesAllowed(Constants.X) name a role even
	// when the value lives in a constant; dropping to authenticated would hide
	// the missing-role convention (T35 finding 11).
	if strings.TrimSpace(g.expr) != "" {
		return ProtRole, nil, false
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
	chains    []*springChain
	orders    []springOrderFact
	scopes    []springScopeCall
	matchers  []springMatcher
	constants []springConstant
	ignored   []springIgnored
	filters   []springFilter
	webflux   bool
}

type springOrderFact struct {
	file  string
	line  int
	order string
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
		case "security_chain", "security_order", "security_scope", "security_matcher",
			"security_matcher_expression", "security_matcher_unmodelled", "security_default",
			"security_ignored", "security_filter", "string_constant":
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
		b.scopes = append(b.scopes, springScopeCall{
			file: f.File, line: f.Line,
			name: f.Metavars["$SCOPE"], owner: f.Metavars["$OWNER"],
			args: f.Metavars["$...ARGS"],
		})
	case "security_filter":
		b.filters = append(b.filters, springFilter{
			file: f.File, line: f.Line,
			name: springFilterName(f),
			args: f.Metavars["$FILTER"],
		})
	case "string_constant":
		b.constants = append(b.constants, springConstant{
			file: f.File, class: f.Metavars["$C"],
			name: f.Metavars["$NAME"], value: f.Metavars["$VALUE"],
		})
	case "security_ignored":
		b.ignored = append(b.ignored, springIgnored{
			file: f.File, line: f.Line,
			name: f.Metavars["$IGNORE"], raw: f.Metavars["$...ARGS"],
		})
	case "security_matcher", "security_matcher_expression":
		if m, ok := springMatcherFact(f); ok {
			b.matchers = append(b.matchers, m)
			b.markFramework(f.Metavars["$MATCHER"], "")
		}
	case "security_matcher_unmodelled":
		m, ok := springMatcherFact(f)
		if ok {
			m.accessUnknown = true
			b.matchers = append(b.matchers, m)
			b.markFramework(f.Metavars["$MATCHER"], "")
		}
	case "security_default":
		if m, ok := springDefaultFact(f); ok {
			b.matchers = append(b.matchers, m)
			b.markFramework("", f.Metavars["$DEFAULT"])
		}
	}
}

func springMatcherFact(f Fact) (springMatcher, bool) {
	m := springMatcher{
		file: f.File, line: f.Line, column: f.Column,
		name:    f.Metavars["$MATCHER"],
		pattern: f.Metavars["$PATTERN"],
		method:  normalizeOptionalMethod(f.Metavars["$METHOD"]),
		access:  f.Metavars["$ACCESS"],
		args:    f.Metavars["$...ARGS"],
	}
	if f.Kind == "security_matcher_expression" {
		m.raw = f.Metavars["$PATTERN"]
	}
	if m.name == "" || m.access == "" || (m.pattern == "" && m.raw == "") {
		return springMatcher{}, false
	}
	return m, true
}

func springDefaultFact(f Fact) (springMatcher, bool) {
	m := springMatcher{
		file: f.File, line: f.Line, column: f.Column,
		name:    f.Metavars["$DEFAULT"],
		pattern: "/**",
		access:  f.Metavars["$ACCESS"],
		args:    f.Metavars["$...ARGS"],
	}
	return m, m.name != "" && m.access != ""
}

func (b *springBuild) markFramework(matcher, fallback string) {
	if matcher == "pathMatchers" || fallback == "anyExchange" {
		b.webflux = true
	}
}

// springFilterName reads the call name of either filter rule: addFilter* names
// the method metavariable, the mechanism rule names $MECHANISM.
func springFilterName(f Fact) string {
	if name := f.Metavars["$MECHANISM"]; name != "" {
		return name
	}
	return f.Metavars["$FILTER_KIND"]
}

// finish assigns scopes and matchers to the chain whose span contains them,
// then orders the chains deterministically in source order. Unreadable
// constructs are recorded instead of being dropped, so the decision becomes
// unknown rather than a guess (T35).
func (b *springBuild) finish() *springConfig {
	if len(b.chains) == 0 && len(b.matchers) == 0 && len(b.ignored) == 0 {
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
	b.assignOrders(cfg)
	for _, sc := range b.scopes {
		b.addScope(cfg, sc)
	}
	cfg.ignored = b.resolveIgnored(cfg)
	leftover := b.assignMatchers(cfg)
	b.assignFilters()
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

func (b *springBuild) assignOrders(cfg *springConfig) {
	// An @Order without a recognized chain usually means a chain signature
	// this resolver does not know; guessing a flat matcher list would erase
	// the chain boundaries the order exists to define.
	if len(b.chains) == 0 && len(b.orders) > 0 {
		cfg.ownershipUnknown = append(cfg.ownershipUnknown, springUncertainty{note: "an @Order fact has no recognized security chain"})
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
}

// assignMatchers resolves expression patterns and attaches matchers to their
// chain; without chains the matchers stay flat for the legacy configurer.
func (b *springBuild) assignMatchers(cfg *springConfig) []springMatcher {
	var leftover []springMatcher
	for _, m := range b.matchers {
		if m.raw != "" && !m.unknown {
			if value, ok := b.resolvePattern(m.raw, m.file); ok {
				m.pattern = value
			} else {
				m.unknown = true
			}
		}
		if m.pattern == "" && !m.unknown {
			continue
		}
		if c := chainFor(b.chains, m); c != nil {
			c.matchers = append(c.matchers, m)
		} else if len(b.chains) > 0 {
			// A matcher that no chain span owns cannot be assigned safely.
			raw := m.raw
			if raw == "" {
				raw = strconv.Quote(m.pattern)
			}
			bounds := springVisibleScope(raw)
			if m.method != "" {
				bounds.method = m.method
			}
			cfg.ownershipUnknown = append(cfg.ownershipUnknown, springUncertainty{bounds: bounds, note: m.evidence() + " belongs to no recognized security chain"})
		} else {
			leftover = append(leftover, m)
		}
	}
	return leftover
}

func (b *springBuild) assignFilters() {
	for _, f := range b.filters {
		if c := chainContaining(b.chains, f.file, f.line); c != nil {
			c.filters = append(c.filters, f)
		}
	}
}

// addScope parses one scope call and attaches its patterns. The builder's
// requestMatchers() has an empty argument list, so that call is skipped here
// while the following .antMatchers(...) call carries the patterns.
func (b *springBuild) addScope(cfg *springConfig, sc springScopeCall) {
	if strings.TrimSpace(sc.args) == "" {
		return
	}
	chain := chainContaining(b.chains, sc.file, sc.line)
	if chain == nil {
		if len(b.chains) > 0 && (sc.name == "securityMatcher" || sc.name == "antMatcher" || sc.name == "requestMatcher") {
			cfg.ownershipUnknown = append(cfg.ownershipUnknown, springUncertainty{bounds: springVisibleScope(sc.args), note: fmt.Sprintf("%s:%d %s scope belongs to no recognized security chain", sc.file, sc.line, sc.name)})
		}
		return
	}
	// HttpSecurity scopes name the request subset of this chain; the matcher
	// DSL inside an authorize lambda uses the same method names on another
	// receiver, so ownership decides. The legacy builder is
	// requestMatchers().antMatchers(...) on the chain's own variable.
	if !springScopeOwned(chain, sc) {
		return
	}
	scope, ok := b.scopeExpression(sc.args, sc.file)
	if !ok {
		cfg.ownershipUnknown = append(cfg.ownershipUnknown, springUncertainty{
			bounds: springVisibleScope(sc.args),
			note:   fmt.Sprintf("%s:%d %s(%s) cannot be evaluated", sc.file, sc.line, sc.name, sc.args),
		})
		return
	}
	chain.scopes = append(chain.scopes, scope)
}

// springScopeOwned reports whether the call configures the chain's request
// scope rather than an authorization matcher inside a lambda.
func springScopeOwned(chain *springChain, sc springScopeCall) bool {
	switch sc.name {
	case "securityMatcher", "antMatcher", "requestMatcher":
		return sc.owner == chain.http
	case "requestMatchers":
		return sc.owner == chain.http || sc.owner == chain.http+".requestMatchers()"
	default: // antMatchers, mvcMatchers, pathMatchers: builder only
		return sc.owner == chain.http+".requestMatchers()"
	}
}

// resolveIgnored parses WebSecurityCustomizer ignored paths. A known path is
// public; an unreadable expression makes every path it may cover unknown.
func (b *springBuild) resolveIgnored(cfg *springConfig) []springIgnored {
	var out []springIgnored
	for _, ignored := range b.ignored {
		scope, ok := b.scopeExpression(ignored.raw, ignored.file)
		paths, simple := scope.ignoredPaths(ignored)
		if !ok || !simple {
			cfg.ignoredUnknown = append(cfg.ignoredUnknown, springUncertainty{
				bounds: springVisibleScope(ignored.raw),
				note:   ignored.evidence() + ": ignore expression cannot be evaluated",
			})
			continue
		}
		out = append(out, paths...)
	}
	return out
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
	protection, roles, evidence, confidence, _ := cfg.decideWithNote(path, method)
	return protection, roles, evidence, confidence
}

// decideWithNote also returns an Unresolved sentence naming an unmodelled
// construct when the answer is unknown.
func (cfg *springConfig) decideWithNote(path, method string) (Protection, []string, []string, string, string) {
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
func (cfg *springConfig) decideAny(path string) (Protection, []string, []string, string, string) {
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	var weakest Protection
	var roles, evidence []string
	weakestMethod := ""
	weakestConfidence, weakestNote := "", ""
	firstRank := -1
	varied := false
	for _, method := range methods {
		protection, methodRoles, methodEvidence, confidence, note := cfg.decideWithNote(path, method)
		if firstRank < 0 {
			firstRank = protectionRank(protection)
		} else if protectionRank(protection) != firstRank {
			varied = true
		}
		if weakestMethod == "" || protectionRank(protection) < protectionRank(weakest) {
			weakest, roles, evidence = protection, methodRoles, methodEvidence
			weakestMethod, weakestConfidence, weakestNote = method, confidence, note
		}
	}
	if varied {
		for i := range evidence {
			evidence[i] = fmt.Sprintf("%s (weakest method %s)", evidence[i], weakestMethod)
		}
	}
	return weakest, roles, evidence, weakestConfidence, weakestNote
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

func (cfg *springConfig) decideChains(path, method string) (Protection, []string, []string, string, string) {
	var matching []*springChain
	for _, c := range cfg.chains {
		switch c.scopeMatch(method, path) {
		case antNo:
			continue
		case antUnknown:
			return ProtUnknown, nil, []string{c.describe() + ": scope constraint cannot be evaluated"}, "low", ""
		default:
			matching = append(matching, c)
		}
	}
	if len(matching) == 0 {
		return ProtPublic, nil, []string{"no chain scope matches; Spring leaves the request unsecured"}, "low", ""
	}
	sort.SliceStable(matching, func(i, j int) bool { return chainBefore(matching[i], matching[j]) })
	if len(matching) > 1 && !chainOrderIsDecidable(matching[0], matching[1]) {
		return ProtUnknown, nil, []string{
			matching[0].describe(),
			matching[1].describe() + ": both chains match and their order is not determinable",
		}, "low", ""
	}
	chain := matching[0]
	// Spring selects the first matching chain even when it declares no
	// authorization rule; later chains are never consulted (T35 finding 4).
	if len(chain.matchers) == 0 {
		if len(chain.filters) > 0 {
			filter := chain.filters[0]
			return ProtUnknown, nil, []string{filter.evidence()}, "low",
				fmt.Sprintf("%s has authentication mechanism .%s() that this resolver does not model", chain.describe(), filter.name)
		}
		return ProtPublic, nil, []string{chain.describe() + ": no authorization rules; Spring leaves the request unsecured"}, "high", ""
	}
	return decideSpringMatchers(chain.matchers, path, method)
}

func (f springFilter) evidence() string {
	if f.args != "" {
		return fmt.Sprintf("%s:%d .%s(%s)", f.file, f.line, f.name, f.args)
	}
	return fmt.Sprintf("%s:%d .%s()", f.file, f.line, f.name)
}

func (c *springChain) scopeMatch(method, path string) antResult {
	if len(c.scopes) == 0 {
		return antYes
	}
	result := antNo
	for _, scope := range c.scopes {
		switch scope.match(method, path) {
		case antYes:
			return antYes
		case antUnknown:
			result = antUnknown
		}
	}
	return result
}

// match evaluates one scope. A negated matcher applies to every path its
// patterns do not match, so the result of the positive match is inverted.
func (s springScope) match(method, path string) antResult {
	result := antNo
	if s.method == "" || s.method == method {
		result = s.positiveMatch(method, path)
	}
	if !s.negated {
		return result
	}
	switch result {
	case antYes:
		return antNo
	case antNo:
		return antYes
	}
	return antUnknown
}

func (s springScope) positiveMatch(method, path string) antResult {
	result := antNo
	for _, child := range s.children {
		switch child.match(method, path) {
		case antYes:
			return antYes
		case antUnknown:
			result = antUnknown
		}
	}
	for _, pattern := range s.patterns {
		switch antMatchResult(normalizePath(pattern), path) {
		case antYes:
			result = antYes
		case antUnknown:
			if result != antYes {
				result = antUnknown
			}
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
		where += " " + c.scopes[0].describe()
	}
	return where
}

// describe renders one scope for an Unresolved sentence: its patterns, marked
// as negated when the chain applies outside them.
func (s springScope) describe() string {
	patterns := s.allPatterns()
	quoted := make([]string, len(patterns))
	for i, pattern := range patterns {
		quoted[i] = strconv.Quote(pattern)
	}
	text := strings.Join(quoted, ", ")
	if s.negated {
		return "not " + text
	}
	return text
}

func decideSpringMatchers(matchers []springMatcher, path, method string) (Protection, []string, []string, string, string) {
	for _, m := range matchers {
		switch m.matchResult(method, path) {
		case antNo:
			continue
		case antUnknown:
			note := ""
			if m.unknown {
				note = "request matcher pattern " + m.raw + " cannot be resolved"
			}
			return ProtUnknown, nil, []string{m.evidence() + " (constraint cannot be evaluated)"}, "low", note
		default:
			protection, roles, confidence, note := m.decisionWithNote()
			return protection, roles, []string{m.evidence()}, confidence, note
		}
	}
	return ProtPublic, nil, []string{"no matcher; Spring permits"}, "low", ""
}

func (m springMatcher) matchResult(method, path string) antResult {
	if m.method != "" && m.method != method {
		return antNo
	}
	if m.unknown {
		bounds := springVisibleScope(m.raw)
		if bounds.hasPatterns() && bounds.match(method, path) == antNo {
			return antNo
		}
		return antUnknown
	}
	return antMatchResult(normalizePath(m.pattern), path)
}

// decision reads the access call. An unrecognised form never becomes public.
func (m springMatcher) decision() (Protection, []string, string) {
	protection, roles, confidence, _ := m.decisionWithNote()
	return protection, roles, confidence
}

// decisionWithNote keeps the reason an unreadable authorization manager could
// not decide, so the route's Unresolved sentence names it (T35 finding 9).
func (m springMatcher) decisionWithNote() (Protection, []string, string, string) {
	if m.accessUnknown {
		return ProtUnknown, nil, "low", fmt.Sprintf("access rule .%s(%s) cannot be read", m.access, m.args)
	}
	switch m.access {
	case "permitAll":
		return ProtPublic, nil, "high", ""
	case "authenticated", "fullyAuthenticated":
		return ProtAuthenticated, nil, "high", ""
	case "denyAll":
		return ProtDenied, nil, "high", ""
	case "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority":
		roles := dedupe(quotedValues(m.args))
		if len(roles) == 0 {
			// A constant argument (AuthoritiesConstants.ADMIN) is still a
			// role check even though its value cannot be read here; downgrading
			// it to authenticated hides the missing role convention.
			return ProtRole, nil, "medium", ""
		}
		return ProtRole, roles, "high", ""
	case "access":
		protection, roles, confidence := springAccessDecision(m.args)
		if protection == ProtUnknown {
			return protection, roles, confidence, "authorization manager " + strings.TrimSpace(m.args) + " cannot be read"
		}
		return protection, roles, confidence, ""
	default:
		return ProtAuthenticated, nil, "medium", ""
	}
}

// springAccessDecision interprets the SpEL of access("...") the same way a
// @PreAuthorize expression is interpreted, so both spell a role identically.
// Spring Boot 3 passes an AuthorizationManager object instead; its literal
// expression is unwrapped, and an unreadable manager is unknown (T35).
func springAccessDecision(args string) (Protection, []string, string) {
	source, ok := springAccessExpression(args)
	if !ok {
		return ProtUnknown, nil, "low"
	}
	protection, roles, known := springSpelDecision(evalSpel(source))
	confidence := "medium"
	if known {
		confidence = "high"
	}
	if protection == ProtRole {
		return ProtRole, roles, confidence
	}
	return protection, nil, confidence
}

// springAccessExpression returns the expression string access() should
// evaluate. A string literal is used as written; a constructor of an
// AuthorizationManager is unwrapped only when its single argument is a
// literal. Any other Java expression is a manager we cannot read.
func springAccessExpression(args string) (string, bool) {
	s := strings.TrimSpace(args)
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(s, "new ") {
		open := strings.IndexByte(s, '(')
		if open < 0 || !strings.HasSuffix(s, ")") {
			return "", false
		}
		class := strings.TrimSpace(s[len("new "):open])
		if !strings.HasSuffix(class, "AuthorizationManager") {
			return "", false
		}
		inner := strings.TrimSpace(s[open+1 : len(s)-1])
		if inner == "" {
			return "", false
		}
		if value, next, ok := readSpelString(inner, 0); ok && next == len(inner) {
			return value, true
		}
		return "", false
	}
	if s[0] == '"' || s[0] == '\'' {
		return s, true
	}
	if s == "true" || s == "false" {
		return s, true
	}
	if springIdentRe.MatchString(s) {
		return "", false // a variable holding a manager, not a SpEL expression
	}
	return s, true
}

// evidence rebuilds the matcher call as written: Spring matcher paths and access expressions are
// never credentials, and the template logic identifies the deciding matcher by its quoted pattern.
// The final redaction pass in sanitizeRoutes still runs over it.
func (m springMatcher) evidence() string {
	call := "." + m.name + "("
	if m.name != "anyRequest" && m.name != "anyExchange" {
		if m.method != "" {
			call += "HttpMethod." + m.method + ", "
		}
		if m.unknown {
			call += m.raw
		} else {
			call += strconv.Quote(m.pattern)
		}
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
