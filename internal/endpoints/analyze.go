package endpoints

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// Convention rule IDs (SPEC §6). T09 turns these into scan findings too.
const (
	RuleUnprotectedAmongProtected = "scp.endpoints.unprotected-among-protected"
	RuleSensitiveRoutePublic      = "scp.endpoints.sensitive-route-public"
	RuleSensitiveRouteWithoutRole = "scp.endpoints.sensitive-route-without-role"
)

// Default path lists from SPEC §7. Config entries are extras added to these.
// registration covers onboarding flows (POST /api/v1/registration), which are
// public by design just like register, login and password recovery.
const (
	defaultPublicPathRegex    = `(?i)(login|logout|signin|sign-in|signup|sign-up|register$|registration|authenticate|/auth(/|$)|/token|refresh|forgot|otp|callback|webhook|notify|health|ping|public|captcha|metrics|/swagger|/docs)`
	defaultSensitivePathRegex = `(?i)/(admin|management|backoffice|back-office|internal|feign|actuator|registry|eureka|debug|test)(/|$)|register/bo|update-cif|/roles?(/|$)|authorit|disburs|transfer|withdraw|inject|approve|reject|reset-password|change-password|update-password|update-email|bank-account|/users/init`
)

// selfServicePath is the part of a sensitive route a logged-in user may change
// for their own account (SPEC §6 rule 3).
var selfServiceRe = regexp.MustCompile(`(?i)(change-password|update-password|update-email)`)

// Analyze applies the SPEC §6 convention rules to an inventory and returns
// findings in file, line order. A route produces at most one finding: the most
// severe applicable rule wins (rule 2, then 1, then 3), so a public sensitive
// route is an error even when rule 1 also applies.
func Analyze(inv *Inventory, cfg config.EndpointsCfg) ([]*finding.Finding, error) {
	if inv == nil {
		return nil, fmt.Errorf("analyze: nil inventory")
	}
	inv = sanitizeInventory(inv)
	rules, err := newConventionRules(cfg)
	if err != nil {
		return nil, err
	}
	byService := map[string][]Route{}
	var services []string
	for _, rt := range inv.Routes {
		rt = effective(rt) // a public route authenticated upstream is judged as authenticated
		if _, ok := byService[rt.Service]; !ok {
			services = append(services, rt.Service)
		}
		byService[rt.Service] = append(byService[rt.Service], rt)
	}
	sort.Strings(services)
	out := make([]*finding.Finding, 0)
	for _, svc := range services {
		routes := byService[svc]
		conv := newServiceConvention(routes, rules)
		for _, rt := range routes {
			if f := conv.findingFor(rt); f != nil {
				out = append(out, f)
			}
		}
	}
	sortFindings(out)
	for i, f := range out {
		f.ID = fmt.Sprintf("endpoints:%05d", i+1)
	}
	return out, nil
}

// conventionRules is the compiled configuration of the three rules.
type conventionRules struct {
	public         *regexp.Regexp
	sensitive      *regexp.Regexp
	publicExtra    []*regexp.Regexp
	sensitiveExtra []*regexp.Regexp
	minRoutes      int
	majority       float64
}

func newConventionRules(cfg config.EndpointsCfg) (*conventionRules, error) {
	if cfg.MinRoutes < 0 {
		return nil, fmt.Errorf("endpoints.minRoutes %d is negative", cfg.MinRoutes)
	}
	if cfg.Majority < 0 || cfg.Majority > 1 {
		return nil, fmt.Errorf("endpoints.majority %v must be between 0 and 1", cfg.Majority)
	}
	r := &conventionRules{
		public:    regexp.MustCompile(defaultPublicPathRegex),
		sensitive: regexp.MustCompile(defaultSensitivePathRegex),
		minRoutes: cfg.MinRoutes,
		majority:  cfg.Majority,
	}
	if r.minRoutes == 0 {
		r.minRoutes = config.DefaultMinRoutes
	}
	if r.majority == 0 {
		r.majority = config.DefaultMajority
	}
	for _, p := range cfg.PublicPaths {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("endpoints.publicPaths %q: %v", p, err)
		}
		r.publicExtra = append(r.publicExtra, re)
	}
	for _, p := range cfg.SensitivePaths {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("endpoints.sensitivePaths %q: %v", p, err)
		}
		r.sensitiveExtra = append(r.sensitiveExtra, re)
	}
	return r, nil
}

func (r *conventionRules) isPublicPath(path string) bool {
	if r.public.MatchString(path) {
		return true
	}
	for _, re := range r.publicExtra {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// sensitiveMatch names the part of the path that matched, for the message.
func (r *conventionRules) sensitiveMatch(path string) string {
	for _, re := range append([]*regexp.Regexp{r.sensitive}, r.sensitiveExtra...) {
		if m := re.FindString(path); m != "" {
			return strings.TrimRight(m, "/")
		}
	}
	return ""
}

// selfServicePath reports a route where a signed-in user acts on their own
// credentials: the only sensitive match is a password or email change and no
// {param} names another account. Such routes still need authentication, but
// any logged-in user is the right audience (SPEC §6 rule 3).
func (r *conventionRules) selfServicePath(path string) bool {
	if strings.Contains(path, "{") {
		return false // /users/{id}/change-password acts on another account
	}
	found := false
	for _, re := range append([]*regexp.Regexp{r.sensitive}, r.sensitiveExtra...) {
		for _, m := range re.FindAllString(path, -1) {
			if !selfServiceRe.MatchString(strings.TrimRight(m, "/")) {
				return false
			}
			found = true
		}
	}
	return found
}

// serviceConvention holds the per-service counts and the peers' gate evidence
// that rules 1 and 3 quote in their messages.
type serviceConvention struct {
	rules         *conventionRules
	stateChanging int
	known         int
	protected     int
	gateEvidence  string
	roleEvidence  string
	hasRole       bool
}

func newServiceConvention(routes []Route, rules *conventionRules) *serviceConvention {
	c := &serviceConvention{rules: rules}
	gates, roles := map[string]int{}, map[string]int{}
	for _, rt := range routes {
		if rt.Protection == ProtRole {
			c.hasRole = true
			addEvidence(roles, firstRoleEvidence(rt))
		}
		if !isStateChanging(rt.Method) || rules.isPublicPath(rt.Path) {
			continue
		}
		c.stateChanging++
		if rt.Protection == ProtUnknown {
			continue // counted as state-changing, but not as a known protection
		}
		c.known++
		if rt.Protection == ProtAuthenticated || rt.Protection == ProtRole {
			c.protected++
			addEvidence(gates, firstEvidence(rt))
		}
	}
	c.gateEvidence = mostCommon(gates)
	c.roleEvidence = mostCommon(roles)
	return c
}

func (c *serviceConvention) findingFor(rt Route) *finding.Finding {
	if rt.Protection == ProtUnknown {
		return nil // uncertainty is counted, never reported as a violation
	}
	sensitive := c.rules.sensitiveMatch(rt.Path) != ""
	if sensitive && rt.Protection == ProtPublic {
		return c.sensitivePublicFinding(rt)
	}
	if c.ruleOneApplies(rt) {
		return c.unprotectedFinding(rt)
	}
	if sensitive && rt.Protection == ProtAuthenticated && c.hasRole && !c.rules.selfServicePath(rt.Path) {
		return c.sensitiveWithoutRoleFinding(rt)
	}
	return nil
}

// ruleOneApplies counts only state-changing routes that are not public by
// design. Rule 2 still reports those paths when their names are sensitive.
func (c *serviceConvention) ruleOneApplies(rt Route) bool {
	if rt.Protection != ProtPublic || !isStateChanging(rt.Method) || c.rules.isPublicPath(rt.Path) {
		return false
	}
	if c.stateChanging < c.rules.minRoutes || c.known == 0 {
		return false
	}
	return float64(c.protected)/float64(c.known) >= c.rules.majority
}

func (c *serviceConvention) unprotectedFinding(rt Route) *finding.Finding {
	gate := "the service's authentication middleware"
	if c.gateEvidence != "" {
		gate = fmt.Sprintf("%q", c.gateEvidence)
	}
	msg := fmt.Sprintf("%s %s is public while %d of %d state-changing routes in this service require authentication (most often %s). Anyone can call it; add the same gate or move the route under the protected group.",
		rt.Method, rt.shownPath(), c.protected, c.known, gate)
	return newConventionFinding(rt, RuleUnprotectedAmongProtected,
		"State-changing route skips the service's authentication convention",
		"Add the authentication middleware the rest of the service uses to this route, or register it under the protected router group.",
		[]string{"CWE-306", "CWE-862"}, "warning", msg)
}

func (c *serviceConvention) sensitivePublicFinding(rt Route) *finding.Finding {
	pattern := c.rules.sensitiveMatch(rt.Path)
	msg := fmt.Sprintf("%s %s is public, but its path matches the sensitive pattern %q. Anyone who can reach the service can use an administrative or money-moving endpoint; require authentication and a role that matches the operation.",
		rt.Method, rt.shownPath(), pattern)
	return newConventionFinding(rt, RuleSensitiveRoutePublic,
		"Sensitive route is reachable without authentication",
		"Require authentication and a role that matches the sensitivity of this path, or remove the route from the public surface.",
		[]string{"CWE-306", "CWE-284"}, "error", msg)
}

func (c *serviceConvention) sensitiveWithoutRoleFinding(rt Route) *finding.Finding {
	roleGate := "a role gate"
	if c.roleEvidence != "" {
		roleGate = fmt.Sprintf("%q", c.roleEvidence)
	}
	msg := fmt.Sprintf("%s %s only requires a logged-in user, but this service also checks roles (e.g. %s). Any authenticated user can reach this sensitive endpoint; add the role gate the rest of the service uses.",
		rt.Method, rt.shownPath(), roleGate)
	return newConventionFinding(rt, RuleSensitiveRouteWithoutRole,
		"Sensitive route accepts any authenticated user",
		"Add the role or permission gate the rest of the service uses (for example RequireRole) to this route.",
		[]string{"CWE-285"}, "warning", msg)
}

func newConventionFinding(rt Route, ruleID, name, help string, cwe []string, severity, message string) *finding.Finding {
	line := rt.Line
	f := &finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		Scanner:       finding.ScannerID{Adapter: "endpoints", Tool: "endpoints"},
		Category:      finding.CatSAST,
		Rule:          finding.Rule{ID: ruleID, Name: name, Help: help, CWE: cwe},
		Severity:      finding.MapSeverity(severity),
		Confidence:    rt.Confidence,
		Message:       message,
		Location:      &finding.Location{Path: rt.File, StartLine: &line, EndLine: &line},
		BaselineState: finding.StateUnknown,
		Redaction:     finding.Redaction{Applied: true},
		Metadata: map[string]any{
			"endpoint":   rt.Method + " " + rt.Path,
			"protection": string(rt.Protection),
			"evidence":   append([]string{}, rt.Evidence...),
		},
	}
	if rt.ExternalPath != "" {
		f.Metadata["externalPath"] = rt.ExternalPath
	}
	f.Fingerprint = finding.Fingerprint{
		Algorithm: finding.FingerprintVersion,
		Value:     finding.FingerprintValue(finding.CatSAST, "endpoints", ruleID, rt.File, rt.Method+" "+rt.Path),
	}
	return f
}

func isStateChanging(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH", "DELETE", "ANY":
		return true
	}
	return false
}

func firstEvidence(rt Route) string {
	if len(rt.Evidence) == 0 {
		return ""
	}
	return rt.Evidence[0]
}

// firstRoleEvidence skips an authentication middleware in front of the role
// middleware, so rule 3 quotes the gate the developer has to copy.
func firstRoleEvidence(rt Route) string {
	for _, ev := range rt.Evidence {
		if roleRe.MatchString(ev) {
			return ev
		}
	}
	return firstEvidence(rt)
}

func addEvidence(counts map[string]int, ev string) {
	if ev != "" {
		counts[ev]++
	}
}

func mostCommon(counts map[string]int) string {
	best, bestCount := "", 0
	for ev, n := range counts {
		if n > bestCount || (n == bestCount && ev < best) {
			best, bestCount = ev, n
		}
	}
	return best
}

func sortFindings(fs []*finding.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		if *a.Location.StartLine != *b.Location.StartLine {
			return *a.Location.StartLine < *b.Location.StartLine
		}
		return a.Rule.ID < b.Rule.ID
	})
}
