package endpoints

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// This file resolves Spring MVC controller annotations into routes (SPEC §5,
// Spring bullet). T04 covers what the controller declares: the class prefix,
// the method mapping and @PreAuthorize/@Secured/@RolesAllowed. The security
// configuration that decides the remaining routes is T05, so they stay unknown.

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

// resolveSpring resolves the Java facts. Kotlin is out of scope (SPEC §9), and
// Spring WebFlux uses the same annotations; the framework label stays
// spring-mvc until a WebFlux-specific difference shows up.
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

	var routes []Route
	var unresolved []string
	for _, file := range files {
		fileRoutes, fileUnresolved := resolveSpringFile(file, byFile[file], root)
		routes = append(routes, fileRoutes...)
		unresolved = append(unresolved, fileUnresolved...)
	}
	return routes, unresolved
}

// resolveSpringFile indexes one controller file by class name and method, then
// turns its route facts into routes.
func resolveSpringFile(file string, facts []Fact, root string) ([]Route, []string) {
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
		route, sentence, err := springRoute(f, prefixes[classOf(f)], classGates, methodGates, root)
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
// for routes whose protection is not in this file (T05 decides it).
func springRoute(f Fact, prefix string, classGates, methodGates map[string][]springGate, root string) (Route, string, error) {
	class, method := classOf(f), f.Metavars["$M"]
	if class == "" || method == "" {
		return Route{}, "", fmt.Errorf("controller class or handler method could not be resolved")
	}
	handler := class + "." + method
	protection, roles, evidence, confidence := springProtection(f, class, method, classGates, methodGates)
	sentence := ""
	if protection == ProtUnknown {
		sentence = fmt.Sprintf("%s:%d %s: protection decided by security configuration (T05)", f.File, f.Line, handler)
	}
	return Route{
		Service:    serviceOf(root, f.File),
		Framework:  "spring-mvc",
		Method:     springVerb(f.Metavars["$VERB"]),
		Path:       joinPaths([]string{prefix}, springPathVarRe.ReplaceAllString(f.Metavars["$PATH"], "{$1}")),
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
// class gate (Spring Security applies the most specific annotation).
func springProtection(f Fact, class, method string, classGates, methodGates map[string][]springGate) (Protection, []string, []string, string) {
	gates := methodGates[class+"."+method]
	classLevel := false
	if len(gates) == 0 {
		gates = classGates[class]
		classLevel = len(gates) > 0
	}
	if len(gates) == 0 {
		evidence := fmt.Sprintf("%s:%d no method-level security annotation; decided by security configuration (T05)", f.File, f.Line)
		return ProtUnknown, nil, []string{evidence}, "low"
	}
	return springGateDecision(gates, classLevel)
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

func springVerb(verb string) string {
	verb = strings.TrimSpace(verb)
	if verb == "" {
		return "ANY" // @RequestMapping without method=
	}
	return normalizeMethod(strings.TrimSuffix(verb, "Mapping"))
}
