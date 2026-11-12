package endpoints

import (
	"fmt"
	"strings"
)

// springRouteParam is the concrete value given to a route template parameter
// when no security pattern pins it to a literal.
const springRouteParam = "__sdt_route_param__"

// springTemplatePath reports whether a route mapping still contains a {name}
// segment, i.e. it stands for several concrete request paths.
func springTemplatePath(path string) bool { return strings.Contains(path, "{") }

// decideConcrete applies the security configuration to one concrete path.
func (cfg *springConfig) decideConcrete(path, method string) (Protection, []string, []string, string) {
	if cfg.ownershipUnknown {
		return ProtUnknown, nil, []string{"security configuration ownership cannot be established"}, "low"
	}
	if len(cfg.chains) == 0 {
		return decideSpringMatchers(cfg.matchers, path, method)
	}
	return cfg.decideChains(path, method)
}

// decideTemplate evaluates the concrete paths a template route can serve. A
// literal matcher that overlaps only part of the template decides that part,
// so the route exposes the weakest overlapping decision (SPEC §5: a permitAll
// on a concrete path a template can take makes the route public). A template
// no pattern pins is evaluated once with a placeholder parameter.
func (cfg *springConfig) decideTemplate(path, method string) (Protection, []string, []string, string) {
	firstRank := -1
	varied, chosen := false, false
	var weakest Protection
	var roles, evidence []string
	weakestPath, confidence := "", ""
	for _, witness := range cfg.routeWitnesses(path) {
		protection, witnessRoles, witnessEvidence, witnessConfidence := cfg.decideConcrete(witness, method)
		rank := protectionRank(protection)
		if firstRank < 0 {
			firstRank = rank
		} else if rank != firstRank {
			varied = true
		}
		if !chosen || rank < protectionRank(weakest) {
			weakest, roles, evidence = protection, witnessRoles, witnessEvidence
			weakestPath, confidence, chosen = witness, witnessConfidence, true
		}
	}
	if varied {
		for i := range evidence {
			evidence[i] = fmt.Sprintf("%s (path %s)", evidence[i], weakestPath)
		}
	}
	return weakest, roles, evidence, confidence
}

// routeWitnesses returns the template's generic path plus one concrete witness
// for every security pattern that overlaps it. Concrete witnesses are what
// expose a literal permitAll hidden behind a {param} segment.
func (cfg *springConfig) routeWitnesses(path string) []string {
	out := []string{springConcreteRoutePath(path)}
	seen := map[string]bool{out[0]: true}
	for _, pattern := range cfg.routePatterns() {
		witness, ok := springOverlapWitness(pattern, path)
		if !ok || seen[witness] {
			continue
		}
		seen[witness] = true
		out = append(out, witness)
	}
	return out
}

func (cfg *springConfig) routePatterns() []string {
	var out []string
	for _, m := range cfg.matchers {
		out = append(out, m.pattern)
	}
	for _, c := range cfg.chains {
		for _, scope := range c.scopes {
			out = append(out, scope.pattern)
		}
		for _, m := range c.matchers {
			out = append(out, m.pattern)
		}
	}
	return out
}

// springConcreteRoutePath replaces every template segment with a value the
// route accepts. It is the "all other paths" representative of the mapping.
func springConcreteRoutePath(path string) string {
	segments := antSegments(normalizePath(path))
	for i, segment := range segments {
		segments[i] = springConcreteSegment(segment)
	}
	if len(segments) == 0 {
		return "/"
	}
	return "/" + strings.Join(segments, "/")
}

// springOverlapWitness returns a concrete path that both the security pattern
// and the route template accept.
func springOverlapWitness(pattern, route string) (string, bool) {
	segments, ok := overlapSegments(antSegments(normalizePath(pattern)), antSegments(normalizePath(route)))
	if !ok {
		return "", false
	}
	if len(segments) == 0 {
		return "/", true
	}
	return "/" + strings.Join(segments, "/"), true
}

func overlapSegments(pattern, route []string) ([]string, bool) {
	if len(pattern) == 0 {
		return nil, len(route) == 0
	}
	if pattern[0] == "**" {
		return consumeOverlap(pattern[1:], route)
	}
	if len(route) == 0 {
		return nil, false
	}
	if route[0] == "**" {
		return consumeOverlap(route[1:], pattern)
	}
	segment, ok := overlapSegment(pattern[0], route[0])
	if !ok {
		return nil, false
	}
	tail, ok := overlapSegments(pattern[1:], route[1:])
	if !ok {
		return nil, false
	}
	return append([]string{segment}, tail...), true
}

// consumeOverlap lets a `**` on either side swallow a prefix of the other
// side, turning the swallowed pattern segments into concrete values.
func consumeOverlap(rest, other []string) ([]string, bool) {
	for k := 0; k <= len(other); k++ {
		head := make([]string, 0, k)
		for _, segment := range other[:k] {
			head = append(head, springConcreteSegment(segment))
		}
		tail, ok := overlapSegments(rest, other[k:])
		if ok {
			return append(head, tail...), true
		}
	}
	return nil, false
}

func overlapSegment(pattern, route string) (string, bool) {
	if springLiteralSegment(pattern) && antSegmentMatch(route, pattern) == antYes {
		return pattern, true
	}
	if springLiteralSegment(route) && antSegmentMatch(pattern, route) == antYes {
		return route, true
	}
	for _, candidate := range []string{springConcreteSegment(route), springConcreteSegment(pattern)} {
		if antSegmentMatch(pattern, candidate) == antYes && antSegmentMatch(route, candidate) == antYes {
			return candidate, true
		}
	}
	return "", false
}

func springLiteralSegment(segment string) bool {
	return !strings.ContainsAny(segment, "{*?")
}

// springConcreteSegment builds one concrete value for a segment pattern. It is
// best effort for exotic regex constraints; antSegmentMatch guards the answer.
func springConcreteSegment(segment string) string {
	if springLiteralSegment(segment) {
		return segment
	}
	var b strings.Builder
	for i := 0; i < len(segment); {
		switch segment[i] {
		case '{':
			end := matchingBrace(segment, i)
			if end < 0 {
				b.WriteString(springRouteParam)
				i = len(segment)
				continue
			}
			b.WriteString(springRouteParam)
			i = end + 1
		case '*', '?':
			b.WriteString("x")
			i++
		default:
			b.WriteByte(segment[i])
			i++
		}
	}
	concrete := b.String()
	if antSegmentMatch(segment, concrete) == antYes {
		return concrete
	}
	for _, fallback := range []string{"x", "1", "a", "item"} {
		if antSegmentMatch(segment, fallback) == antYes {
			return fallback
		}
	}
	return concrete
}
