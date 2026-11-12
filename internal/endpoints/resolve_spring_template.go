package endpoints

import (
	"fmt"
	"strconv"
	"strings"
)

// springRouteParam is the concrete value given to a route template parameter
// when no security pattern pins it to a literal.
const springRouteParam = "__sdt_route_param__"

// springTemplatePath reports whether a route mapping still contains a {name}
// segment, i.e. it stands for several concrete request paths.
func springTemplatePath(path string) bool { return strings.Contains(path, "{") }

// decideConcrete applies the security configuration to one concrete path.
func (cfg *springConfig) decideConcrete(path, method string) (Protection, []string, []string, string, string) {
	if protection, roles, evidence, confidence, ok := cfg.decideIgnored(path, method); ok {
		return protection, roles, evidence, confidence, ""
	}
	if len(cfg.ignoredUnknown) > 0 {
		return ProtUnknown, nil, []string{cfg.ignoredUnknown[0]}, "low", cfg.ignoredUnknown[0]
	}
	if cfg.ownershipUnknown {
		return ProtUnknown, nil, []string{"security configuration ownership cannot be established"}, "low", cfg.ownershipNote
	}
	if len(cfg.chains) == 0 {
		return decideSpringMatchers(cfg.matchers, path, method)
	}
	return cfg.decideChains(path, method)
}

// decideIgnored reports whether the path bypasses the security filter chain.
func (cfg *springConfig) decideIgnored(path, method string) (Protection, []string, []string, string, bool) {
	for _, ignored := range cfg.ignored {
		if ignored.method != "" && ignored.method != method {
			continue
		}
		switch antMatchResult(normalizePath(ignored.pattern), path) {
		case antYes:
			return ProtPublic, nil, []string{ignored.evidence() + " (bypasses the security filter chain)"}, "high", true
		case antUnknown:
			return ProtUnknown, nil, []string{ignored.evidence() + " (constraint cannot be evaluated)"}, "low", true
		}
	}
	return "", nil, nil, "", false
}

// decideTemplate evaluates the concrete paths a template route can serve. A
// literal matcher that overlaps only part of the template decides that part,
// so the route exposes the weakest overlapping decision (SPEC §5: a permitAll
// on a concrete path a template can take makes the route public). When an
// overlap cannot be sampled, the answer stays unknown instead of protected.
func (cfg *springConfig) decideTemplate(path, method string) (Protection, []string, []string, string, string) {
	witnesses, uncertain := cfg.routeWitnesses(path, method)
	firstRank := -1
	varied, chosen := false, false
	var weakest Protection
	var roles, evidence []string
	weakestPath, confidence, note := "", "", ""
	for _, witness := range witnesses {
		protection, witnessRoles, witnessEvidence, witnessConfidence, witnessNote := cfg.decideConcrete(witness, method)
		rank := protectionRank(protection)
		if firstRank < 0 {
			firstRank = rank
		} else if rank != firstRank {
			varied = true
		}
		if !chosen || rank < protectionRank(weakest) {
			weakest, roles, evidence = protection, witnessRoles, witnessEvidence
			weakestPath, confidence, chosen = witness, witnessConfidence, true
			note = witnessNote
		}
	}
	if len(uncertain) > 0 && protectionRank(weakest) > protectionRank(ProtUnknown) {
		return ProtUnknown, nil, []string{uncertain[0] + ": overlap with the route template cannot be evaluated"}, "low",
			uncertain[0] + " may apply to this route template and cannot be evaluated"
	}
	if varied {
		for i := range evidence {
			evidence[i] = fmt.Sprintf("%s (path %s)", evidence[i], weakestPath)
		}
	}
	return weakest, roles, evidence, confidence, note
}

// routeWitnesses returns the template's generic path plus concrete witnesses
// for every security pattern that can overlap it. A pattern whose overlap
// cannot be sampled is reported as uncertain rather than assumed protected.
func (cfg *springConfig) routeWitnesses(path, method string) ([]string, []string) {
	out := []string{springConcreteRoutePath(path)}
	seen := map[string]bool{out[0]: true}
	var uncertain []string
	for _, m := range cfg.matcherPatterns() {
		candidates := springOverlapCandidates(m.pattern, path)
		if len(candidates) == 0 {
			continue
		}
		reached := false
		for _, witness := range candidates {
			if !seen[witness] {
				seen[witness] = true
				out = append(out, witness)
			}
			if m.name == "anyRequest" || m.name == "anyExchange" ||
				cfg.witnessNamesPattern(witness, method, m.pattern) {
				reached = true
			}
		}
		if !reached && !cfg.patternCovered(m, method) && !cfg.earlierCoversRoute(m, path, method) {
			uncertain = append(uncertain, fmt.Sprintf("%s:%d matcher %s", m.file, m.line, strconv.Quote(m.pattern)))
		}
	}
	for _, pattern := range append(cfg.scopePatterns(), cfg.ignoredPatterns()...) {
		for _, witness := range springOverlapCandidates(pattern, path) {
			if !seen[witness] {
				seen[witness] = true
				out = append(out, witness)
			}
		}
	}
	return out, uncertain
}

func (cfg *springConfig) matcherPatterns() []springMatcher {
	out := append([]springMatcher{}, cfg.matchers...)
	for _, c := range cfg.chains {
		out = append(out, c.matchers...)
	}
	return out
}

func (cfg *springConfig) scopePatterns() []string {
	var out []string
	for _, c := range cfg.chains {
		for _, scope := range c.scopes {
			out = append(out, scope.patterns...)
		}
	}
	return out
}

func (cfg *springConfig) ignoredPatterns() []string {
	out := make([]string, 0, len(cfg.ignored))
	for _, ignored := range cfg.ignored {
		out = append(out, ignored.pattern)
	}
	return out
}

// witnessNamesPattern reports whether a witness is decided by the matcher that
// produced it rather than by an earlier rule.
func (cfg *springConfig) witnessNamesPattern(witness, method, pattern string) bool {
	_, _, evidence, _, _ := cfg.decideConcrete(witness, method)
	for _, entry := range evidence {
		if strings.Contains(entry, strconv.Quote(pattern)) {
			return true
		}
	}
	return false
}

// patternCovered reports whether another matcher provably covers the whole
// pattern, in which case its own decision cannot change any path.
func (cfg *springConfig) patternCovered(target springMatcher, method string) bool {
	for _, m := range cfg.matcherPatterns() {
		if m.pattern == target.pattern || m.unknown || m.name == "anyRequest" || m.name == "anyExchange" {
			continue
		}
		if m.method != "" && m.method != method {
			continue
		}
		if springAntCovers(m.pattern, target.pattern) {
			return true
		}
	}
	return false
}

// earlierCoversRoute reports whether a matcher before target already covers
// the whole route template, so target can never decide any of its paths.
func (cfg *springConfig) earlierCoversRoute(target springMatcher, route, method string) bool {
	for _, m := range cfg.matcherPatterns() {
		if m.file == target.file && m.line == target.line && m.column == target.column && m.pattern == target.pattern {
			return false
		}
		if m.method != "" && m.method != method {
			continue
		}
		if m.unknown || m.name == "anyRequest" || m.name == "anyExchange" {
			continue
		}
		if springAntCovers(m.pattern, route) {
			return true
		}
	}
	return false
}

// springOverlapCandidates builds concrete paths for every segment shape the
// pattern and the route template share, so a wildcard pattern that is partly
// shadowed by an earlier literal still gets a witness of its own.
func springOverlapCandidates(pattern, route string) []string {
	p, r := antSegments(normalizePath(pattern)), antSegments(normalizePath(route))
	for _, segment := range append(append([]string{}, p...), r...) {
		if segment == "**" {
			if witness, ok := springOverlapWitness(pattern, route); ok {
				return []string{witness}
			}
			return nil
		}
	}
	if len(p) != len(r) {
		if witness, ok := springOverlapWitness(pattern, route); ok {
			return []string{witness}
		}
		return nil
	}
	combos := [][]string{{}}
	for i := range p {
		var allowed []string
		for _, candidate := range springSegmentCandidates(p[i]) {
			if antSegmentMatch(r[i], candidate) == antYes {
				allowed = append(allowed, candidate)
			}
		}
		if len(allowed) == 0 {
			if witness, ok := springOverlapWitness(pattern, route); ok {
				return []string{witness}
			}
			return nil
		}
		combos = springCombinations(combos, allowed, 24)
	}
	out := make([]string, 0, len(combos))
	for _, segments := range combos {
		out = append(out, "/"+strings.Join(segments, "/"))
	}
	return out
}

func springSegmentCandidates(segment string) []string {
	if !strings.ContainsAny(segment, "*?{") {
		return []string{segment}
	}
	out := []string{springConcreteSegment(segment)}
	for _, fill := range []string{"", "x", "a", "b", "1", "ab", "42", "item", "zz"} {
		candidate := springFillSegment(segment, fill)
		if candidate == "" || containsString(out, candidate) {
			continue
		}
		if antSegmentMatch(segment, candidate) == antYes {
			out = append(out, candidate)
		}
	}
	return out
}

// springFillSegment substitutes every wildcard or placeholder with fill.
func springFillSegment(segment, fill string) string {
	var b strings.Builder
	for i := 0; i < len(segment); {
		switch segment[i] {
		case '{':
			end := matchingBrace(segment, i)
			if end < 0 {
				return ""
			}
			b.WriteString(fill)
			i = end + 1
		case '*', '?':
			b.WriteString(fill)
			i++
		default:
			b.WriteByte(segment[i])
			i++
		}
	}
	return b.String()
}

func springCombinations(prefix [][]string, values []string, limit int) [][]string {
	out := make([][]string, 0, len(prefix)*len(values))
	for _, head := range prefix {
		for _, value := range values {
			if len(out) >= limit {
				return out
			}
			next := append(append([]string{}, head...), value)
			out = append(out, next)
		}
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// springAntCovers reports whether every path matched by target is matched by
// cover. Only shapes the resolver can prove are accepted; anything else is
// false so the caller stays unknown instead of guessing.
func springAntCovers(cover, target string) bool {
	return springSegmentsCover(antSegments(normalizePath(cover)), antSegments(normalizePath(target)))
}

func springSegmentsCover(cover, target []string) bool {
	if len(cover) == 0 {
		return len(target) == 0
	}
	if cover[0] == "**" {
		for k := 0; k <= len(target); k++ {
			if springSegmentsCover(cover[1:], target[k:]) {
				return true
			}
		}
		return false
	}
	if len(target) == 0 || target[0] == "**" {
		return false
	}
	if !springSegmentCovers(cover[0], target[0]) {
		return false
	}
	return springSegmentsCover(cover[1:], target[1:])
}

func springSegmentCovers(cover, target string) bool {
	if cover == target {
		return true
	}
	if cover == "*" {
		return !strings.Contains(target, "/")
	}
	if !strings.ContainsAny(cover, "*?{") || strings.ContainsAny(target, "*?{") {
		return false
	}
	return antSegmentMatch(cover, target) == antYes
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
