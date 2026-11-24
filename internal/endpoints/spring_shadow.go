package endpoints

import (
	"fmt"
	"sort"
	"strings"
)

// shadowedBy reports whether an earlier stricter single-wildcard (`*`) Ant
// matcher or chain scope missed this route only because `*` matches a single
// path segment rather than nested subpaths (`**`).
//
// Example: `.antMatchers("/api/admin/*").hasRole("ADMIN")` followed by
// `.anyRequest().authenticated()` leaves `/api/admin/users/export` at
// `authenticated` instead of `role`.
func (cfg *springConfig) shadowedBy(path, method string, actual Protection) string {
	if cfg == nil || ProtectionRank(actual) == 0 || actual == ProtDenied {
		return ""
	}
	probe := sampleConcretePath(path)
	if len(cfg.chains) == 0 {
		return firstShadowingMatcher(cfg.matchers, probe, method, actual)
	}

	var matching []*springChain
	for _, c := range cfg.chains {
		switch c.scopeMatch(method, probe) {
		case antNo:
			continue
		case antUnknown:
			return ""
		default:
			matching = append(matching, c)
		}
	}
	if len(matching) == 0 {
		// No chain matched the route; check if a chain scope used single `*`
		// where `**` would have captured and protected the route more strictly.
		for _, c := range cfg.chains {
			if ev := chainScopeShadow(c, probe, method, actual); ev != "" {
				return ev
			}
		}
		return ""
	}
	sort.SliceStable(matching, func(i, j int) bool { return chainBefore(matching[i], matching[j]) })
	if len(matching) > 1 && !chainOrderIsDecidable(matching[0], matching[1]) {
		return ""
	}
	return firstShadowingMatcher(matching[0].matchers, probe, method, actual)
}

func firstShadowingMatcher(matchers []springMatcher, probe, method string, actual Protection) string {
	actualRank := ProtectionRank(actual)
	for _, m := range matchers {
		res := matcherMatchForVerb(m, method, probe)
		if res == antYes || res == antUnknown {
			// Reached the deciding (or undecidable) matcher; nothing after it
			// could have shadowed this route.
			break
		}
		if m.unknown || m.name == "anyRequest" || m.name == "anyExchange" {
			continue
		}
		if m.method != "" && method != "ANY" && m.method != method {
			continue
		}
		norm := normalizePath(m.pattern)
		if !hasSingleStarSegment(norm) {
			continue
		}
		if antMatchResult(deepenSingleStar(norm), probe) != antYes {
			continue
		}
		mProt, _, _ := m.decision()
		if ProtectionRank(mProt) > actualRank {
			return m.evidence()
		}
	}
	return ""
}

func matcherMatchForVerb(m springMatcher, method, probe string) antResult {
	if method == "ANY" {
		// An ANY route matches a matcher only if the matcher is method-agnostic.
		if m.method != "" {
			return antNo
		}
		return m.matchResult("GET", probe)
	}
	return m.matchResult(method, probe)
}

func chainScopeShadow(c *springChain, probe, method string, actual Protection) string {
	for _, sc := range c.scopes {
		if sc.negated {
			continue
		}
		if sc.method != "" && method != "ANY" && sc.method != method {
			continue
		}
		for _, pat := range sc.allPatterns() {
			norm := normalizePath(pat)
			if !hasSingleStarSegment(norm) {
				continue
			}
			if antMatchResult(deepenSingleStar(norm), probe) != antYes {
				continue
			}
			// Would this chain's matchers protect the route more strictly?
			prot, _, _, _, _ := decideSpringMatchers(c.matchers, probe, concreteVerb(method))
			if ProtectionRank(prot) > ProtectionRank(actual) {
				return fmt.Sprintf("%s:%d security chain %s", c.file, c.line, sc.describe())
			}
		}
	}
	return ""
}

func concreteVerb(method string) string {
	if method == "ANY" || method == "" {
		return "GET"
	}
	return method
}

// sampleConcretePath replaces `{param}` template segments with a concrete value
// so Ant depth comparisons (`*` vs `**`) work uniformly on parameterized paths.
func sampleConcretePath(path string) string {
	segs := antSegments(path)
	if len(segs) == 0 {
		return "/"
	}
	for i, s := range segs {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			segs[i] = "sample"
		}
	}
	return "/" + strings.Join(segs, "/")
}

// hasSingleStarSegment reports whether pattern contains a standalone `*`
// segment (not `**`), e.g. `/api/admin/*` or `/api/*/settings`.
func hasSingleStarSegment(pattern string) bool {
	for _, seg := range antSegments(pattern) {
		if seg == "*" {
			return true
		}
	}
	return false
}

// deepenSingleStar replaces standalone `*` segments with `**` to test whether a
// single-wildcard matcher was meant to cover nested subpaths.
func deepenSingleStar(pattern string) string {
	segs := antSegments(pattern)
	for i, seg := range segs {
		if seg == "*" {
			segs[i] = "**"
		}
	}
	return "/" + strings.Join(segs, "/")
}
