package endpoints

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
	"gopkg.in/yaml.v3"
)

const (
	// RepoInvariantsFile is the repository-local declarative security contract.
	RepoInvariantsFile = ".secure-dev/invariants.yaml"

	InvariantsAPIVersion = "secure-dev/invariants/v1alpha1"
	InvariantsKind       = "SecurityInvariants"

	// RuleInvariantViolated is emitted when a route breaches a repo-declared invariant.
	RuleInvariantViolated = "scp.endpoints.invariant-violated"
)

// InvariantsDoc is the typed contract parsed from .secure-dev/invariants.yaml.
type InvariantsDoc struct {
	APIVersion       string            `yaml:"apiVersion" json:"apiVersion"`
	Kind             string            `yaml:"kind" json:"kind"`
	RouteInvariants  []RouteInvariant  `yaml:"routeInvariants,omitempty" json:"routeInvariants,omitempty"`
	DomainInvariants []DomainInvariant `yaml:"domainInvariants,omitempty" json:"domainInvariants,omitempty"`
}

// RouteInvariant declares deterministic access-control and handler contracts
// enforced on matching HTTP routes during `sdt scan` and `sdt endpoints`.
type RouteInvariant struct {
	ID                    string   `yaml:"id" json:"id"`
	Description           string   `yaml:"description,omitempty" json:"description,omitempty"`
	Service               string   `yaml:"service,omitempty" json:"service,omitempty"`
	Paths                 []string `yaml:"paths" json:"paths"`
	Methods               []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	ForbidMethods         []string `yaml:"forbidMethods,omitempty" json:"forbidMethods,omitempty"`
	MinProtection         string   `yaml:"minProtection,omitempty" json:"minProtection,omitempty"`
	FailOnUnknown         bool     `yaml:"failOnUnknown,omitempty" json:"failOnUnknown,omitempty"`
	RequireRoles          []string `yaml:"requireRoles,omitempty" json:"requireRoles,omitempty"`
	RequireEvidence       []string `yaml:"requireEvidence,omitempty" json:"requireEvidence,omitempty"`
	RequirePrincipalCheck bool     `yaml:"requirePrincipalCheck,omitempty" json:"requirePrincipalCheck,omitempty"`
	Severity              string   `yaml:"severity,omitempty" json:"severity,omitempty"`
	CWE                   []string `yaml:"cwe,omitempty" json:"cwe,omitempty"`
}

// DomainInvariant declares a semantic business-logic invariant scoped to file
// path globs, consumed by tools/sdt_review_diff.py during PR diff auditing.
type DomainInvariant struct {
	ID           string   `yaml:"id" json:"id"`
	Paths        []string `yaml:"paths" json:"paths"`
	AbuseClasses []string `yaml:"abuseClasses,omitempty" json:"abuseClasses,omitempty"`
	Statement    string   `yaml:"statement" json:"statement"`
	Severity     string   `yaml:"severity,omitempty" json:"severity,omitempty"`
}

// LoadInvariants reads and strictly validates .secure-dev/invariants.yaml under
// root. A missing file returns (nil, nil). A malformed file or unknown field
// fails closed with an error so a typo never silently disables a security contract.
func LoadInvariants(root string) (*InvariantsDoc, error) {
	if strings.TrimSpace(root) == "" {
		return nil, nil
	}
	path := filepath.Join(root, RepoInvariantsFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", RepoInvariantsFile, err)
	}
	return ParseInvariants(raw, RepoInvariantsFile)
}

// ParseInvariants parses and validates an invariants YAML document strictly
// (unknown keys fail closed).
func ParseInvariants(raw []byte, source string) (*InvariantsDoc, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var doc InvariantsDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", source, err)
	}
	if doc.APIVersion != InvariantsAPIVersion {
		return nil, fmt.Errorf("%s: unsupported apiVersion %q (want %q)", source, doc.APIVersion, InvariantsAPIVersion)
	}
	if doc.Kind != InvariantsKind {
		return nil, fmt.Errorf("%s: unsupported kind %q (want %q)", source, doc.Kind, InvariantsKind)
	}
	seen := map[string]bool{}
	for i, ri := range doc.RouteInvariants {
		if strings.TrimSpace(ri.ID) == "" {
			return nil, fmt.Errorf("%s: routeInvariants[%d] requires non-empty id", source, i)
		}
		if seen[ri.ID] {
			return nil, fmt.Errorf("%s: duplicate invariant id %q", source, ri.ID)
		}
		seen[ri.ID] = true
		if len(ri.Paths) == 0 {
			return nil, fmt.Errorf("%s: routeInvariant %q requires at least one path", source, ri.ID)
		}
		for _, p := range ri.Paths {
			if !strings.HasPrefix(p, "/") {
				return nil, fmt.Errorf("%s: routeInvariant %q path %q must start with '/'", source, ri.ID, p)
			}
		}
		if ri.MinProtection != "" {
			switch Protection(ri.MinProtection) {
			case ProtAuthenticated, ProtRole, ProtDenied:
			default:
				return nil, fmt.Errorf("%s: routeInvariant %q invalid minProtection %q (want authenticated|role|denied)", source, ri.ID, ri.MinProtection)
			}
		}
		if ri.Severity != "" && ri.Severity != "error" && ri.Severity != "warning" {
			return nil, fmt.Errorf("%s: routeInvariant %q invalid severity %q (want error|warning)", source, ri.ID, ri.Severity)
		}
		for _, ev := range ri.RequireEvidence {
			if _, err := regexp.Compile(ev); err != nil {
				return nil, fmt.Errorf("%s: routeInvariant %q invalid requireEvidence regex %q: %w", source, ri.ID, ev, err)
			}
		}
	}
	for i, di := range doc.DomainInvariants {
		if strings.TrimSpace(di.ID) == "" {
			return nil, fmt.Errorf("%s: domainInvariants[%d] requires non-empty id", source, i)
		}
		if seen[di.ID] {
			return nil, fmt.Errorf("%s: duplicate invariant id %q", source, di.ID)
		}
		seen[di.ID] = true
		if len(di.Paths) == 0 {
			return nil, fmt.Errorf("%s: domainInvariant %q requires at least one path", source, di.ID)
		}
		if strings.TrimSpace(di.Statement) == "" {
			return nil, fmt.Errorf("%s: domainInvariant %q requires a statement", source, di.ID)
		}
	}
	return &doc, nil
}

// EvaluateInvariants checks every RouteInvariant against matching routes in inv
// and emits high-confidence findings for any violation.
func EvaluateInvariants(root string, inv *Inventory, doc *InvariantsDoc) []*finding.Finding {
	if doc == nil || len(doc.RouteInvariants) == 0 || inv == nil || len(inv.Routes) == 0 {
		return nil
	}
	absRoot := ""
	if strings.TrimSpace(root) != "" {
		if abs, err := filepath.Abs(root); err == nil {
			if resolved, rerr := filepath.EvalSymlinks(abs); rerr == nil {
				absRoot = resolved
			} else {
				absRoot = abs
			}
		}
	}
	clean := sanitizeInventory(inv)
	var out []*finding.Finding

	for _, ri := range doc.RouteInvariants {
		evRegexes := make([]*regexp.Regexp, 0, len(ri.RequireEvidence))
		for _, expr := range ri.RequireEvidence {
			if re, err := regexp.Compile(expr); err == nil {
				evRegexes = append(evRegexes, re)
			}
		}
		for _, rt := range clean.Routes {
			eff := effective(rt)
			if !ri.matchesRoute(eff) {
				continue
			}
			reasons := ri.violations(absRoot, eff, evRegexes)
			if len(reasons) == 0 {
				continue
			}
			out = append(out, invariantFinding(ri, eff, reasons))
		}
	}
	sortFindings(out)
	return out
}

func (ri RouteInvariant) matchesRoute(rt Route) bool {
	if ri.Service != "" && ri.Service != "*" && ri.Service != rt.Service {
		return false
	}
	if len(ri.Methods) > 0 && !methodInList(rt.Method, ri.Methods) {
		return false
	}
	for _, p := range ri.Paths {
		if antMatchResult(normalizePath(p), rt.Path) == antYes {
			return true
		}
	}
	return false
}

func (ri RouteInvariant) violations(absRoot string, rt Route, evRegexes []*regexp.Regexp) []string {
	var reasons []string

	if len(ri.ForbidMethods) > 0 && methodInList(rt.Method, ri.ForbidMethods) {
		reasons = append(reasons, fmt.Sprintf("HTTP method %s is forbidden by invariant %q", rt.Method, ri.ID))
	}

	if ri.MinProtection != "" {
		want := Protection(ri.MinProtection)
		if rt.Protection == ProtUnknown {
			if ri.FailOnUnknown {
				reasons = append(reasons, fmt.Sprintf("protection is unknown, but invariant %q requires at least %s (failOnUnknown=true)", ri.ID, want))
			}
		} else if ProtectionRank(rt.Protection) < ProtectionRank(want) {
			reasons = append(reasons, fmt.Sprintf("protection is %s, weaker than required %s", rt.Protection, want))
		}
	}

	if len(ri.RequireRoles) > 0 && rt.Protection != ProtDenied {
		if rt.Protection == ProtUnknown {
			if ri.FailOnUnknown {
				reasons = append(reasons, fmt.Sprintf("protection is unknown, cannot verify required roles %s", formatRoles(ri.RequireRoles)))
			}
		} else if rt.Protection != ProtRole {
			reasons = append(reasons, fmt.Sprintf("requires role in %s, but route protection is %s", formatRoles(ri.RequireRoles), rt.Protection))
		} else if len(rt.Roles) > 0 && !hasAnyRole(rt.Roles, ri.RequireRoles) {
			reasons = append(reasons, fmt.Sprintf("route roles %s do not satisfy required roles %s", formatRoles(rt.Roles), formatRoles(ri.RequireRoles)))
		}
	}

	if len(evRegexes) > 0 && rt.Protection != ProtDenied {
		joined := strings.Join(rt.Evidence, "\n") + "\n" + rt.UpstreamAuth
		for i, re := range evRegexes {
			if !re.MatchString(joined) {
				reasons = append(reasons, fmt.Sprintf("missing required guard/evidence matching %q", ri.RequireEvidence[i]))
			}
		}
	}

	if ri.RequirePrincipalCheck && absRoot != "" && rt.Protection != ProtDenied && rt.Protection != ProtRole {
		if len(objectPathParams(rt.Path)) > 0 {
			if body, _, ok := extractHandlerBody(absRoot, rt); ok && strings.TrimSpace(body) != "" {
				if !hasPrincipalOrOwnershipCheck(body) {
					reasons = append(reasons, "handler does not reference authenticated caller, owner, or tenant identity")
				}
			}
		}
	}

	return reasons
}

func invariantFinding(ri RouteInvariant, rt Route, reasons []string) *finding.Finding {
	sev := ri.Severity
	if sev == "" {
		sev = "error"
	}
	cwes := ri.CWE
	if len(cwes) == 0 {
		cwes = []string{"CWE-862"}
	}
	desc := ""
	if strings.TrimSpace(ri.Description) != "" {
		desc = " (" + strings.TrimSpace(ri.Description) + ")"
	}
	msg := fmt.Sprintf("%s %s violates security invariant %q%s: %s.",
		rt.Method, rt.shownPath(), ri.ID, desc, strings.Join(reasons, "; "))
	f := newConventionFinding(rt, RuleInvariantViolated,
		"Route violates repository security invariant",
		fmt.Sprintf("Update the route or handler to satisfy invariant %q in %s.", ri.ID, RepoInvariantsFile),
		cwes, sev, msg)
	f.Confidence = "high"
	f.Fingerprint = finding.Fingerprint{
		Algorithm: finding.FingerprintVersion,
		Value: finding.FingerprintValue(
			finding.CatSAST, "endpoints", RuleInvariantViolated,
			rt.File, fmt.Sprintf("%s %s %s %s", ri.ID, rt.Service, rt.Method, rt.Path),
		),
	}
	f.Metadata["invariantId"] = ri.ID
	f.Metadata["violations"] = reasons
	return f
}

func methodInList(method string, list []string) bool {
	m := strings.ToUpper(strings.TrimSpace(method))
	for _, item := range list {
		if strings.ToUpper(strings.TrimSpace(item)) == m {
			return true
		}
	}
	return false
}

func hasAnyRole(routeRoles, required []string) bool {
	req := map[string]bool{}
	for _, r := range required {
		req[strings.ToLower(strings.TrimSpace(r))] = true
	}
	for _, r := range routeRoles {
		if req[strings.ToLower(strings.TrimSpace(r))] {
			return true
		}
	}
	return false
}
