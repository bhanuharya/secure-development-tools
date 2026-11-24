package endpoints

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// RouteSnapshot is the minimal persisted protection state of one route, stored
// in a baseline so pull-request scans can detect and block protection downgrades.
type RouteSnapshot struct {
	Service    string   `json:"service"`
	Method     string   `json:"method"`
	Path       string   `json:"path"`
	Protection string   `json:"protection"`
	Roles      []string `json:"roles,omitempty"`
	File       string   `json:"file,omitempty"`
	Line       int      `json:"line,omitempty"`
}

// SnapshotKey returns the canonical lookup key for a route across scans.
func SnapshotKey(service, method, path string) string {
	return service + " " + method + " " + path
}

// Snapshot projects an inventory into a map keyed by SnapshotKey, recording
// effective protection (respecting upstreamAuth declarations) with sorted roles.
func Snapshot(inv *Inventory) map[string]RouteSnapshot {
	out := map[string]RouteSnapshot{}
	if inv == nil {
		return out
	}
	for _, rt := range inv.Routes {
		eff := effective(rt)
		roles := append([]string(nil), eff.Roles...)
		sort.Strings(roles)
		key := SnapshotKey(eff.Service, eff.Method, eff.Path)
		out[key] = RouteSnapshot{
			Service:    eff.Service,
			Method:     eff.Method,
			Path:       eff.Path,
			Protection: string(eff.Protection),
			Roles:      roles,
			File:       eff.File,
			Line:       eff.Line,
		}
	}
	return out
}

// CompareProtection diffs a current inventory against a previous baseline
// snapshot and emits high-severity blocking findings whenever an existing route
// had its protection weakened or its required role set loosened.
//
// Soundness: transitions involving `unknown` are never reported as regressions
// because `unknown` represents analyzer uncertainty rather than weakened code.
func CompareProtection(prev map[string]RouteSnapshot, current *Inventory) []*finding.Finding {
	if len(prev) == 0 || current == nil || len(current.Routes) == 0 {
		return nil
	}
	clean := sanitizeInventory(current)
	var out []*finding.Finding
	for _, rt := range clean.Routes {
		eff := effective(rt)
		old, ok := prev[SnapshotKey(eff.Service, eff.Method, eff.Path)]
		if !ok {
			continue
		}
		oldProt := Protection(old.Protection)
		newProt := eff.Protection
		oldRank := ProtectionRank(oldProt)
		newRank := ProtectionRank(newProt)
		if oldRank == 0 || newRank == 0 {
			continue // never treat `unknown` as a regression
		}

		reason := ""
		switch {
		case newRank < oldRank:
			reason = fmt.Sprintf("protection weakened from %s to %s", formatProtection(oldProt, old.Roles), formatProtection(newProt, eff.Roles))
		case oldProt == ProtRole && newProt == ProtRole && roleRequirementLoosened(old.Roles, eff.Roles):
			reason = fmt.Sprintf("allowed roles widened from %s to %s", formatRoles(old.Roles), formatRoles(eff.Roles))
		default:
			continue
		}

		msg := fmt.Sprintf("%s %s regressed its access control: %s. Weakening an existing route's protection expands who can call it; restore the previous gate or record a governed exception.",
			eff.Method, eff.shownPath(), reason)
		f := newConventionFinding(eff, RuleProtectionDowngraded,
			"Route access-control protection was weakened",
			"Restore the previous authentication/role gate or document why lowering access control on this route is intentional.",
			[]string{"CWE-862"}, "error", msg)
		f.Confidence = "high"
		f.BaselineState = finding.StateNew
		f.Fingerprint = finding.Fingerprint{
			Algorithm: finding.FingerprintVersion,
			Value: finding.FingerprintValue(
				finding.CatSAST, "endpoints", RuleProtectionDowngraded,
				eff.File, fmt.Sprintf("%s %s %s %s->%s", eff.Service, eff.Method, eff.Path, oldProt, newProt),
			),
		}
		f.Metadata["previousProtection"] = string(oldProt)
		if len(old.Roles) > 0 {
			f.Metadata["previousRoles"] = append([]string(nil), old.Roles...)
		}
		out = append(out, f)
	}
	sortFindings(out)
	for i, f := range out {
		f.ID = fmt.Sprintf("endpoints:reg:%05d", i+1)
	}
	return out
}

func formatProtection(p Protection, roles []string) string {
	if p == ProtRole && len(roles) > 0 {
		return fmt.Sprintf("role (%s)", strings.Join(roles, ", "))
	}
	return string(p)
}

func formatRoles(roles []string) string {
	if len(roles) == 0 {
		return "(unspecified)"
	}
	sorted := append([]string(nil), roles...)
	sort.Strings(sorted)
	return "[" + strings.Join(sorted, ", ") + "]"
}

// roleRequirementLoosened reports whether a role-protected route widened
// access. Roles on a route mean "any of these roles is permitted", so removing
// a role (e.g. [ADMIN, USER] -> [ADMIN]) narrows access and is not a
// regression, while adding any role not previously permitted (or dropping all
// explicit roles) widens access.
func roleRequirementLoosened(oldRoles, newRoles []string) bool {
	if len(oldRoles) == 0 {
		return false
	}
	if len(newRoles) == 0 {
		return true
	}
	oldSet := map[string]bool{}
	for _, r := range oldRoles {
		oldSet[r] = true
	}
	for _, r := range newRoles {
		if !oldSet[r] {
			return true
		}
	}
	return false
}
