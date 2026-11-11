package endpoints

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Default gate list from SPEC §5; config overrides arrive in T08.
var (
	gateRe   = regexp.MustCompile(`(?i)(auth|jwt|bearer|token|protect|guard|session|login|verify|permission|rbac|acl|role|admin|require)`)
	roleRe   = regexp.MustCompile(`(?i)(role|authority|adminonly|admin_only|admin-only)`)
	quotedRe = regexp.MustCompile(`"([^"]+)"`)
	colonRe  = regexp.MustCompile(`(^|/):([A-Za-z_][A-Za-z0-9_]*)`)
	angleRe  = regexp.MustCompile(`<[^>]*>`)
	slashRe  = regexp.MustCompile(`/{2,}`)
)

type factKey struct {
	file string
	line int
}

// resolveGo turns Go fact rules into routes. T02 covers gin flat routes;
// groups, Use, echo/fiber/chi/nethttp arrive in T03. Same-file resolution
// only: middleware attached in another file is invisible here by design and
// will surface as `unknown` in those tasks.
func resolveGo(facts []Fact, root string) ([]Route, []string) {
	routes := map[factKey]Fact{}
	middleware := map[factKey][]string{}
	for _, f := range facts {
		k := factKey{f.File, f.Line}
		switch f.Kind {
		case "route":
			routes[k] = f
		case "route_middleware":
			if mw := f.Metavars["$MW"]; mw != "" {
				middleware[k] = append(middleware[k], mw)
			}
		}
	}

	keys := make([]factKey, 0, len(routes))
	for k := range routes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].file != keys[j].file {
			return keys[i].file < keys[j].file
		}
		return keys[i].line < keys[j].line
	})

	var out []Route
	var unresolved []string
	for _, k := range keys {
		f := routes[k]
		method := strings.ToUpper(strings.TrimSpace(f.Metavars["$METHOD"]))
		if method == "" {
			// gin's Handle carries the verb as its first argument.
			method = strings.ToUpper(strings.Trim(strings.TrimSpace(f.Metavars["$VERB"]), `"`))
		}
		path := normalizePath(f.Metavars["$PATH"])
		if method == "" || !strings.HasPrefix(path, "/") {
			unresolved = append(unresolved, fmt.Sprintf("%s:%d route could not be resolved (method %q, path %q)", k.file, k.line, method, path))
			continue
		}
		prot, roles, evidence := protectionOf(k, middleware[k])
		out = append(out, Route{
			Service:    serviceOf(root, k.file),
			Framework:  "gin",
			Method:     method,
			Path:       path,
			Handler:    f.Metavars["$HANDLER"],
			File:       k.file,
			Line:       k.line,
			Protection: prot,
			Roles:      roles,
			Evidence:   evidence,
			Confidence: "high",
		})
	}
	return out, unresolved
}

// protectionOf decides one route from its own middleware chain. The first
// matching gate names the protection; role wins over plain authentication
// because it is the stricter claim (and the one a convention check needs).
func protectionOf(k factKey, middleware []string) (Protection, []string, []string) {
	var evidence []string
	var roles []string
	role := false
	authenticated := false
	for _, mw := range middleware {
		if !gateRe.MatchString(mw) {
			continue
		}
		authenticated = true
		evidence = append(evidence, fmt.Sprintf("%s:%d middleware %s", k.file, k.line, mw))
		if roleRe.MatchString(mw) {
			role = true
			for _, m := range quotedRe.FindAllStringSubmatch(mw, -1) {
				roles = append(roles, m[1])
			}
		}
	}
	if role {
		if len(roles) == 0 && strings.Contains(strings.ToLower(strings.Join(middleware, " ")), "admin") {
			roles = []string{"admin"}
		}
		return ProtRole, dedupe(roles), evidence
	}
	if authenticated {
		return ProtAuthenticated, nil, evidence
	}
	evidence = append(evidence, fmt.Sprintf("%s:%d no gate middleware on the route", k.file, k.line))
	for _, mw := range middleware {
		evidence = append(evidence, fmt.Sprintf("%s:%d middleware %s (does not match the gate list)", k.file, k.line, mw))
	}
	return ProtPublic, nil, evidence
}

// normalizePath applies SPEC §4: one slash between parts; `:id`, `{id}` and
// `<int:id>` all become `{id}`; no trailing slash except for "/".
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = colonRe.ReplaceAllString(p, "$1{$2}")
	p = angleRe.ReplaceAllStringFunc(p, func(m string) string {
		name := strings.Trim(m, "<>")
		if i := strings.LastIndex(name, ":"); i >= 0 {
			name = name[i+1:]
		}
		return "{" + name + "}"
	})
	p = slashRe.ReplaceAllString(p, "/")
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// serviceOf returns the directory of the nearest go.mod at or above the file,
// relative to the scanned root ("." for the root service).
func serviceOf(root, file string) string {
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(root, dir, "go.mod")); err == nil {
			dir = filepath.ToSlash(filepath.Clean(dir))
			if dir == "" {
				return "."
			}
			return dir
		}
		if dir == "." || dir == "" || dir == string(filepath.Separator) {
			return "."
		}
		dir = filepath.Dir(dir)
	}
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
