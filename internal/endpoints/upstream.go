package endpoints

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"gopkg.in/yaml.v3"
)

// RepoEndpointsFile is where a repository declares, next to its exceptions, which of its
// routes another component authenticates before they reach the service.
const RepoEndpointsFile = ".secure-dev/endpoints.yaml"

type upstreamDecl struct {
	config.UpstreamAuth
	source string // where it was declared, for the evidence line
}

// upstreamDecls joins the scan configuration's declarations and the repository's own file.
// A file that cannot be read or holds an invalid entry is reported, not fatal: the routes
// then keep their own protection.
func upstreamDecls(root string, cfg config.EndpointsCfg) ([]upstreamDecl, []string) {
	var out []upstreamDecl
	for _, u := range cfg.UpstreamAuth {
		out = append(out, upstreamDecl{u, "scan configuration endpoints.upstreamAuth"})
	}
	raw, err := os.ReadFile(filepath.Join(root, RepoEndpointsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, []string{fmt.Sprintf("%s: not read: %v", RepoEndpointsFile, err)}
	}
	var doc struct {
		UpstreamAuth []config.UpstreamAuth `yaml:"upstreamAuth"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return out, []string{fmt.Sprintf("%s: not applied: %v", RepoEndpointsFile, err)}
	}
	var notes []string
	for i, u := range doc.UpstreamAuth {
		if strings.TrimSpace(u.By) == "" {
			notes = append(notes, fmt.Sprintf("%s: upstreamAuth[%d] not applied: \"by\" must say who authenticates the routes",
				RepoEndpointsFile, i))
			continue
		}
		out = append(out, upstreamDecl{u, RepoEndpointsFile})
	}
	return out, notes
}

// applyUpstreamAuth marks the routes a declaration covers. Protection keeps what the service
// itself enforces (reachable inside the network without the gateway); the analysis treats a
// covered public route as authenticated.
func applyUpstreamAuth(routes []Route, decls []upstreamDecl) []Route {
	for i, rt := range routes {
		for _, d := range decls {
			if !d.covers(rt) {
				continue
			}
			routes[i].UpstreamAuth = d.By
			routes[i].Evidence = append(append([]string{}, rt.Evidence...),
				fmt.Sprintf("%s: authenticated upstream by %s", d.source, d.By))
			break
		}
	}
	return routes
}

func (d upstreamDecl) covers(rt Route) bool {
	if d.Service != "" && d.Service != "*" && d.Service != rt.Service {
		return false
	}
	if len(d.Paths) == 0 {
		return true
	}
	for _, p := range d.Paths {
		if antMatchResult(normalizePath(p), rt.Path) == antYes {
			return true
		}
	}
	return false
}

// effective is the protection the convention rules judge: a public route that a declared
// upstream component authenticates counts as authenticated.
func effective(rt Route) Route {
	if rt.UpstreamAuth != "" && rt.Protection == ProtPublic {
		rt.Protection = ProtAuthenticated
	}
	return rt
}
