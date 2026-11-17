package endpoints

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Spring Boot serves a controller's routes under a prefix set in configuration, not in code:
// server.servlet.context-path (server.context-path before Boot 2) plus spring.mvc.servlet.path
// for Spring MVC, spring.webflux.base-path for WebFlux. Security matchers and the findings'
// fingerprints use the path inside the application, so Route.Path keeps that path and the
// served path goes to Route.ExternalPath.

var (
	mvcBaseKeys     = []string{"server.servlet.context-path", "server.context-path"}
	mvcServletKeys  = []string{"spring.mvc.servlet.path"}
	webfluxBaseKeys = []string{"spring.webflux.base-path"}
	// application-<profile>.yml|yaml|properties
	springProfileFile = regexp.MustCompile(`^application-([\w.-]+)\.(?:ya?ml|properties)$`)
	springPlaceholder = regexp.MustCompile(`^\$\{([^:}]+)(?::([^}]*))?\}$`)
	springConfigSkip  = map[string]bool{"node_modules": true, "target": true, "build": true, ".git": true,
		"test": true, "tests": true, "vendor": true, "dist": true}
)

// springBase is what one service's configuration says about its prefix.
type springBase struct {
	mvc, webflux string   // prefixes to put before Route.Path ("" when none)
	notes        []string // Unresolved sentences: placeholders, profiles that differ, conflicting files
}

// applyBasePaths sets ExternalPath on Spring routes whose service configures a prefix.
func applyBasePaths(root string, routes []Route) ([]Route, []string) {
	bases := map[string]springBase{}
	var notes []string
	for i, rt := range routes {
		if !strings.HasPrefix(rt.Framework, "spring") {
			continue
		}
		base, seen := bases[rt.Service]
		if !seen {
			base = readSpringBase(root, rt.Service)
			bases[rt.Service] = base
			notes = append(notes, base.notes...)
		}
		prefix := base.mvc
		if rt.Framework == "spring-webflux" {
			prefix = base.webflux
		}
		if prefix != "" {
			routes[i].ExternalPath = joinPaths([]string{prefix}, rt.Path)
		}
	}
	return routes, notes
}

// readSpringBase reads the service's base configuration files (application.yml, .yaml or
// .properties, outside test and build trees). Profile files only add a note when they set a
// different prefix: which profile runs is not known here.
func readSpringBase(root, service string) springBase {
	dir := filepath.Join(root, service)
	var base, profiles []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != dir && springConfigSkip[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		switch name := d.Name(); {
		case name == "application.yml" || name == "application.yaml" || name == "application.properties":
			base = append(base, path)
		case springProfileFile.MatchString(name):
			profiles = append(profiles, path)
		}
		return nil
	})
	sort.Strings(base)
	sort.Strings(profiles)
	rel := func(path string) string {
		if r, err := filepath.Rel(root, path); err == nil {
			return filepath.ToSlash(r)
		}
		return path
	}

	var out springBase
	mvcFrom, webfluxFrom := "", ""
	for _, file := range base {
		values := readSpringValues(file)
		if mvc, ok, note := springPrefix(values, mvcBaseKeys, mvcServletKeys, rel(file)); note != "" {
			out.notes = append(out.notes, note)
		} else if ok {
			if mvcFrom != "" && mvc != out.mvc {
				out.notes = append(out.notes, fmt.Sprintf("%s sets context path %q, %s sets %q; %s is used",
					mvcFrom, out.mvc, rel(file), mvc, mvcFrom))
			} else if mvcFrom == "" {
				out.mvc, mvcFrom = mvc, rel(file)
			}
		}
		if wf, ok, note := springPrefix(values, webfluxBaseKeys, nil, rel(file)); note != "" {
			out.notes = append(out.notes, note)
		} else if ok && webfluxFrom == "" {
			out.webflux, webfluxFrom = wf, rel(file)
		}
	}
	for _, file := range profiles {
		values := readSpringValues(file)
		profile := springProfileFile.FindStringSubmatch(filepath.Base(file))[1]
		if mvc, ok, _ := springPrefix(values, mvcBaseKeys, mvcServletKeys, rel(file)); ok && mvc != out.mvc {
			out.notes = append(out.notes, fmt.Sprintf("%s: profile %q serves the routes under %q instead of %q",
				rel(file), profile, orRoot(mvc), orRoot(out.mvc)))
		}
		if wf, ok, _ := springPrefix(values, webfluxBaseKeys, nil, rel(file)); ok && wf != out.webflux {
			out.notes = append(out.notes, fmt.Sprintf("%s: profile %q serves the routes under %q instead of %q",
				rel(file), profile, orRoot(wf), orRoot(out.webflux)))
		}
	}
	return out
}

// springPrefix joins the first set key of each list. ok is false when no key is set; a value
// that is a placeholder without a default gives a note and no prefix.
func springPrefix(values map[string]string, first, second []string, file string) (string, bool, string) {
	prefix, set := "", false
	for _, keys := range [][]string{first, second} {
		for _, key := range keys {
			raw, found := values[key]
			if !found {
				continue
			}
			value, resolved := resolveSpringPlaceholder(raw)
			if !resolved {
				return "", false, fmt.Sprintf("%s: %s is %s; served paths are not shown", file, key, raw)
			}
			prefix, set = joinPaths([]string{prefix}, value), true
			break
		}
	}
	if prefix == "/" {
		prefix = ""
	}
	return prefix, set, ""
}

// resolveSpringPlaceholder returns the default of ${NAME:default}; ${NAME} cannot be resolved.
func resolveSpringPlaceholder(raw string) (string, bool) {
	value := strings.TrimSpace(strings.Trim(strings.TrimSpace(raw), `"'`))
	if m := springPlaceholder.FindStringSubmatch(value); m != nil {
		if m[2] == "" && !strings.Contains(value, ":") {
			return "", false
		}
		value = m[2]
	}
	if strings.Contains(value, "${") {
		return "", false
	}
	return value, true
}

// readSpringValues flattens a properties file or the base document(s) of a YAML file into
// dotted keys. YAML documents that activate on a profile are skipped.
func readSpringValues(file string) map[string]string {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	values := map[string]string{}
	if strings.HasSuffix(file, ".properties") {
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || line[0] == '#' || line[0] == '!' {
				continue
			}
			if i := strings.IndexAny(line, "=:"); i > 0 {
				values[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
			}
		}
		return values
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	for {
		var doc map[string]any
		if err := decoder.Decode(&doc); err != nil {
			break
		}
		flat := map[string]string{}
		flattenYAML("", doc, flat)
		if flat["spring.config.activate.on-profile"] != "" || flat["spring.profiles"] != "" {
			continue
		}
		for k, v := range flat {
			if _, set := values[k]; !set {
				values[k] = v
			}
		}
	}
	return values
}

func flattenYAML(prefix string, value any, out map[string]string) {
	switch v := value.(type) {
	case map[string]any:
		for k, item := range v {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flattenYAML(key, item, out)
		}
	case nil:
		out[prefix] = ""
	default:
		out[prefix] = fmt.Sprint(v)
	}
}

func orRoot(prefix string) string {
	if prefix == "" {
		return "/"
	}
	return prefix
}

// shownPath is the path a reader should see: the served path when configuration adds a prefix.
func (r Route) shownPath() string {
	if r.ExternalPath != "" {
		return r.ExternalPath
	}
	return r.Path
}
