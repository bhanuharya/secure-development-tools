// Package detect inspects repository facts for capability-based selection.
package detect

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Facts about a repository.
type Facts struct {
	Languages []string `json:"languages"`
	Manifests []string `json:"manifests"`
	HasIaC    bool     `json:"hasIaC"`
	HasGit    bool     `json:"hasGit"`
	Shallow   bool     `json:"shallow"`
}

// Inspect walks the repo root (bounded, skipping heavy dirs).
func Inspect(root string) Facts {
	var f Facts
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		f.HasGit = true
	}
	if _, err := os.Stat(filepath.Join(root, ".git", "shallow")); err == nil {
		f.Shallow = true
	}
	langs := map[string]bool{}
	manifests := map[string]bool{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(p)
			switch base {
			case ".git", "node_modules", "vendor", ".venv", "venv", "target", "dist", "build", "__pycache__", ".cache", "reports":
				return filepath.SkipDir
			}
			return nil
		}
		name := filepath.Base(p)
		ext := strings.ToLower(filepath.Ext(name))
		switch ext {
		case ".py":
			langs["python"] = true
		case ".js":
			langs["javascript"] = true
		case ".ts", ".tsx":
			langs["typescript"] = true
		case ".go":
			langs["go"] = true
		case ".java":
			langs["java"] = true
		case ".kt", ".kts":
			langs["kotlin"] = true
		case ".yaml", ".yml":
			langs["yaml"] = true
		}
		switch name {
		case "package.json", "package-lock.json", "requirements.txt", "go.mod", "go.sum",
			"pom.xml", "build.gradle", "Cargo.toml", "Cargo.lock", "Gemfile", "composer.json":
			manifests[name] = true
		case "Dockerfile", "docker-compose.yml", "docker-compose.yaml":
			f.HasIaC = true
			manifests[name] = true
		}
		if strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tfvars") {
			f.HasIaC = true
		}
		if strings.HasSuffix(p, "k8s.yaml") || strings.Contains(p, "kubernetes") {
			f.HasIaC = true
		}
		return nil
	})
	for l := range langs {
		f.Languages = append(f.Languages, l)
	}
	for m := range manifests {
		f.Manifests = append(f.Manifests, m)
	}
	sort.Strings(f.Languages)
	sort.Strings(f.Manifests)
	return f
}
