package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Vendored rule files stay verbatim, so their readable names live in one
// overlay at <pack>/vendor/titles.yaml. Load it once per pack: a scan asks for
// it for every finding, and the file holds one line per vendored rule.
var (
	titlesMu    sync.Mutex
	titlesCache = map[string]map[string]string{}
)

func ruleTitles(pack string) map[string]string {
	path, err := filepath.Abs(filepath.Join(pack, "vendor", "titles.yaml"))
	if err != nil {
		return nil
	}
	titlesMu.Lock()
	defer titlesMu.Unlock()
	if titles, ok := titlesCache[path]; ok {
		return titles
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil // no overlay: first-party rules and the id fallback still work
	}
	var titles map[string]string
	if err := yaml.Unmarshal(raw, &titles); err != nil {
		return nil
	}
	for id, title := range titles {
		titles[id] = strings.TrimSpace(title)
	}
	titlesCache[path] = titles
	return titles
}

// overlayTitle looks a rule up by the id sdt reports. A pack directory with a
// different name leaves its path in the engine's id; the overlay itself is
// keyed from vendor/ onward, so try that suffix too.
func overlayTitle(titles map[string]string, ruleID string) string {
	if title := titles[ruleID]; title != "" {
		return title
	}
	if i := strings.Index(ruleID, "vendor."); i > 0 {
		return titles[ruleID[i:]]
	}
	return ""
}
