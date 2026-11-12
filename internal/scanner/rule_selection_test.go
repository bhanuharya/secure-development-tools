package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A repository holding only Consul HCL, an .env file and nginx.conf has no
// YAML file to detect. The generic yaml rule pack must still be selected, or
// Consul, actuator and nginx findings can never fire (T25, review 13).
func TestRuleFilesCoverConfigOnlyRepository(t *testing.T) {
	withRulePack(t)
	root := t.TempDir()
	for name, body := range map[string]string{
		"consul.hcl": "acl { enabled = false }\n",
		"prod.env":   "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=*\n",
		"nginx.conf": "location /management { proxy_pass http://app; }\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := strings.Join(ruleFiles(root, detectLanguages(root)), "\n")
	for _, want := range []string{"yaml/infra-exposure.yaml", "yaml/gateway-routes.yaml"} {
		if !strings.Contains(got, want) {
			t.Errorf("config-only repository is missing %s; got:\n%s", want, got)
		}
	}
}
