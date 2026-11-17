package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/plan"
	"github.com/spf13/cobra"
)

func artifactTestConfig(t *testing.T) *config.ScanConfiguration {
	t.Helper()
	cfg := config.Defaults()
	cfg.Outputs.Directory = t.TempDir()
	cfg.Runtime.CacheDirectory = filepath.Join(cfg.Outputs.Directory, "cache")
	return cfg
}

// A required scanner failing after the endpoint inventory completed must not
// discard the inventory; the error path keeps every collected artifact.
func TestFinalizeKeepsAdapterArtifactsOnFailure(t *testing.T) {
	cfg := artifactTestConfig(t)
	extra := []extraArtifact{{
		name: "endpoints.json", data: []byte("{\"routes\":[]}\n"),
		media: "application/json", schema: "sdt-endpoints/v1",
	}}
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	_, _ = finalize(cmd, cfg, &plan.Plan{}, "run-1", time.Now(), nil,
		[]string{"trivy missing"}, nil, map[string]string{"endpoints": "completed"},
		map[string]string{}, "execution_failed", ExitExecutionFailed, extra,
		"required scanners unhealthy")

	if _, err := os.Stat(filepath.Join(cfg.Outputs.Directory, "endpoints.json")); err != nil {
		t.Fatalf("endpoints.json was not written on the failure path: %v", err)
	}
}

// A later run without an inventory must not leave the earlier run's routes in
// a reused output directory.
func TestFinalizeRemovesStaleEndpointInventory(t *testing.T) {
	cfg := artifactTestConfig(t)
	stale := filepath.Join(cfg.Outputs.Directory, "endpoints.json")
	if err := os.WriteFile(stale, []byte("{\"routes\":[{\"path\":\"/old\"}]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	_, _ = finalize(cmd, cfg, &plan.Plan{}, "run-2", time.Now(), nil, nil, nil,
		map[string]string{}, map[string]string{}, "execution_failed", ExitExecutionFailed,
		nil, "no inventory this run")

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale endpoints.json is still present (stat err=%v)", err)
	}
}
