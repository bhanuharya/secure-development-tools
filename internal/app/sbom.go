package app

import (
	"context"
	"fmt"
	"os"

	"github.com/bhanuharya/secure-development-tools/internal/execute"
	"github.com/bhanuharya/secure-development-tools/internal/plan"
	"github.com/bhanuharya/secure-development-tools/internal/report"
	"github.com/bhanuharya/secure-development-tools/internal/scanner"
)

// extraArtifact is a caller-supplied report file (e.g. SBOM evidence)
// finalized alongside the built-in artifacts.
type extraArtifact struct {
	name   string
	data   []byte
	media  string
	schema string
}

// runTrivySBOM generates a merged CycloneDX inventory from the same trivy
// runs the scan used: filesystem SBOM when trivy-fs completed, image SBOM
// when trivy-image completed. Returns ("", diagnostic) when there is nothing
// to inventory or generation failed — SBOM is evidence, never a gate.
func runTrivySBOM(ctx context.Context, tasks []plan.Task, root, imageRef string, health map[string]string) ([]byte, string) {
	bin := ""
	for _, t := range tasks {
		if t.Adapter == "trivy-fs" || t.Adapter == "trivy-image" {
			bin = t.Executable
			break
		}
	}
	if bin == "" {
		return nil, "sbom skipped: trivy not in plan"
	}
	skipDirs := ".git,node_modules,vendor,dist,build,.venv,venv,target,__pycache__"
	var docs [][]byte
	if health["trivy-fs"] == string(scanner.HealthCompleted) {
		out, err := os.CreateTemp("", "sdt-sbom-fs-*.json")
		if err != nil {
			return nil, fmt.Sprintf("sbom skipped: %v", err)
		}
		path := out.Name()
		_ = out.Close()
		defer os.Remove(path)
		r := execute.RunOne(ctx, execute.Task{
			Adapter: "trivy-fs-sbom", Executable: bin,
			Args: []string{"fs", "--quiet", "--format", "cyclonedx",
				"--no-progress", "--exit-code", "0",
				"--skip-dirs", skipDirs, "--output", path, root},
			TimeoutSeconds: 600, Dir: root, ReportPath: path,
		}, func(s string) string { return report.Redact(s) })
		if r.Err != nil {
			return nil, fmt.Sprintf("sbom skipped: filesystem inventory failed (%v)", r.Err)
		}
		docs = append(docs, r.Stdout)
	}
	if imageRef != "" && health["trivy-image"] == string(scanner.HealthCompleted) {
		out, err := os.CreateTemp("", "sdt-sbom-img-*.json")
		if err != nil {
			return nil, fmt.Sprintf("sbom skipped: %v", err)
		}
		path := out.Name()
		_ = out.Close()
		defer os.Remove(path)
		r := execute.RunOne(ctx, execute.Task{
			Adapter: "trivy-image-sbom", Executable: bin,
			Args: []string{"image", "--quiet", "--format", "cyclonedx",
				"--no-progress", "--exit-code", "0",
				"--output", path, imageRef},
			TimeoutSeconds: 600, Dir: root, ReportPath: path,
		}, func(s string) string { return report.Redact(s) })
		if r.Err != nil {
			return nil, fmt.Sprintf("sbom skipped: image inventory failed (%v)", r.Err)
		}
		docs = append(docs, r.Stdout)
	}
	if len(docs) == 0 {
		return nil, "sbom skipped: no completed trivy inventory to report"
	}
	merged, err := report.MergeCycloneDX(docs...)
	if err != nil {
		return nil, fmt.Sprintf("sbom skipped: merge failed (%v)", err)
	}
	return merged, ""
}
