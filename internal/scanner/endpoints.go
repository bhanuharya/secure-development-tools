package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
	"github.com/bhanuharya/secure-development-tools/internal/endpoints"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

func init() { Register(&EndpointsAdapter{}) }

// EndpointsAdapter inventories HTTP routes and reports the ones that break the
// service's own access-control convention (SPEC §6, §8). The inventory runs in
// process during Plan: it is pure Go plus one Opengrep facts run, and the Task
// carries the resulting native report so no second process is needed.
type EndpointsAdapter struct{}

// endpointsReport is the native report handed from Plan to Parse: the
// inventory that becomes endpoints.json and the convention findings that join
// the scan's findings.
type endpointsReport struct {
	Inventory *endpoints.Inventory `json:"inventory"`
	Findings  []*finding.Finding   `json:"findings"`
}

func (a *EndpointsAdapter) Identity() (string, string, []string) {
	return "endpoints", "endpoints", []string{finding.CatSAST}
}

func (a *EndpointsAdapter) Validate(cfg *config.ScanConfiguration) []string { return nil }

func (a *EndpointsAdapter) Detect(root string, languages []string) Applicability {
	return Applicability{State: "applicable", Reason: "endpoint inventory always applicable"}
}

func (a *EndpointsAdapter) Plan(ctx *sdtctx.ScanContext, cfg *config.ScanConfiguration, root string) (Task, error) {
	inv, err := endpoints.BuildInventory(root, cfg.Endpoints)
	if err != nil {
		return Task{}, fmt.Errorf("endpoint inventory: %w", err)
	}
	findings, err := endpoints.Analyze(inv, cfg.Endpoints)
	if err != nil {
		return Task{}, fmt.Errorf("endpoint convention config: %w", err)
	}
	raw, err := json.Marshal(endpointsReport{Inventory: inv, Findings: findings})
	if err != nil {
		return Task{}, fmt.Errorf("render endpoint report: %w", err)
	}
	return Task{
		Adapter: "endpoints", Tool: "endpoints", Targets: []string{root},
		TimeoutSeconds: 120, Mode: "in-process", Stdout: raw,
	}, nil
}

func (a *EndpointsAdapter) Parse(toolVersion string, root string, stdout []byte, stderrRedacted string, nativeExit int) ParseResult {
	if nativeExit != 0 {
		return ParseResult{Health: HealthFailed, Diagnostics: []string{fmt.Sprintf("endpoints exited %d: %s", nativeExit, truncate(stderrRedacted, 300))}}
	}
	var report endpointsReport
	if err := json.Unmarshal(stdout, &report); err != nil || report.Inventory == nil {
		return ParseResult{Health: HealthMalformed, Diagnostics: []string{"endpoints returned no inventory report"}}
	}
	var inventory bytes.Buffer
	if err := endpoints.WriteJSON(&inventory, report.Inventory); err != nil {
		return ParseResult{Health: HealthMalformed, Diagnostics: []string{fmt.Sprintf("render endpoints.json: %v", err)}}
	}
	return ParseResult{
		Findings: report.Findings,
		Health:   HealthCompleted,
		Artifacts: []Artifact{{
			Name: "endpoints.json", Data: inventory.Bytes(),
			MediaType: "application/json", Schema: endpoints.Schema,
		}},
	}
}
