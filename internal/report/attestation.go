package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/plan"
	"github.com/bhanuharya/secure-development-tools/internal/policy"
	"github.com/bhanuharya/secure-development-tools/internal/version"
)

const (
	// InTotoStatementType is the standard in-toto Statement v1 envelope type.
	InTotoStatementType = "https://in-toto.io/Statement/v1"
	// ScanPredicateType identifies an SDT scan verification attestation predicate.
	ScanPredicateType = "https://secure-dev.dev/attestation/scan/v1alpha1"
)

// InTotoStatement is a standard in-toto v1 statement ready for signing (e.g. via cosign).
type InTotoStatement struct {
	Type          string          `json:"_type"`
	Subject       []InTotoSubject `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     ScanPredicate   `json:"predicate"`
}

// InTotoSubject binds an artifact or git commit by cryptographic digest.
type InTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// AttestedTool records a scanner adapter, version, and binary SHA-256 digest.
type AttestedTool struct {
	Adapter      string `json:"adapter"`
	Tool         string `json:"tool"`
	Version      string `json:"version,omitempty"`
	BinarySHA256 string `json:"binarySha256,omitempty"`
}

// ScanPredicate captures the immutable verification inputs and verdict of a scan.
type ScanPredicate struct {
	BuilderID     string         `json:"builderId"`
	RunID         string         `json:"runId"`
	PlanID        string         `json:"planId"`
	Profile       string         `json:"profile"`
	Mode          string         `json:"mode,omitempty"`
	Status        string         `json:"status"`
	ExitCode      int            `json:"exitCode"`
	StartedAt     string         `json:"startedAt"`
	CompletedAt   string         `json:"completedAt"`
	ContextDigest string         `json:"contextDigest"`
	ConfigDigest  string         `json:"configDigest"`
	PolicyDigest  string         `json:"policyDigest"`
	PlanDigest    string         `json:"planDigest"`
	Tools         []AttestedTool `json:"tools"`
	Findings      FindingCounts  `json:"findings"`
	Blockers      int            `json:"blockers"`
	Warnings      int            `json:"warnings"`
}

// ToAttestation renders a single-line JSONL in-toto Statement v1 binding the
// generated run artifacts (including run-manifest.json) and scanner binary
// digests to the scan verdict and policy/rule digests.
func ToAttestation(m Manifest, manifestBytes []byte, p *plan.Plan, out policy.Outcome) ([]byte, error) {
	subjects := make([]InTotoSubject, 0, len(m.Artifacts)+1)
	subjects = append(subjects, InTotoSubject{
		Name:   "run-manifest.json",
		Digest: map[string]string{"sha256": stripSHA256Prefix(Checksum(manifestBytes))},
	})
	for _, art := range m.Artifacts {
		if art.Status != "generated" || art.Checksum == "" {
			continue
		}
		subjects = append(subjects, InTotoSubject{
			Name:   art.Path,
			Digest: map[string]string{"sha256": stripSHA256Prefix(art.Checksum)},
		})
	}

	execByAdapter := map[string]string{}
	if p != nil {
		for _, t := range p.Tasks {
			execByAdapter[t.Adapter] = t.Executable
		}
	}
	attestedTools := make([]AttestedTool, 0, len(m.Tools))
	for _, t := range m.Tools {
		at := AttestedTool{Adapter: t.Adapter, Tool: t.Tool, Version: t.Version}
		if bin := execByAdapter[t.Adapter]; bin != "" {
			if digest, err := fileSHA256(bin); err == nil {
				at.BinarySHA256 = digest
			}
		}
		attestedTools = append(attestedTools, at)
	}

	stmt := InTotoStatement{
		Type:          InTotoStatementType,
		Subject:       subjects,
		PredicateType: ScanPredicateType,
		Predicate: ScanPredicate{
			BuilderID:     "sdt/" + version.CLI,
			RunID:         m.RunID,
			PlanID:        m.PlanID,
			Profile:       m.Profile,
			Mode:          m.Mode,
			Status:        m.Status,
			ExitCode:      m.ExitCode,
			StartedAt:     m.StartedAt,
			CompletedAt:   m.CompletedAt,
			ContextDigest: m.ContextDigest,
			ConfigDigest:  m.ConfigDigest,
			PolicyDigest:  m.PolicyDigest,
			PlanDigest:    m.PlanDigest,
			Tools:         attestedTools,
			Findings:      m.Findings,
			Blockers:      len(out.Blockers),
			Warnings:      len(out.Warnings),
		},
	}
	raw, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func stripSHA256Prefix(s string) string {
	return strings.TrimPrefix(s, "sha256:")
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
