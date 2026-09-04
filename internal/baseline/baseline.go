// Package baseline implements explicit new/existing classification
// (PRD POL-003) and governed exceptions (POL-004).
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// Baseline is the explicit known-fingerprint set. Never holds raw secrets.
type Baseline struct {
	SchemaVersion      string           `json:"schemaVersion"`
	FingerprintVersion string           `json:"fingerprintVersion"`
	ConfigDigest       string           `json:"configDigest"`
	CreatedRevision    string           `json:"createdRevision"`
	Entries            map[string]Entry `json:"entries"`
}

// Entry is one accepted finding identity.
type Entry struct {
	Rule     string `json:"rule"`
	Category string `json:"category"`
	Path     string `json:"path,omitempty"`
}

// Exception is a governed suppression.
type Exception struct {
	ID           string   `json:"id" yaml:"id"`
	Fingerprints []string `json:"fingerprints,omitempty" yaml:"fingerprints,omitempty"`
	Rules        []string `json:"rules,omitempty" yaml:"rules,omitempty"`
	Paths        []string `json:"paths,omitempty" yaml:"paths,omitempty"`
	Reason       string   `json:"reason" yaml:"reason"`
	Owner        string   `json:"owner" yaml:"owner"`
	CreatedAt    string   `json:"createdAt" yaml:"createdAt"`
	ExpiresAt    string   `json:"expiresAt" yaml:"expiresAt"`
	Ticket       string   `json:"ticket,omitempty" yaml:"ticket,omitempty"`
}

// Load reads a baseline file; missing file means empty baseline.
func Load(path string) (*Baseline, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{SchemaVersion: "secure-dev/baseline/v1alpha1", FingerprintVersion: finding.FingerprintVersion, Entries: map[string]Entry{}}, nil
		}
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	if b.Entries == nil {
		b.Entries = map[string]Entry{}
	}
	if b.FingerprintVersion != "" && b.FingerprintVersion != finding.FingerprintVersion {
		return nil, fmt.Errorf("incompatible fingerprint version %q (want %q)", b.FingerprintVersion, finding.FingerprintVersion)
	}
	return &b, nil
}

// Apply classifies findings; returns resolved (baseline entries with no match).
func (b *Baseline) Apply(findings []*finding.Finding) (resolved []string) {
	seen := map[string]bool{}
	for _, f := range findings {
		if _, ok := b.Entries[f.Fingerprint.Value]; ok {
			f.BaselineState = finding.StateExisting
		} else {
			f.BaselineState = finding.StateNew
		}
		seen[f.Fingerprint.Value] = true
	}
	for fp := range b.Entries {
		if !seen[fp] {
			resolved = append(resolved, fp)
		}
	}
	return resolved
}

// Create writes a baseline from canonical findings.
func Create(path string, findings []*finding.Finding, configDigest, revision string) error {
	b := &Baseline{
		SchemaVersion:      "secure-dev/baseline/v1alpha1",
		FingerprintVersion: finding.FingerprintVersion,
		ConfigDigest:       configDigest,
		CreatedRevision:    revision,
		Entries:            map[string]Entry{},
	}
	for _, f := range findings {
		loc := ""
		if f.Location != nil {
			loc = f.Location.Path
		}
		b.Entries[f.Fingerprint.Value] = Entry{Rule: f.Rule.ID, Category: f.Category, Path: loc}
	}
	raw, _ := json.MarshalIndent(b, "", "  ")
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// ValidateException enforces owner/reason/expiry; expired never suppresses.
func ValidateException(e Exception, now time.Time) (expired bool, err error) {
	if e.Reason == "" || e.Owner == "" || e.ExpiresAt == "" {
		return false, fmt.Errorf("exception %q requires reason, owner, expiresAt", e.ID)
	}
	exp, err := time.Parse("2006-01-02", e.ExpiresAt)
	if err != nil {
		return false, fmt.Errorf("exception %q: bad expiresAt: %w", e.ID, err)
	}
	if !exp.After(now) {
		return true, nil
	}
	return false, nil
}

// Matches reports whether an exception covers a finding.
func (e Exception) Matches(f *finding.Finding) bool {
	for _, fp := range e.Fingerprints {
		if fp == f.Fingerprint.Value {
			return true
		}
	}
	return false
}
