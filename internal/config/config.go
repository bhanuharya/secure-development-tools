// Package config loads, validates, and merges .secure-dev.yaml.
//
// Precedence (PRD CFG-002): compiled defaults < inherited bundle (extends,
// P1 - rejected for now unless file reference) < repository file < selected
// profile overlay < allowed SDT_* env overrides < CLI flags (applied by caller).
//
// Unknown keys fail closed (PRD CFG-001). No field may express shell.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion = "secure-dev/v1alpha1"
	Kind       = "ScanConfiguration"
)

// ScanConfiguration is the typed v1alpha1 model.
type ScanConfiguration struct {
	APIVersion string             `yaml:"apiVersion" json:"apiVersion"`
	Kind       string             `yaml:"kind" json:"kind"`
	Metadata   Metadata           `yaml:"metadata" json:"metadata"`
	Project    Project            `yaml:"project" json:"project"`
	Extends    []string           `yaml:"extends,omitempty" json:"extends,omitempty"`
	Profiles   map[string]Profile `yaml:"profiles" json:"profiles"`
	Scanners   Scanners           `yaml:"scanners,omitempty" json:"scanners,omitempty"`
	Policy     Policy             `yaml:"policy,omitempty" json:"policy,omitempty"`
	Baseline   Baseline           `yaml:"baseline,omitempty" json:"baseline,omitempty"`
	Exceptions ExceptionsCfg      `yaml:"exceptions,omitempty" json:"exceptions,omitempty"`
	Outputs    Outputs            `yaml:"outputs,omitempty" json:"outputs,omitempty"`
	Runtime    Runtime            `yaml:"runtime,omitempty" json:"runtime,omitempty"`
	Publish    Publish            `yaml:"publish,omitempty" json:"publish,omitempty"`
	AI         AI                 `yaml:"ai,omitempty" json:"ai,omitempty"`
}

type Metadata struct {
	Name   string            `yaml:"name" json:"name"`
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

type Project struct {
	Root          string   `yaml:"root,omitempty" json:"root,omitempty"`
	DefaultBranch string   `yaml:"defaultBranch,omitempty" json:"defaultBranch,omitempty"`
	Include       []string `yaml:"include,omitempty" json:"include,omitempty"`
	Exclude       []string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
}

type Profile struct {
	Mode             string         `yaml:"mode,omitempty" json:"mode,omitempty"` // changed | repository
	Scanners         []string       `yaml:"scanners,omitempty" json:"scanners,omitempty"`
	RequiredScanners []string       `yaml:"requiredScanners,omitempty" json:"requiredScanners,omitempty"`
	Timeout          string         `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Parallelism      int            `yaml:"parallelism,omitempty" json:"parallelism,omitempty"`
	MissingHistory   string         `yaml:"missingHistory,omitempty" json:"missingHistory,omitempty"` // fail|warn|fallback
	RequireImage     bool           `yaml:"requireImage,omitempty" json:"requireImage,omitempty"`
	UpdateMode       string         `yaml:"updateMode,omitempty" json:"updateMode,omitempty"`
	PolicyOverlay    map[string]any `yaml:"policyOverlay,omitempty" json:"policyOverlay,omitempty"`
}

type Scanners struct {
	Opengrep   OpengrepCfg   `yaml:"opengrep,omitempty" json:"opengrep,omitempty"`
	Gitleaks   GitleaksCfg   `yaml:"gitleaks,omitempty" json:"gitleaks,omitempty"`
	TrivyFS    TrivyFSCfg    `yaml:"trivy-fs,omitempty" json:"trivy-fs,omitempty"`
	TrivyImage TrivyImageCfg `yaml:"trivy-image,omitempty" json:"trivy-image,omitempty"`
}

type OpengrepCfg struct {
	Type    string   `yaml:"type,omitempty" json:"type,omitempty"`
	Rules   RulesRef `yaml:"rules,omitempty" json:"rules,omitempty"`
	Exclude []string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	Timeout string   `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

type RulesRef struct {
	Bundles []string `yaml:"bundles,omitempty" json:"bundles,omitempty"`
	Paths   []string `yaml:"paths,omitempty" json:"paths,omitempty"`
}

type GitleaksCfg struct {
	Type    string            `yaml:"type,omitempty" json:"type,omitempty"`
	History map[string]string `yaml:"history,omitempty" json:"history,omitempty"`
	Redact  string            `yaml:"redact,omitempty" json:"redact,omitempty"`
	Config  string            `yaml:"config,omitempty" json:"config,omitempty"`
	Timeout string            `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

type TrivyFSCfg struct {
	Type          string   `yaml:"type,omitempty" json:"type,omitempty"`
	Scanners      []string `yaml:"scanners,omitempty" json:"scanners,omitempty"`
	Severities    []string `yaml:"severities,omitempty" json:"severities,omitempty"`
	IgnoreUnfixed bool     `yaml:"ignoreUnfixed,omitempty" json:"ignoreUnfixed,omitempty"`
	Timeout       string   `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

type TrivyImageCfg struct {
	Type          string   `yaml:"type,omitempty" json:"type,omitempty"`
	Scanners      []string `yaml:"scanners,omitempty" json:"scanners,omitempty"`
	Severities    []string `yaml:"severities,omitempty" json:"severities,omitempty"`
	IgnoreUnfixed bool     `yaml:"ignoreUnfixed,omitempty" json:"ignoreUnfixed,omitempty"`
	Timeout       string   `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

type Policy struct {
	BehaviorOnRequiredScannerError string       `yaml:"behaviorOnRequiredScannerError,omitempty" json:"behaviorOnRequiredScannerError,omitempty"`
	DefaultAction                  string       `yaml:"defaultAction,omitempty" json:"defaultAction,omitempty"`
	Rules                          []PolicyRule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

type PolicyRule struct {
	ID     string      `yaml:"id" json:"id"`
	Match  PolicyMatch `yaml:"match" json:"match"`
	Action string      `yaml:"action" json:"action"` // fail|warn|report
}

type PolicyMatch struct {
	Categories     []string `yaml:"categories,omitempty" json:"categories,omitempty"`
	Severities     []string `yaml:"severities,omitempty" json:"severities,omitempty"`
	BaselineStates []string `yaml:"baselineStates,omitempty" json:"baselineStates,omitempty"`
	FixAvailable   *bool    `yaml:"fixAvailable,omitempty" json:"fixAvailable,omitempty"`
	// Reachable matches dependency reachability states ("reachable" |
	// "unreachable"). Findings with unknown/unanalyzed reachability match
	// neither value, so uncertainty can never silently demote a finding.
	Reachable []string `yaml:"reachable,omitempty" json:"reachable,omitempty"`
}

type Baseline struct {
	File                             string `yaml:"file,omitempty" json:"file,omitempty"`
	OnIncompatibleFingerprintVersion string `yaml:"onIncompatibleFingerprintVersion,omitempty" json:"onIncompatibleFingerprintVersion,omitempty"`
	ReportResolved                   bool   `yaml:"reportResolved,omitempty" json:"reportResolved,omitempty"`
}

type ExceptionsCfg struct {
	File                  string `yaml:"file,omitempty" json:"file,omitempty"`
	RequireOwner          bool   `yaml:"requireOwner,omitempty" json:"requireOwner,omitempty"`
	RequireReason         bool   `yaml:"requireReason,omitempty" json:"requireReason,omitempty"`
	RequireExpiry         bool   `yaml:"requireExpiry,omitempty" json:"requireExpiry,omitempty"`
	AllowSecretExceptions bool   `yaml:"allowSecretExceptions,omitempty" json:"allowSecretExceptions,omitempty"`
}

type Outputs struct {
	Directory        string   `yaml:"directory,omitempty" json:"directory,omitempty"`
	Formats          []string `yaml:"formats,omitempty" json:"formats,omitempty"`
	RawScannerOutput bool     `yaml:"rawScannerOutput,omitempty" json:"rawScannerOutput,omitempty"`
	AtomicWrites     bool     `yaml:"atomicWrites,omitempty" json:"atomicWrites,omitempty"`
	Redaction        string   `yaml:"redaction,omitempty" json:"redaction,omitempty"`
}

type Runtime struct {
	CacheDirectory     string `yaml:"cacheDirectory,omitempty" json:"cacheDirectory,omitempty"`
	TemporaryDirectory string `yaml:"temporaryDirectory,omitempty" json:"temporaryDirectory,omitempty"`
	UpdateMode         string `yaml:"updateMode,omitempty" json:"updateMode,omitempty"`
	Offline            bool   `yaml:"offline,omitempty" json:"offline,omitempty"`
	Parallelism        any    `yaml:"parallelism,omitempty" json:"parallelism,omitempty"`
	Network            string `yaml:"network,omitempty" json:"network,omitempty"`
}

type Publish struct {
	Enabled  bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Provider string `yaml:"provider,omitempty" json:"provider,omitempty"`
}

type AI struct {
	Enabled            bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Mode               string `yaml:"mode,omitempty" json:"mode,omitempty"`
	SourceContextLines int    `yaml:"sourceContextLines,omitempty" json:"sourceContextLines,omitempty"`
	SendSecretFindings bool   `yaml:"sendSecretFindings,omitempty" json:"sendSecretFindings,omitempty"`
}

// knownTopLevel is the strict allow-list for unknown-key rejection.
var knownTopLevel = map[string]bool{
	"apiVersion": true, "kind": true, "metadata": true, "project": true,
	"extends": true, "profiles": true, "scanners": true, "policy": true,
	"baseline": true, "exceptions": true, "outputs": true, "runtime": true,
	"publish": true, "ai": true,
}

// Defaults returns compiled safe defaults (PRD layer 1).
func Defaults() *ScanConfiguration {
	return &ScanConfiguration{
		APIVersion: APIVersion,
		Kind:       Kind,
		Metadata:   Metadata{Name: "repository-default"},
		Project:    Project{Root: ".", DefaultBranch: "main", Include: []string{"**"}},
		Profiles: map[string]Profile{
			"pr": {
				Mode: "changed", Scanners: []string{"opengrep", "gitleaks", "trivy-fs"},
				RequiredScanners: []string{"opengrep", "gitleaks", "trivy-fs"},
				Timeout:          "15m", Parallelism: 3, MissingHistory: "fail",
			},
			"full": {
				Mode: "repository", Scanners: []string{"opengrep", "gitleaks", "trivy-fs"},
				RequiredScanners: []string{"opengrep", "gitleaks", "trivy-fs"},
				Timeout:          "45m", Parallelism: 3, MissingHistory: "fail",
			},
			"release": {
				Mode: "repository", Scanners: []string{"opengrep", "gitleaks", "trivy-fs", "trivy-image"},
				RequiredScanners: []string{"opengrep", "gitleaks", "trivy-fs", "trivy-image"},
				Timeout:          "60m", Parallelism: 2, MissingHistory: "fail", RequireImage: true, UpdateMode: "locked",
			},
		},
		Policy: Policy{
			BehaviorOnRequiredScannerError: "fail",
			DefaultAction:                  "report",
			Rules: []PolicyRule{
				{ID: "block-secrets", Match: PolicyMatch{Categories: []string{"secret"}, BaselineStates: []string{"new", "existing", "unknown"}}, Action: "fail"},
				{ID: "block-new-high-sast", Match: PolicyMatch{Categories: []string{"sast"}, Severities: []string{"high", "critical"}, BaselineStates: []string{"new", "unknown"}}, Action: "fail"},
				{ID: "block-new-critical-dependencies", Match: PolicyMatch{Categories: []string{"dependency-vulnerability", "image-vulnerability"}, Severities: []string{"critical"}, BaselineStates: []string{"new", "unknown"}}, Action: "fail"},
				{ID: "block-new-high-iac", Match: PolicyMatch{Categories: []string{"misconfiguration"}, Severities: []string{"high", "critical"}, BaselineStates: []string{"new", "unknown"}}, Action: "fail"},
			},
		},
		Baseline:   Baseline{File: ".secure-dev/baseline.json", OnIncompatibleFingerprintVersion: "fail", ReportResolved: true},
		Exceptions: ExceptionsCfg{File: ".secure-dev/exceptions.yaml", RequireOwner: true, RequireReason: true, RequireExpiry: true},
		Outputs:    Outputs{Directory: "reports", Formats: []string{"console", "json", "sarif", "manifest"}, AtomicWrites: true, Redaction: "strict"},
		Runtime:    Runtime{CacheDirectory: ".cache/sdt", TemporaryDirectory: ".cache/sdt/tmp", UpdateMode: "database", Network: "updates-only"},
		Publish:    Publish{Enabled: false, Provider: "auto"},
		AI:         AI{Enabled: false, Mode: "explain-only", SourceContextLines: 20},
	}
}

// LoadFile reads and strictly validates a config file.
func LoadFile(path string) (*ScanConfiguration, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read config %s: %w", path, err)
	}
	return Parse(raw, path)
}

// Parse strictly decodes YAML: unknown top-level keys fail.
func Parse(raw []byte, source string) (*ScanConfiguration, string, error) {
	var node yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(false) // we do our own top-level check for a path-specific error
	if err := dec.Decode(&node); err != nil {
		return nil, "", fmt.Errorf("parse %s: %w", source, err)
	}
	// Top-level mapping unknown-key check.
	top := &node
	if top.Kind == yaml.DocumentNode && len(top.Content) > 0 {
		top = top.Content[0]
	}
	if top.Kind == yaml.MappingNode {
		for i := 0; i < len(top.Content); i += 2 {
			k := top.Content[i].Value
			if !knownTopLevel[k] {
				return nil, "", fmt.Errorf("parse %s: unknown field %q (strict schema; see schemas/config-v1alpha1.json)", source, k)
			}
		}
	}
	var cfg ScanConfiguration
	if err := node.Decode(&cfg); err != nil {
		return nil, "", fmt.Errorf("decode %s: %w", source, err)
	}
	if cfg.APIVersion != APIVersion {
		return nil, "", fmt.Errorf("unsupported apiVersion %q: want %q", cfg.APIVersion, APIVersion)
	}
	if cfg.Kind != Kind {
		return nil, "", fmt.Errorf("unsupported kind %q: want %q", cfg.Kind, Kind)
	}
	if err := Validate(&cfg); err != nil {
		return nil, "", err
	}
	digest := Digest(raw)
	return &cfg, digest, nil
}

// Validate checks semantic constraints (no shell-capable fields exist by construction).
func Validate(cfg *ScanConfiguration) error {
	if len(cfg.Profiles) == 0 {
		return fmt.Errorf("config must define at least one profile")
	}
	for name, p := range cfg.Profiles {
		if p.Mode != "" && p.Mode != "changed" && p.Mode != "repository" {
			return fmt.Errorf("profile %q: invalid mode %q", name, p.Mode)
		}
		if p.MissingHistory != "" && p.MissingHistory != "fail" && p.MissingHistory != "warn" && p.MissingHistory != "fallback" {
			return fmt.Errorf("profile %q: invalid missingHistory %q", name, p.MissingHistory)
		}
		for _, s := range append(append([]string{}, p.Scanners...), p.RequiredScanners...) {
			switch s {
			case "opengrep", "gitleaks", "trivy-fs", "trivy-image":
			default:
				return fmt.Errorf("profile %q: unknown scanner %q", name, s)
			}
		}
	}
	for _, r := range cfg.Policy.Rules {
		if r.ID == "" {
			return fmt.Errorf("policy rule missing id")
		}
		switch r.Action {
		case "fail", "warn", "report":
		default:
			return fmt.Errorf("policy rule %q: invalid action %q", r.ID, r.Action)
		}
	}
	return nil
}

// Merge overlays repo config onto defaults (shallow per-section, profiles replaced by name).
func Merge(base, over *ScanConfiguration) *ScanConfiguration {
	out := *base
	if over.Metadata.Name != "" {
		out.Metadata = over.Metadata
	}
	if over.Project.Root != "" || over.Project.DefaultBranch != "" || len(over.Project.Include) > 0 || len(over.Project.Exclude) > 0 {
		p := out.Project
		if over.Project.Root != "" {
			p.Root = over.Project.Root
		}
		if over.Project.DefaultBranch != "" {
			p.DefaultBranch = over.Project.DefaultBranch
		}
		if len(over.Project.Include) > 0 {
			p.Include = over.Project.Include
		}
		if len(over.Project.Exclude) > 0 {
			p.Exclude = over.Project.Exclude
		}
		out.Project = p
	}
	if len(over.Extends) > 0 {
		out.Extends = over.Extends
	}
	for k, v := range over.Profiles {
		if out.Profiles == nil {
			out.Profiles = map[string]Profile{}
		}
		out.Profiles[k] = v
	}
	// Scanners/policy/etc: overlay non-zero sections wholesale.
	if !scannersEmpty(over.Scanners) {
		out.Scanners = over.Scanners
	}
	if over.Policy.DefaultAction != "" || len(over.Policy.Rules) > 0 || over.Policy.BehaviorOnRequiredScannerError != "" {
		out.Policy = over.Policy
	}
	if over.Baseline.File != "" || over.Baseline.OnIncompatibleFingerprintVersion != "" || over.Baseline.ReportResolved {
		out.Baseline = over.Baseline
	}
	if over.Exceptions.File != "" || over.Exceptions.RequireOwner || over.Exceptions.RequireReason || over.Exceptions.RequireExpiry || over.Exceptions.AllowSecretExceptions {
		out.Exceptions = over.Exceptions
	}
	if over.Outputs.Directory != "" || len(over.Outputs.Formats) > 0 || over.Outputs.AtomicWrites || over.Outputs.Redaction != "" || over.Outputs.RawScannerOutput {
		out.Outputs = over.Outputs
	}
	if over.Runtime.CacheDirectory != "" || over.Runtime.TemporaryDirectory != "" || over.Runtime.UpdateMode != "" || over.Runtime.Offline || over.Runtime.Network != "" || over.Runtime.Parallelism != nil {
		out.Runtime = over.Runtime
	}
	if over.Publish.Enabled || over.Publish.Provider != "" {
		p := out.Publish
		if over.Publish.Enabled {
			p.Enabled = true
		}
		if over.Publish.Provider != "" {
			p.Provider = over.Publish.Provider
		}
		out.Publish = p
	}
	if over.AI.Enabled || over.AI.Mode != "" || over.AI.SourceContextLines != 0 || over.AI.SendSecretFindings {
		a := out.AI
		if over.AI.Enabled {
			a.Enabled = true
		}
		if over.AI.Mode != "" {
			a.Mode = over.AI.Mode
		}
		if over.AI.SourceContextLines != 0 {
			a.SourceContextLines = over.AI.SourceContextLines
		}
		if over.AI.SendSecretFindings {
			a.SendSecretFindings = true
		}
		out.AI = a
	}
	return &out
}

func scannersEmpty(s Scanners) bool {
	return s.Opengrep.Type == "" && len(s.Opengrep.Rules.Bundles) == 0 && len(s.Opengrep.Rules.Paths) == 0 &&
		s.Gitleaks.Type == "" && s.TrivyFS.Type == "" && s.TrivyImage.Type == ""
}

// ApplyEnvOverlay applies allowed SDT_* neutral overrides (PRD layer 5).
// Only runtime/context values; never policy thresholds.
func ApplyEnvOverlay(cfg *ScanConfiguration, getenv func(string) string) []string {
	var warnings []string
	if v := getenv("SDT_OUTPUT_DIR"); v != "" {
		cfg.Outputs.Directory = v
	}
	if v := getenv("SDT_CACHE_DIR"); v != "" {
		cfg.Runtime.CacheDirectory = v
		cfg.Runtime.TemporaryDirectory = filepath.Join(v, "tmp")
	}
	if v := getenv("SDT_OFFLINE"); v != "" {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			cfg.Runtime.Offline = true
		case "0", "false", "no", "off":
			cfg.Runtime.Offline = false
		default:
			warnings = append(warnings, fmt.Sprintf("ignoring invalid SDT_OFFLINE=%q", v))
		}
	}
	return warnings
}

// Digest returns sha256 hex of canonical bytes.
func Digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// EffectiveDigest digests the merged effective config deterministically.
func EffectiveDigest(cfg *ScanConfiguration) string {
	var keys []string
	for k := range cfg.Profiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(cfg.APIVersion + "/" + cfg.Kind + "/" + cfg.Metadata.Name + "|")
	for _, k := range keys {
		p := cfg.Profiles[k]
		sb.WriteString(k + "=" + p.Mode + "," + strings.Join(p.Scanners, "+") + "," + p.Timeout + ";")
	}
	sb.WriteString("|policy=" + cfg.Policy.DefaultAction + "/" + cfg.Policy.BehaviorOnRequiredScannerError)
	for _, r := range cfg.Policy.Rules {
		sb.WriteString(";" + r.ID + ":" + r.Action)
	}
	return Digest([]byte(sb.String()))
}
