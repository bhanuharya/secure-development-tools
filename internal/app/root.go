// Package app wires the sdt command surface (PRD §13).
package app

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	sdtctx "github.com/bhanuharya/secure-development-tools/internal/context"
	"github.com/bhanuharya/secure-development-tools/internal/version"
)

// Exit codes (PRD §13).
const (
	ExitPassed          = 0
	ExitPolicyFailed    = 1
	ExitInvalidInput    = 2
	ExitExecutionFailed = 3
	ExitInconclusive    = 4
	ExitInternalError   = 5
)

// ExitError carries a process exit code through cobra.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

// Globals bound to persistent flags + SDT_* env.
type globals struct {
	Config  string
	Profile string
	Event   string
	Base    string
	Head    string
	Image   string
	Output  string
	Cache   string
	Offline bool
	Staged  bool
}

var g globals

// NewRoot builds the sdt command tree.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "sdt",
		Short:         "Secure Development Tools: local-first security scanning runtime",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	p := root.PersistentFlags()
	p.StringVar(&g.Config, "config", os.Getenv("SDT_CONFIG"), "config path (SDT_CONFIG)")
	p.StringVar(&g.Profile, "profile", envDefault("SDT_PROFILE", "pr"), "scan profile (SDT_PROFILE)")
	p.StringVar(&g.Event, "event", envDefault("SDT_EVENT", "local"), "neutral event (SDT_EVENT)")
	p.StringVar(&g.Base, "base", os.Getenv("SDT_BASE"), "base revision (SDT_BASE)")
	p.StringVar(&g.Head, "head", envDefault("SDT_HEAD", "HEAD"), "head revision (SDT_HEAD)")
	p.StringVar(&g.Image, "image", os.Getenv("SDT_IMAGE"), "image reference (SDT_IMAGE)")
	p.StringVar(&g.Output, "output", envDefault("SDT_OUTPUT_DIR", "reports"), "artifact root (SDT_OUTPUT_DIR)")
	p.StringVar(&g.Cache, "cache", envDefault("SDT_CACHE_DIR", ".cache/sdt"), "cache root (SDT_CACHE_DIR)")
	offline := os.Getenv("SDT_OFFLINE") == "true" || os.Getenv("SDT_OFFLINE") == "1"
	p.BoolVar(&g.Offline, "offline", offline, "disable network updates (SDT_OFFLINE)")
	p.BoolVar(&g.Staged, "staged", false, "pre-commit fast path: scan staged files only, defer full-tree scanners to CI")

	root.AddCommand(
		newInitCmd(), newDoctorCmd(), newDetectCmd(),
		newConfigCmd(), newPlanCmd(), newScanCmd(),
		newBaselineCmd(), newPolicyCmd(), newRulesCmd(),
		newPublishCmd(), newExplainCmd(), newFixCmd(), newVersionCmd(),
	)
	return root
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// effectiveConfig loads defaults + repo file + env overlay.
func effectiveConfig() (*config.ScanConfiguration, string, string, []string, error) {
	base := config.Defaults()
	path := g.Config
	if path == "" {
		path = ".secure-dev.yaml"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if g.Config != "" {
			return nil, "", "", nil, &ExitError{Code: ExitInvalidInput, Msg: fmt.Sprintf("read config: %v", err)}
		}
		// No repo file: pure defaults.
		warns := config.ApplyEnvOverlay(base, os.Getenv)
		return base, "", config.EffectiveDigest(base), warns, nil
	}
	parsed, _, err := config.Parse(raw, path)
	if err != nil {
		return nil, "", "", nil, &ExitError{Code: ExitInvalidInput, Msg: err.Error()}
	}
	merged := config.Merge(base, parsed)
	warns := config.ApplyEnvOverlay(merged, os.Getenv)
	return merged, path, config.EffectiveDigest(merged), warns, nil
}

// ScanRoot resolves the repository root for scanning (project.root or CWD).
// The resolved root must exist, must resolve inside the authorized checkout
// (the git top-level containing CWD, or CWD itself outside git), and must
// not escape via symlinks. Anything else fails closed.
func ScanRoot(cfg *config.ScanConfiguration) (string, error) {
	root, err := os.Getwd()
	if err != nil {
		return "", &ExitError{Code: ExitInternalError, Msg: err.Error()}
	}
	if cfg.Project.Root != "" && cfg.Project.Root != "." {
		root = cfg.Project.Root
		if !filepath.IsAbs(root) {
			cwd, _ := os.Getwd()
			root = filepath.Join(cwd, root)
		}
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", &ExitError{Code: ExitInvalidInput, Msg: fmt.Sprintf("bad project root: %v", err)}
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", &ExitError{Code: ExitInvalidInput, Msg: fmt.Sprintf("bad project root %q: %v", root, err)}
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", &ExitError{Code: ExitInvalidInput, Msg: fmt.Sprintf("project root %q is not a directory", root)}
	}
	anchor, err := checkoutAnchor()
	if err != nil {
		return "", &ExitError{Code: ExitInternalError, Msg: err.Error()}
	}
	if resolved != anchor && !isWithin(resolved, anchor) {
		return "", &ExitError{Code: ExitInvalidInput, Msg: fmt.Sprintf("project root %q escapes the authorized checkout %q", root, anchor)}
	}
	return resolved, nil
}

// resolveContext builds the neutral context from globals.
func resolveContext(cfg *config.ScanConfiguration) (*sdtctx.ScanContext, []string, error) {
	root, err := ScanRoot(cfg)
	if err != nil {
		return nil, nil, err
	}
	in := sdtctx.Inputs{
		Profile: g.Profile, Event: g.Event, Base: g.Base, Head: g.Head,
		Image: g.Image, OutputDir: g.Output, CacheDir: g.Cache, Offline: g.Offline || cfg.Runtime.Offline,
		Staged: g.Staged,
	}
	ctx, warns, err := sdtctx.Resolve(in, root)
	if err != nil {
		return nil, nil, &ExitError{Code: ExitInvalidInput, Msg: err.Error()}
	}
	ctx.DefaultBranch = cfg.Project.DefaultBranch
	ctx.OutputRoot = g.Output
	ctx.CacheRoot = g.Cache
	return ctx, warns, nil
}

func newRunID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "run-" + hex.EncodeToString(b[:])
}

func failf(code int, format string, args ...any) error {
	return &ExitError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// checkoutAnchor returns the authorized checkout root: the git top-level
// containing CWD when inside a repository, otherwise CWD itself (symlinks
// resolved). Scan roots outside this anchor are refused.
func checkoutAnchor() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		resolved, rerr := filepath.EvalSymlinks(cwd)
		if rerr != nil {
			return cwd, nil
		}
		return resolved, nil
	}
	top := strings.TrimSpace(string(out))
	if top == "" {
		return cwd, nil
	}
	if resolved, rerr := filepath.EvalSymlinks(top); rerr == nil {
		return resolved, nil
	}
	return top, nil
}

func isWithin(candidate, anchor string) bool {
	return candidate == anchor || strings.HasPrefix(candidate, anchor+string(filepath.Separator))
}

var _ = version.CLI
