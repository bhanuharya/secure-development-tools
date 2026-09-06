// Package context resolves the provider-neutral ScanContext (PRD CTX-001/002/003).
package context

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const SchemaVersion = "secure-dev/context/v1alpha1"

// Event is the neutral event enum.
type Event string

const (
	EventLocal       Event = "local"
	EventPullRequest Event = "pull_request"
	EventPush        Event = "push"
	EventSchedule    Event = "schedule"
	EventRelease     Event = "release"
)

// ScanContext is the provider-neutral execution context.
type ScanContext struct {
	SchemaVersion  string   `json:"schemaVersion"`
	RepositoryRoot string   `json:"repositoryRoot,omitempty"`
	Event          Event    `json:"event"`
	HeadRevision   string   `json:"headRevision"`
	BaseRevision   string   `json:"baseRevision,omitempty"`
	MergeBase      string   `json:"mergeBase,omitempty"`
	ChangedPaths   []string `json:"changedPaths,omitempty"`
	DefaultBranch  string   `json:"defaultBranch,omitempty"`
	ImageReference string   `json:"imageReference,omitempty"`
	OutputRoot     string   `json:"outputRoot"`
	CacheRoot      string   `json:"cacheRoot"`
	Offline        bool     `json:"offline"`
	Shallow        bool     `json:"shallow,omitempty"`
	// Staged marks the pre-commit fast path: ChangedPaths come from the git
	// index (staged files) instead of a base/head range, and full-tree
	// scanners are deferred to CI. Included in the digest: staged state is
	// real scan input, and staged vs committed must never digest identically.
	Staged bool `json:"staged,omitempty"`
}

// Inputs are explicit invocation values (flags > SDT_* env > defaults).
type Inputs struct {
	ConfigPath string
	Profile    string
	Event      string
	Base       string
	Head       string
	Image      string
	OutputDir  string
	CacheDir   string
	Offline    bool
	OfflineSet bool
	Staged     bool
}

// FromEnv builds Inputs from SDT_* variables.
func FromEnv(getenv func(string) string) Inputs {
	return Inputs{
		ConfigPath: getenv("SDT_CONFIG"),
		Profile:    getenv("SDT_PROFILE"),
		Event:      getenv("SDT_EVENT"),
		Base:       getenv("SDT_BASE"),
		Head:       getenv("SDT_HEAD"),
		Image:      getenv("SDT_IMAGE"),
		OutputDir:  getenv("SDT_OUTPUT_DIR"),
		CacheDir:   getenv("SDT_CACHE_DIR"),
	}
}

// Resolve builds the ScanContext from inputs + git facts.
func Resolve(in Inputs, repoRoot string) (*ScanContext, []string, error) {
	var warnings []string
	event := Event(in.Event)
	if event == "" {
		event = EventLocal
	}
	switch event {
	case EventLocal, EventPullRequest, EventPush, EventSchedule, EventRelease:
	default:
		return nil, nil, fmt.Errorf("invalid event %q: want local|pull_request|push|schedule|release", in.Event)
	}
	head := in.Head
	if head == "" {
		head = "HEAD"
	}
	headOID, err := gitOutput(repoRoot, "rev-parse", "--verify", head)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve head %q: %w", head, err)
	}
	ctx := &ScanContext{
		SchemaVersion:  SchemaVersion,
		RepositoryRoot: repoRoot,
		Event:          event,
		HeadRevision:   strings.TrimSpace(headOID),
		OutputRoot:     in.OutputDir,
		CacheRoot:      in.CacheDir,
		Offline:        in.Offline,
		Staged:         in.Staged,
	}
	ctx.Shallow = isShallow(repoRoot)
	if in.Staged {
		staged, err := stagedPaths(repoRoot)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve staged files: %w", err)
		}
		ctx.ChangedPaths = staged
		return ctx, warnings, nil
	}
	if in.Base != "" {
		baseOID, err := gitOutput(repoRoot, "rev-parse", "--verify", in.Base)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve base %q: %w", in.Base, err)
		}
		ctx.BaseRevision = strings.TrimSpace(baseOID)
		mb, err := gitOutput(repoRoot, "merge-base", ctx.BaseRevision, ctx.HeadRevision)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("no merge-base for %s...%s; changed paths unresolved", in.Base, head))
		} else {
			ctx.MergeBase = strings.TrimSpace(mb)
			paths, err := changedPaths(repoRoot, ctx.MergeBase, ctx.HeadRevision)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("changed-path resolution failed: %v", err))
			} else {
				ctx.ChangedPaths = paths
			}
		}
	}
	return ctx, warnings, nil
}

func changedPaths(root, mb, head string) ([]string, error) {
	out, err := gitOutput(root, "diff", "--name-only", "-z", mb, head)
	if err != nil {
		return nil, err
	}
	return splitNullPaths(out), nil
}

// stagedPaths lists files staged in the git index (pre-commit fast path).
// Only staged content is in scope: unstaged worktree changes and untracked
// files are invisible here by design. Stage with `git add` first.
func stagedPaths(root string) ([]string, error) {
	out, err := gitOutput(root, "diff", "--cached", "--name-only", "-z")
	if err != nil {
		return nil, err
	}
	return splitNullPaths(out), nil
}

func splitNullPaths(out string) []string {
	var paths []string
	for _, p := range strings.Split(out, "\x00") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Normalize to repo-relative with forward slashes.
		p = filepath.ToSlash(p)
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

func isShallow(root string) bool {
	_, err := os.Stat(filepath.Join(root, ".git", "shallow"))
	if err == nil {
		return true
	}
	out, err := gitOutput(root, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "true"
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return string(out), nil
}

// Digest is the stable context digest for plan correlation.
func (c *ScanContext) Digest() string {
	mode := ""
	if c.Staged {
		mode = "staged"
	}
	h := sha256.New()
	h.Write([]byte(string(c.Event) + "|" + c.HeadRevision + "|" + c.BaseRevision + "|" + c.MergeBase + "|" + c.ImageReference + "|" + mode + "|"))
	cp := append([]string{}, c.ChangedPaths...)
	sort.Strings(cp)
	for _, p := range cp {
		h.Write([]byte(p + "\n"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
