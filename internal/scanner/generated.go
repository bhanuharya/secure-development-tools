package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Machine-written source files (minified bundles, generated data) are left out
// of the code scan. The cross-function analysis treats a minified bundle as one
// enormous function and does not finish on it, and the engine's per-file time
// limit does not apply there: one committed bundle cost a repository its whole
// code scan. A finding inside such a file could not be fixed in it either.
// Secret and dependency scanning still read these files.
//
// The test is on content, not on the name: a file of at least generatedMinBytes
// with one line of generatedLongLine bytes, or generatedAverageLine bytes per
// line on average.
const (
	generatedMinBytes    = 20_000
	generatedMaxBytes    = 5_000_000 // larger files are already left out by --max-target-bytes
	generatedLongLine    = 5_000
	generatedAverageLine = 250
	// generatedArgBytes bounds what the exclusions add to the command line.
	generatedArgBytes = 256 << 10
)

var generatedCandidates = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true, ".vue": true,
	".css": true, ".html": true, ".htm": true, ".json": true, ".xml": true, ".svg": true,
	".php": true, ".py": true, ".java": true,
}

type generatedFile struct {
	Path string // relative to the scan root, with forward slashes
	Size int64
}

// skipGenerated returns the --exclude arguments that keep machine-written files
// out of the code scan, the files they cover, and a sentence for the run
// manifest. SDT_SCAN_GENERATED_FILES=1 scans them after all.
func skipGenerated(root string) (args []string, skipped []string, note string) {
	if os.Getenv("SDT_SCAN_GENERATED_FILES") == "1" {
		return nil, nil, ""
	}
	return excludeFiles(root, generatedFiles(root), generatedArgBytes)
}

// excludeFiles turns files (largest first) into --exclude arguments within a
// budget of command-line bytes: when they do not all fit, the largest go.
func excludeFiles(root string, files []generatedFile, budget int) (args []string, skipped []string, note string) {
	var bytes int64
	for _, file := range files {
		pattern := globLiteral(filepath.Join(root, filepath.FromSlash(file.Path)))
		if budget -= len(pattern) + len("--exclude") + 2; budget < 0 {
			break
		}
		args = append(args, "--exclude", pattern)
		skipped = append(skipped, file.Path)
		bytes += file.Size
	}
	if len(skipped) == 0 {
		return nil, nil, ""
	}
	sort.Strings(skipped)
	note = fmt.Sprintf("%d minified or generated files (%.1f MB) were not analysed by the code scan", len(skipped), float64(bytes)/1e6)
	if len(skipped) == 1 {
		note = fmt.Sprintf("1 minified or generated file (%.1f MB) was not analysed by the code scan", float64(bytes)/1e6)
	}
	if left := len(files) - len(skipped); left > 0 {
		note += fmt.Sprintf("; %d smaller ones were analysed (too many to leave out)", left)
	}
	return args, skipped, note
}

// globLiteral makes an absolute path match only itself as an --exclude pattern.
// A relative pattern would also match the same path under any other directory.
var globLiteral = strings.NewReplacer("[", "[[]", "*", "[*]", "?", "[?]").Replace

// generatedFiles lists the machine-written source files under root, largest first.
func generatedFiles(root string) []generatedFile {
	skip := excludedDirectories()
	var found []generatedFile
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if path != root && skip[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(entry.Name())
		if !entry.Type().IsRegular() || !generatedCandidates[filepath.Ext(name)] || strings.HasSuffix(name, ".min.js") {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Size() < generatedMinBytes || info.Size() > generatedMaxBytes {
			return nil
		}
		if rel, err := filepath.Rel(root, path); err == nil && machineWritten(path, info.Size()) {
			found = append(found, generatedFile{Path: filepath.ToSlash(rel), Size: info.Size()})
		}
		return nil
	})
	sort.Slice(found, func(i, j int) bool {
		if found[i].Size != found[j].Size {
			return found[i].Size > found[j].Size
		}
		return found[i].Path < found[j].Path
	})
	return found
}

// excludedDirectories are the directory names the scan already leaves out
// (the "name/*" entries of opengrepExcludes): no need to read their files.
func excludedDirectories() map[string]bool {
	names := map[string]bool{}
	for _, pattern := range opengrepExcludes() {
		if name, ok := strings.CutSuffix(pattern, "/*"); ok && !strings.ContainsAny(name, "*?[/") {
			names[name] = true
		}
	}
	return names
}

// machineWritten reads a file until it finds a line no person writes, or its end.
func machineWritten(path string, size int64) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	buffer := make([]byte, 64<<10)
	lines, current := int64(1), 0
	for {
		n, err := file.Read(buffer)
		for _, b := range buffer[:n] {
			if b == '\n' {
				lines++
				current = 0
			} else if current++; current >= generatedLongLine {
				return true
			}
		}
		if err != nil { // the end of the file, or a read error: judge what was read
			break
		}
	}
	return size/lines >= generatedAverageLine
}
