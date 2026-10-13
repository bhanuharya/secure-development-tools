package scanner

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// The engine's command line loads rule files one by one, slowly: 18 s for the
// 132 files of a typical scan, against 2.5 s for the same rules in one file.
// That was a quarter of a small repository's scan, every time.
//
// mergedRules writes that one file. A rule keeps the id it is reported with
// today: loading a rule file puts the file's directory (dots for slashes) in
// front of its rules' ids, so the merged file holds the ids with that prefix
// already and is loaded with --no-rewrite-rule-ids.
//
// Anything unusual in a rule file (an anchor, a second document, two rules
// with one id, a value that does not survive rewriting) is an error, and the
// caller then passes the files one by one as before.
//
// wanted, when it is set, leaves out the rules it answers no for; name is the
// merged file's name in the cache.
func mergedRules(files []string, root, cacheRoot, name string, wanted func(languages []string) bool) (string, error) {
	var merged []*yaml.Node
	var expected []any
	from := map[string]string{}
	for _, file := range files {
		rules, plain, err := rulesIn(file)
		if err != nil {
			return "", err
		}
		prefix := ruleIDPrefix(file, root)
		for i, rule := range rules {
			id := mappingValue(rule, "id")
			if id == nil || id.Kind != yaml.ScalarNode || id.Value == "" {
				return "", fmt.Errorf("%s: a rule without an id", file)
			}
			id.Value = prefix + id.Value
			if first, twice := from[id.Value]; twice {
				return "", fmt.Errorf("rule id %s is in both %s and %s", id.Value, first, file)
			}
			from[id.Value] = file
			if wanted != nil && !wanted(ruleLanguages(rule)) {
				continue
			}
			merged = append(merged, rule)
			plain[i]["id"] = id.Value
			expected = append(expected, plain[i])
		}
	}
	if len(merged) == 0 {
		return "", errors.New("no rules to merge")
	}
	document := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "rules"},
		{Kind: yaml.SequenceNode, Tag: "!!seq", Content: merged},
	}}}}
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return "", err
	}
	if err := encoder.Close(); err != nil {
		return "", err
	}
	// The file is only used if reading it back gives the rules that went in.
	var written struct {
		Rules []any `yaml:"rules"`
	}
	if err := yaml.Unmarshal(out.Bytes(), &written); err != nil {
		return "", fmt.Errorf("merged rules do not read back: %w", err)
	}
	if !reflect.DeepEqual(written.Rules, expected) {
		return "", errors.New("merged rules differ from the rule files")
	}
	path, err := nativeReportPath(cacheRoot, name)
	if err != nil {
		return "", err
	}
	// Written beside its final name and renamed: a scanner never reads half a file.
	temporary := fmt.Sprintf("%s.%d", path, os.Getpid())
	if err := os.WriteFile(temporary, out.Bytes(), 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return "", err
	}
	return path, nil
}

// rulesIn reads one rule file twice over: as nodes, which keep every value as
// it is written, and as plain values, to check the merged file against.
func rulesIn(file string) ([]*yaml.Node, []map[string]any, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document, second yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}
	if err := decoder.Decode(&second); !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("%s: more than one document", file)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode || len(document.Content[0].Content) != 2 {
		return nil, nil, fmt.Errorf("%s: expected only a rules list", file)
	}
	list := mappingValue(document.Content[0], "rules")
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil, nil, fmt.Errorf("%s: expected only a rules list", file)
	}
	var plain struct {
		Rules []map[string]any `yaml:"rules"`
	}
	if err := yaml.Unmarshal(raw, &plain); err != nil || len(plain.Rules) != len(list.Content) {
		return nil, nil, fmt.Errorf("%s: rules are not all mappings", file)
	}
	for _, rule := range list.Content {
		if rule.Kind != yaml.MappingNode || !portable(rule) {
			return nil, nil, fmt.Errorf("%s: a rule uses an anchor or an alias", file)
		}
	}
	return list.Content, plain.Rules, nil
}

// portable reports whether a node can move to another document unchanged (no
// anchors or aliases), and drops its comments, which rules do not depend on.
// A folded block scalar (">") is written back double-quoted: the YAML library
// adds a blank line when it re-folds one that has indented lines, which would
// change a multi-line pattern.
func portable(node *yaml.Node) bool {
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return false
	}
	node.HeadComment, node.LineComment, node.FootComment = "", "", ""
	if node.Kind == yaml.ScalarNode && node.Style&yaml.FoldedStyle != 0 {
		node.Style = yaml.DoubleQuotedStyle
	}
	for _, child := range node.Content {
		if !portable(child) {
			return false
		}
	}
	return true
}

// ruleLanguages is the languages list of a rule; nil when it has none.
func ruleLanguages(rule *yaml.Node) []string {
	list := mappingValue(rule, "languages")
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil
	}
	var languages []string
	for _, item := range list.Content {
		languages = append(languages, item.Value)
	}
	return languages
}

// languageExtensions lists, for the languages the rule pack has rules for, the
// file names the engine reads as that language. A list here must not be
// shorter than the engine's own: a rule is left out of a staged scan when no
// staged file has one of its languages' extensions.
var languageExtensions = map[string][]string{
	"python": {".py", ".pyi", ".pyw"}, "python2": {".py", ".pyi", ".pyw"}, "python3": {".py", ".pyi", ".pyw"}, "py": {".py", ".pyi", ".pyw"},
	"javascript": {".js", ".jsx", ".cjs", ".mjs", ".vue"}, "js": {".js", ".jsx", ".cjs", ".mjs", ".vue"},
	"typescript": {".ts", ".tsx", ".mts", ".cts", ".vue"}, "ts": {".ts", ".tsx", ".mts", ".cts", ".vue"},
	"go": {".go"}, "golang": {".go"},
	"java":   {".java"},
	"kotlin": {".kt", ".kts", ".ktm"}, "kt": {".kt", ".kts", ".ktm"},
	"php":   {".php", ".phtml", ".tpl", ".inc", ".php3", ".php4", ".php5", ".phps"},
	"c":     {".c", ".h"},
	"rust":  {".rs"},
	"scala": {".scala", ".sc"},
	"json":  {".json", ".ipynb"},
	"yaml":  {".yaml", ".yml"},
	"dart":  {".dart"},
}

// rulesFor answers which rules a scan of the files under dir can need. A rule
// is needed unless every language it names is in languageExtensions and no
// file has one of those extensions. A rule for any file (generic, regex) or
// for a language not in the table is always needed.
//
// The answer is nil, meaning every rule, when a file has no extension and
// starts with "#!": the engine reads the interpreter's name there, and this
// function does not.
func rulesFor(dir string) func(languages []string) bool {
	extensions := map[string]bool{}
	script := false
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if extension != "" {
			extensions[extension] = true
			return nil
		}
		if file, err := os.Open(path); err == nil {
			start := make([]byte, 2)
			if n, _ := io.ReadFull(file, start); n == 2 && string(start) == "#!" {
				script = true
			}
			file.Close()
		}
		return nil
	})
	if script {
		return nil
	}
	return func(languages []string) bool {
		if len(languages) == 0 {
			return true
		}
		for _, language := range languages {
			known, ok := languageExtensions[strings.ToLower(language)]
			if !ok {
				return true
			}
			for _, extension := range known {
				if extensions[extension] {
					return true
				}
			}
		}
		return false
	}
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

// ruleIDPrefix is what the engine's command line puts in front of the id of a
// rule loaded from file: the file's directory with dots for slashes, relative
// to the directory it runs in (the scan root) when the file is inside it.
func ruleIDPrefix(file, root string) string {
	dir := filepath.Dir(file)
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	if rel, err := filepath.Rel(root, dir); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		dir = rel
	}
	parts := strings.FieldsFunc(filepath.ToSlash(dir), func(r rune) bool { return r == '/' })
	if len(parts) == 0 || (len(parts) == 1 && parts[0] == ".") {
		return ""
	}
	return strings.Join(parts, ".") + "."
}
