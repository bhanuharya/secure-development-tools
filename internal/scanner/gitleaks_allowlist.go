package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// A repository's .gitleaks.toml is trusted by default, so a pull request could add an
// allowlist that lets every file or every value through and switch secret scanning off.
// catchAllGitleaksReason reads the parts of the file that decide this and names the
// first problem it finds. A pattern counts as a catch-all when it allows every sample
// below. That is a test of behaviour, not of spelling: '''.*''', '''(.*)''', '''.*?''',
// '''[\s\S]*''' and '''.''' all fail it the same way. A pattern written to allow almost
// everything except these samples still passes; scanners.gitleaks.trustRepoConfig: false
// is the setting for repositories whose pull request authors are not trusted.

// allowlistPathSamples are file paths as Gitleaks sees them: absolute in a current-tree
// scan, relative in a history scan.
var allowlistPathSamples = []string{
	"/work/repo/src/main/java/com/example/App.java",
	"src/main/resources/application.yml",
	"internal/service/payment.go",
	".env",
	"x",
}

// allowlistValueSamples are short, low-entropy stand-ins for the values a rule reports.
var allowlistValueSamples = []string{"hunter2", "ABCD1234", "x", "p@ss-w0rd"}

// maxGitleaksExtendDepth follows [extend] path as far as Gitleaks itself does from a
// repository config (the sdt config extends the repository file, which may extend one more).
const maxGitleaksExtendDepth = 2

type gitleaksAllowlist struct {
	where     string
	condition string
	commits   int
	paths     []string
	regexes   []string
	stopwords []string
}

type gitleaksRepoConfig struct {
	allowlists      []*gitleaksAllowlist
	extendPath      string
	useDefaultFalse bool
	hasRules        bool
}

// unsafeRepoGitleaksReason returns why the repository config at path must not be
// extended, or "" when it is safe to use.
func unsafeRepoGitleaksReason(path string) string {
	root := filepath.Dir(path)
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	return checkRepoGitleaksConfig(root, path, 0)
}

func checkRepoGitleaksConfig(root, path string, depth int) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "unreadable config"
	}
	cfg, err := parseGitleaksRepoConfig(string(raw))
	if err != nil {
		return "could not be read for the catch-all allowlist check: " + err.Error()
	}
	for _, al := range cfg.allowlists {
		if reason := al.catchAll(); reason != "" {
			return reason + ", which would switch off secret scanning"
		}
	}
	if cfg.useDefaultFalse && !cfg.hasRules {
		return "useDefault = false without custom rules would switch off secret scanning"
	}
	if cfg.extendPath == "" || depth+1 >= maxGitleaksExtendDepth {
		return ""
	}
	// Gitleaks resolves a relative extend path from its working directory, the scan root.
	next := cfg.extendPath
	if !filepath.IsAbs(next) {
		next = filepath.Join(root, next)
	}
	resolved, err := filepath.EvalSymlinks(next)
	if err != nil || (resolved != root && !strings.HasPrefix(resolved, root+string(filepath.Separator))) {
		return fmt.Sprintf("[extend] path %q is outside the repository or cannot be read", cfg.extendPath)
	}
	if reason := checkRepoGitleaksConfig(root, resolved, depth+1); reason != "" {
		return fmt.Sprintf("extended config %q: %s", cfg.extendPath, reason)
	}
	return ""
}

// catchAll names the criterion that makes this allowlist allow everything, or "".
// Criteria are OR'ed unless condition = "AND", when every one of them must allow
// everything; a commit list never does.
func (al *gitleaksAllowlist) catchAll() string {
	var hits []string
	criteria := 0
	if len(al.paths) > 0 {
		criteria++
		if p, ok := firstCatchAllPattern(al.paths, allowlistPathSamples); ok {
			hits = append(hits, fmt.Sprintf("%s paths pattern %q matches every path", al.where, p))
		}
	}
	if len(al.regexes) > 0 {
		criteria++
		if p, ok := firstCatchAllPattern(al.regexes, allowlistValueSamples); ok {
			hits = append(hits, fmt.Sprintf("%s regexes pattern %q matches every value", al.where, p))
		}
	}
	if len(al.stopwords) > 0 {
		criteria++
		if w, ok := firstCatchAllStopword(al.stopwords); ok {
			hits = append(hits, fmt.Sprintf("%s stopword %q is part of every value", al.where, w))
		}
	}
	if al.commits > 0 {
		criteria++
	}
	if len(hits) == 0 {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(al.condition), "AND") && len(hits) < criteria {
		return ""
	}
	return hits[0]
}

func firstCatchAllPattern(patterns, samples []string) (string, bool) {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue // Gitleaks refuses the file itself; nothing is allowed through
		}
		all := true
		for _, s := range samples {
			if !re.MatchString(s) {
				all = false
				break
			}
		}
		if all {
			return p, true
		}
	}
	return "", false
}

func firstCatchAllStopword(words []string) (string, bool) {
	for _, w := range words {
		lw := strings.ToLower(w)
		all := true
		for _, s := range allowlistValueSamples {
			if !strings.Contains(strings.ToLower(s), lw) {
				all = false
				break
			}
		}
		if all {
			return w, true
		}
	}
	return "", false
}

// parseGitleaksRepoConfig reads the allowlists, [extend] and [[rules]] of a gitleaks
// TOML file. It understands the TOML a config can use to write them: [allowlist],
// [[allowlists]], [rules.allowlist], [[rules.allowlists]], dotted keys, inline tables
// and arrays of them, and all four string forms. Anything it cannot parse is an error,
// so a file written to confuse this reader is not extended.
func parseGitleaksRepoConfig(text string) (*gitleaksRepoConfig, error) {
	p := &tomlReader{s: text}
	cfg := &gitleaksRepoConfig{}
	groups := map[string]*gitleaksAllowlist{}
	var table []string
	header := 0
	for {
		p.skipBlankLinesAndComments()
		if p.eof() {
			break
		}
		if p.peek() == '[' {
			double := strings.HasPrefix(p.s[p.i:], "[[")
			p.i++
			if double {
				p.i++
			}
			p.skipSpaces()
			key, err := p.key()
			if err != nil {
				return nil, err
			}
			p.skipSpaces()
			closing := "]"
			if double {
				closing = "]]"
			}
			if !strings.HasPrefix(p.s[p.i:], closing) {
				return nil, p.errorf("unterminated table header")
			}
			p.i += len(closing)
			if err := p.endOfLine(); err != nil {
				return nil, err
			}
			table = key
			header++
			if double && len(key) == 1 && key[0] == "rules" {
				cfg.hasRules = true
			}
			continue
		}
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		p.skipSpaces()
		if p.eof() || p.peek() != '=' {
			return nil, p.errorf("expected '=' after key")
		}
		p.i++
		p.skipSpaces()
		val, err := p.value()
		if err != nil {
			return nil, err
		}
		if err := p.endOfLine(); err != nil {
			return nil, err
		}
		full := append(append([]string{}, table...), key...)
		collectGitleaksSettings(cfg, groups, strconv.Itoa(header), full, val)
	}
	return cfg, nil
}

// collectGitleaksSettings records one assignment. group tells allowlists apart: each
// table header starts a new one, and each inline table in an array is its own.
func collectGitleaksSettings(cfg *gitleaksRepoConfig, groups map[string]*gitleaksAllowlist, group string, key []string, val tomlValue) {
	switch val.kind {
	case tomlTable:
		for _, kv := range val.table {
			collectGitleaksSettings(cfg, groups, group, append(append([]string{}, key...), kv.key...), kv.val)
		}
		return
	case tomlArray:
		if len(val.array) > 0 && val.array[0].kind == tomlTable {
			for i, item := range val.array {
				collectGitleaksSettings(cfg, groups, fmt.Sprintf("%s#%d", group, i), key, item)
			}
			return
		}
	}
	n := len(key)
	if n == 2 && key[0] == "extend" {
		switch key[1] {
		case "path":
			if val.kind == tomlString {
				cfg.extendPath = val.str
			}
		case "useDefault":
			cfg.useDefaultFalse = val.kind == tomlOther && val.str == "false"
		}
		return
	}
	if n >= 2 && key[0] == "rules" {
		cfg.hasRules = true
	}
	if n < 2 || (key[n-2] != "allowlist" && key[n-2] != "allowlists") {
		return
	}
	where := "[" + strings.Join(key[:n-1], ".") + "]"
	id := group + "/" + strings.Join(key[:n-1], ".")
	al := groups[id]
	if al == nil {
		al = &gitleaksAllowlist{where: where}
		groups[id] = al
		cfg.allowlists = append(cfg.allowlists, al)
	}
	switch key[n-1] {
	case "paths":
		al.paths = append(al.paths, val.strings()...)
	case "regexes":
		al.regexes = append(al.regexes, val.strings()...)
	case "stopwords":
		al.stopwords = append(al.stopwords, val.strings()...)
	case "commits":
		al.commits += len(val.strings())
	case "condition":
		al.condition = val.str
	}
}

type tomlKind int

const (
	tomlOther tomlKind = iota
	tomlString
	tomlArray
	tomlTable
)

type tomlValue struct {
	kind  tomlKind
	str   string // a string's value, or the raw text of a number, boolean or date
	array []tomlValue
	table []tomlKeyValue
}

type tomlKeyValue struct {
	key []string
	val tomlValue
}

// strings returns a string value, or every string inside an array value.
func (v tomlValue) strings() []string {
	switch v.kind {
	case tomlString:
		return []string{v.str}
	case tomlArray:
		var out []string
		for _, item := range v.array {
			out = append(out, item.strings()...)
		}
		return out
	}
	return nil
}

// tomlReader is just enough TOML for parseGitleaksRepoConfig.
type tomlReader struct {
	s string
	i int
}

func (p *tomlReader) eof() bool  { return p.i >= len(p.s) }
func (p *tomlReader) peek() byte { return p.s[p.i] }

func (p *tomlReader) errorf(format string, args ...any) error {
	line := 1 + strings.Count(p.s[:min(p.i, len(p.s))], "\n")
	return fmt.Errorf("line %d: %s", line, fmt.Sprintf(format, args...))
}

func (p *tomlReader) skipSpaces() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.i++
	}
}

func (p *tomlReader) skipComment() {
	if !p.eof() && p.peek() == '#' {
		for !p.eof() && p.peek() != '\n' {
			p.i++
		}
	}
}

func (p *tomlReader) skipBlankLinesAndComments() {
	for !p.eof() {
		switch p.peek() {
		case ' ', '\t', '\r', '\n':
			p.i++
		case '#':
			p.skipComment()
		default:
			return
		}
	}
}

// endOfLine accepts trailing spaces and a comment before the newline.
func (p *tomlReader) endOfLine() error {
	p.skipSpaces()
	p.skipComment()
	if p.eof() {
		return nil
	}
	if p.peek() == '\r' {
		p.i++
	}
	if p.eof() || p.peek() == '\n' {
		return nil
	}
	return p.errorf("unexpected text after value")
}

// key reads a bare, quoted or dotted key.
func (p *tomlReader) key() ([]string, error) {
	var parts []string
	for {
		p.skipSpaces()
		if p.eof() {
			return nil, p.errorf("expected a key")
		}
		switch c := p.peek(); {
		case c == '"' || c == '\'':
			v, err := p.str()
			if err != nil {
				return nil, err
			}
			parts = append(parts, v)
		default:
			start := p.i
			for !p.eof() && isBareKeyChar(p.peek()) {
				p.i++
			}
			if p.i == start {
				return nil, p.errorf("expected a key")
			}
			parts = append(parts, p.s[start:p.i])
		}
		p.skipSpaces()
		if p.eof() || p.peek() != '.' {
			return parts, nil
		}
		p.i++
	}
}

func isBareKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func (p *tomlReader) value() (tomlValue, error) {
	if p.eof() {
		return tomlValue{}, p.errorf("expected a value")
	}
	switch p.peek() {
	case '"', '\'':
		s, err := p.str()
		return tomlValue{kind: tomlString, str: s}, err
	case '[':
		return p.arrayValue()
	case '{':
		return p.inlineTable()
	}
	start := p.i
	for !p.eof() && !strings.ContainsRune(",]}#\r\n", rune(p.peek())) {
		p.i++
	}
	raw := strings.TrimSpace(p.s[start:p.i])
	if raw == "" {
		return tomlValue{}, p.errorf("expected a value")
	}
	return tomlValue{kind: tomlOther, str: raw}, nil
}

func (p *tomlReader) arrayValue() (tomlValue, error) {
	p.i++ // [
	out := tomlValue{kind: tomlArray}
	for {
		p.skipBlankLinesAndComments()
		if p.eof() {
			return out, p.errorf("unterminated array")
		}
		if p.peek() == ']' {
			p.i++
			return out, nil
		}
		v, err := p.value()
		if err != nil {
			return out, err
		}
		out.array = append(out.array, v)
		p.skipBlankLinesAndComments()
		if p.eof() {
			return out, p.errorf("unterminated array")
		}
		switch p.peek() {
		case ',':
			p.i++
		case ']':
			p.i++
			return out, nil
		default:
			return out, p.errorf("expected ',' or ']' in array")
		}
	}
}

func (p *tomlReader) inlineTable() (tomlValue, error) {
	p.i++ // {
	out := tomlValue{kind: tomlTable}
	for {
		p.skipBlankLinesAndComments()
		if p.eof() {
			return out, p.errorf("unterminated inline table")
		}
		if p.peek() == '}' {
			p.i++
			return out, nil
		}
		k, err := p.key()
		if err != nil {
			return out, err
		}
		p.skipSpaces()
		if p.eof() || p.peek() != '=' {
			return out, p.errorf("expected '=' in inline table")
		}
		p.i++
		p.skipSpaces()
		v, err := p.value()
		if err != nil {
			return out, err
		}
		out.table = append(out.table, tomlKeyValue{key: k, val: v})
		p.skipBlankLinesAndComments()
		if p.eof() {
			return out, p.errorf("unterminated inline table")
		}
		switch p.peek() {
		case ',':
			p.i++
		case '}':
			p.i++
			return out, nil
		default:
			return out, p.errorf("expected ',' or '}' in inline table")
		}
	}
}

// str reads any of the four TOML string forms at the current position.
func (p *tomlReader) str() (string, error) {
	rest := p.s[p.i:]
	switch {
	case strings.HasPrefix(rest, `"""`):
		return p.multiline('"', true)
	case strings.HasPrefix(rest, `'''`):
		return p.multiline('\'', false)
	case rest[0] == '\'':
		end := strings.IndexAny(rest[1:], "'\n")
		if end < 0 || rest[1+end] != '\'' {
			return "", p.errorf("unterminated literal string")
		}
		p.i += end + 2
		return rest[1 : 1+end], nil
	}
	p.i++ // "
	var b strings.Builder
	for {
		if p.eof() || p.peek() == '\n' {
			return "", p.errorf("unterminated string")
		}
		c := p.peek()
		if c == '"' {
			p.i++
			return b.String(), nil
		}
		if c == '\\' {
			if err := p.escape(&b); err != nil {
				return "", err
			}
			continue
		}
		b.WriteByte(c)
		p.i++
	}
}

// multiline reads a multi-line string (three single or three double quotes). A
// newline right after the opening quotes is dropped, and up to two quotes may stand
// right before the closing ones.
func (p *tomlReader) multiline(q byte, escapes bool) (string, error) {
	p.i += 3
	if strings.HasPrefix(p.s[p.i:], "\r\n") {
		p.i += 2
	} else if !p.eof() && p.peek() == '\n' {
		p.i++
	}
	var b strings.Builder
	for {
		if p.eof() {
			return "", p.errorf("unterminated multi-line string")
		}
		c := p.peek()
		if c == q {
			n := 0
			for p.i+n < len(p.s) && p.s[p.i+n] == q {
				n++
			}
			if n >= 3 {
				if n > 5 {
					return "", p.errorf("too many quotes closing a multi-line string")
				}
				b.WriteString(strings.Repeat(string(q), n-3))
				p.i += n
				return b.String(), nil
			}
			b.WriteString(strings.Repeat(string(q), n))
			p.i += n
			continue
		}
		if escapes && c == '\\' {
			// A backslash at the end of a line joins it to the next non-blank text.
			j := p.i + 1
			for j < len(p.s) && (p.s[j] == ' ' || p.s[j] == '\t') {
				j++
			}
			if j < len(p.s) && (p.s[j] == '\n' || p.s[j] == '\r') {
				for j < len(p.s) && strings.ContainsRune(" \t\r\n", rune(p.s[j])) {
					j++
				}
				p.i = j
				continue
			}
			if err := p.escape(&b); err != nil {
				return "", err
			}
			continue
		}
		b.WriteByte(c)
		p.i++
	}
}

// escape reads one backslash escape of a basic string.
func (p *tomlReader) escape(b *strings.Builder) error {
	if p.i+1 >= len(p.s) {
		return p.errorf("unterminated escape")
	}
	c := p.s[p.i+1]
	p.i += 2
	switch c {
	case 'b':
		b.WriteByte('\b')
	case 't':
		b.WriteByte('\t')
	case 'n':
		b.WriteByte('\n')
	case 'f':
		b.WriteByte('\f')
	case 'r':
		b.WriteByte('\r')
	case 'e':
		b.WriteByte(0x1b)
	case '"':
		b.WriteByte('"')
	case '\\':
		b.WriteByte('\\')
	case 'x', 'u', 'U':
		size := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
		if p.i+size > len(p.s) {
			return p.errorf("short \\%c escape", c)
		}
		n, err := strconv.ParseUint(p.s[p.i:p.i+size], 16, 32)
		if err != nil {
			return p.errorf("bad \\%c escape", c)
		}
		b.WriteRune(rune(n))
		p.i += size
	default:
		return p.errorf("unknown escape \\%c", c)
	}
	return nil
}
