package endpoints

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/config"
	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// AnalyzeWithRoot runs Analyze plus source-backed handler logic-abuse checks
// (BOLA/IDOR unscoped object access) and deterministic security invariants from
// .secure-dev/invariants.yaml when present. When root is empty, it falls back
// cleanly to route-only Analyze.
func AnalyzeWithRoot(root string, inv *Inventory, cfg config.EndpointsCfg) ([]*finding.Finding, error) {
	base, err := Analyze(inv, cfg)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(root) == "" || inv == nil || len(inv.Routes) == 0 {
		return base, nil
	}
	invDoc, err := LoadInvariants(root)
	if err != nil {
		return nil, err
	}
	rules, err := newConventionRules(cfg)
	if err != nil {
		return nil, err
	}
	bolaFindings := analyzeBOLA(root, sanitizeInventory(inv), rules)
	invFindings := EvaluateInvariants(root, inv, invDoc)
	if len(bolaFindings) == 0 && len(invFindings) == 0 {
		return base, nil
	}
	// Avoid duplicating a route that already received a higher-severity route finding.
	covered := make(map[string]bool, len(base))
	for _, f := range base {
		ep, _ := f.Metadata["endpoint"].(string)
		path := ""
		line := 0
		if f.Location != nil {
			path = f.Location.Path
			if f.Location.StartLine != nil {
				line = *f.Location.StartLine
			}
		}
		covered[fmt.Sprintf("%s|%s|%d", ep, path, line)] = true
	}
	merged := append([]*finding.Finding{}, base...)
	for _, f := range bolaFindings {
		ep, _ := f.Metadata["endpoint"].(string)
		key := fmt.Sprintf("%s|%s|%d", ep, f.Location.Path, *f.Location.StartLine)
		if covered[key] {
			continue
		}
		merged = append(merged, f)
	}
	// Explicit repo security invariants are always reported (never masked by
	// heuristic convention warnings).
	merged = append(merged, invFindings...)
	sortFindings(merged)
	for i, f := range merged {
		f.ID = fmt.Sprintf("endpoints:%05d", i+1)
	}
	return merged, nil
}

// pathParamRe extracts `{name}` template parameters from normalized route paths.
var pathParamRe = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_-]*)\}`)

// nonObjectParamRe lists path parameters that typically select a catalog,
// language, format, or pagination slice rather than a user-owned record.
var nonObjectParamRe = regexp.MustCompile(`(?i)^(version|ver|v|lang|language|locale|country|currency|region|zone|format|ext|page|slug|category|type|kind|status|tag|topic|code|state)$`)

// objectParamRe identifies path parameters that name a specific object/record.
var objectParamRe = regexp.MustCompile(`(?i)^(id|uuid|guid|pk|key|.*_?id|.*Id|.*Uuid|.*UUID|account|order|user|invoice|wallet|payment|transfer|document|doc|file|record|profile|customer|member|ticket|loan|card|project|org|tenant|subscription|session|tx|transaction)$`)

// directDataAccessRe matches unmistakable repository / ORM / SQL calls that
// fetch, update, or delete a record directly from a store.
var directDataAccessRe = regexp.MustCompile(
	`\b(` +
		`findById|getById|getReferenceById|deleteById|removeById|updateById|existsById|findOneById|` +
		`FindByID|FindById|GetByID|GetById|DeleteByID|DeleteById|UpdateByID|UpdateById|` +
		`findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findByPk|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|deleteOne|updateOne|findOneAndUpdate|findOneAndDelete|` +
		`get_object_or_404|QueryRow|QueryRowContext|ExecContext|` +
		`db\.(?:First|Take|Find|Delete|Updates|Update|Save|Model|Where|Exec|QueryRow|query|get|execute|scalar|scalars|delete)|` +
		`(?:objects|session)\.(?:get|filter|query|delete|execute|scalar|scalars)` +
		`)\s*\(` +
		`|(?i)\b(?:SELECT\s+.+\s+FROM\s+\w+\s+WHERE|UPDATE\s+\w+\s+SET\s+.+\s+WHERE|DELETE\s+FROM\s+\w+\s+WHERE)\b`,
)

// ownershipQueryRe matches repository/ORM calls whose name or query explicitly
// scopes the object lookup to the caller, owner, user, account, or tenant.
var ownershipQueryRe = regexp.MustCompile(
	`(?i)\b(?:find|get|delete|remove|update|exists)\w*ByIdAnd(?:User|Owner|Tenant|Account|Member|Org|Organization|Customer|Caller|Creator|Author)\w*\s*\(` +
		`|(?i)\b(?:find|get|delete|update)\w*(?:ForUser|ForOwner|ForTenant|OwnedBy|ByOwner)\w*\s*\(` +
		`|(?i)\b(?:user_id|owner_id|tenant_id|account_id|org_id|created_by)\s*=\s*`,
)

// principalBindingRe detects references to the authenticated caller, principal,
// session user, JWT claims, tenant, or explicit ownership verification inside
// a handler signature or body.
var principalBindingRe = regexp.MustCompile(
	`\b(` +
		`Principal|Authentication|AuthenticationPrincipal|SecurityContextHolder|SecurityUtils|` +
		`getUserPrincipal|getCurrentUser|currentUser|current_user|get_current_user|loggedInUser|authUser|sessionUser|` +
		`req\.user|req\.auth|req\.session|request\.user|ctx\.user|context\.user|` +
		`c\.Locals|ctx\.Locals|c\.UserContext|r\.Context\(\)\.Value|` +
		`userFromContext|callerFromContext|principalFromContext|actorFromContext|tenantFromContext|` +
		`claims\.|jwtClaims|tokenClaims|` +
		`checkOwner\w*|verifyOwner\w*|assertOwner\w*|ensureOwner\w*|isOwner\w*|canAccess\w*|authorize\w*` +
		`)\b` +
		`|(?i)\bc\.Get\s*\(\s*["'](?:user|uid|sub|subject|principal|claims|account|tenant|owner|caller|actor|member|auth)[^"']*["']\s*\)` +
		`|(?i)\b(?:caller|current|auth|session|logged_?in|verified)_?(?:user|account|tenant|owner|member|org)_?(?:id)?\b`,
)

// objectPathParams returns the object-identifying `{param}` names in path.
func objectPathParams(path string) []string {
	matches := pathParamRe.FindAllStringSubmatch(path, -1)
	if len(matches) == 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range matches {
		name := m[1]
		if seen[name] || nonObjectParamRe.MatchString(name) {
			continue
		}
		if objectParamRe.MatchString(name) {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

type bolaCandidate struct {
	route      Route
	params     []string
	dataAccess string
	endLine    int
}

type boundPeer struct {
	handler string
	file    string
	line    int
}

// credentialOrContactWords are whole-word tokens in route paths or handler
// names that indicate a state-changing BOLA endpoint can take over an account.
var credentialOrContactWords = map[string]bool{
	"password": true,
	"passwd":   true,
	"pin":      true,
	"otp":      true,
	"email":    true,
	"mobile":   true,
	"phone":    true,
	"mfa":      true,
	"session":  true,
	"token":    true,
}

// splitIdentifierWords splits s on non-ASCII letters and camelCase boundaries,
// returning lowercased whole words ("reset-pin", "resetPin", "reset_pin" all
// yield "reset" and "pin"; "shipping", "mapping", "opinion", "tokenizer" stay
// intact and do not match "pin" or "token").
func splitIdentifierWords(s string) []string {
	var words []string
	n := len(s)
	start := -1
	isLower := func(b byte) bool { return b >= 'a' && b <= 'z' }
	isUpper := func(b byte) bool { return b >= 'A' && b <= 'Z' }
	isLetter := func(b byte) bool { return isLower(b) || isUpper(b) }
	for i := 0; i < n; i++ {
		b := s[i]
		if !isLetter(b) {
			if start >= 0 {
				words = append(words, strings.ToLower(s[start:i]))
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		prev := s[i-1]
		if isUpper(b) && (isLower(prev) || (i+1 < n && isLower(s[i+1]))) {
			words = append(words, strings.ToLower(s[start:i]))
			start = i
		}
	}
	if start >= 0 {
		words = append(words, strings.ToLower(s[start:]))
	}
	return words
}

func hasCredentialOrContactWord(s string) bool {
	for _, w := range splitIdentifierWords(s) {
		if credentialOrContactWords[w] {
			return true
		}
	}
	return false
}

// bolaImpact classifies a BOLA finding from its HTTP verb and target resource:
// state-changing credential/contact routes are account-takeover, other state
// changes are logic-abuse, and reads (GET/HEAD) are data-exposure.
func bolaImpact(rt Route) string {
	if !isStateChanging(rt.Method) {
		return "data-exposure"
	}
	if hasCredentialOrContactWord(rt.Path) || hasCredentialOrContactWord(rt.Handler) {
		return "account-takeover"
	}
	return "logic-abuse"
}

func analyzeBOLA(root string, inv *Inventory, rules *conventionRules) []*finding.Finding {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil
	}
	if resolved, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = resolved
	}

	byService := map[string][]Route{}
	var services []string
	for _, rt := range inv.Routes {
		rt = effective(rt)
		if _, ok := byService[rt.Service]; !ok {
			services = append(services, rt.Service)
		}
		byService[rt.Service] = append(byService[rt.Service], rt)
	}
	sort.Strings(services)

	var out []*finding.Finding
	for _, svc := range services {
		var candidates []bolaCandidate
		var peers []boundPeer
		for _, rt := range byService[svc] {
			// BOLA check targets authenticated user-facing routes: role-gated
			// admin endpoints and public/unknown/denied routes are handled by
			// route-level rules.
			if rt.Protection != ProtAuthenticated {
				continue
			}
			if rules.isPublicPath(rt.Path) {
				continue
			}
			params := objectPathParams(rt.Path)
			if len(params) == 0 {
				continue
			}
			body, endLine, ok := extractHandlerBody(absRoot, rt)
			if !ok || strings.TrimSpace(body) == "" {
				continue // soundness: unreadable or unresolvable handler -> stay silent
			}
			if hasPrincipalOrOwnershipCheck(body) {
				peers = append(peers, boundPeer{handler: rt.Handler, file: rt.File, line: rt.Line})
				continue
			}
			access := findDirectDataAccess(body)
			if access == "" {
				continue // soundness: only flag concrete direct store access, not opaque delegates
			}
			candidates = append(candidates, bolaCandidate{route: rt, params: params, dataAccess: access, endLine: endLine})
		}
		for _, cand := range candidates {
			out = append(out, bolaFinding(cand, peers))
		}
	}
	return out
}

func hasPrincipalOrOwnershipCheck(code string) bool {
	return ownershipQueryRe.MatchString(code) || principalBindingRe.MatchString(code)
}

func findDirectDataAccess(code string) string {
	m := directDataAccessRe.FindStringSubmatch(code)
	if len(m) == 0 {
		return ""
	}
	if len(m) > 1 && m[1] != "" {
		return m[1]
	}
	// SQL match: return a short redacted summary rather than raw query text.
	upper := strings.ToUpper(strings.TrimSpace(m[0]))
	switch {
	case strings.HasPrefix(upper, "DELETE"):
		return "SQL DELETE ... WHERE"
	case strings.HasPrefix(upper, "UPDATE"):
		return "SQL UPDATE ... WHERE"
	default:
		return "SQL SELECT ... WHERE"
	}
}

func bolaFinding(cand bolaCandidate, peers []boundPeer) *finding.Finding {
	rt := cand.route
	paramList := "{" + strings.Join(cand.params, "}, {") + "}"
	peerNote := ""
	confidence := "medium"
	if len(peers) > 0 {
		confidence = "high"
		p := peers[0]
		name := p.handler
		if name == "" {
			name = "a peer handler"
		}
		peerNote = fmt.Sprintf(" Peer handler %s (%s:%d) in this service binds caller identity before accessing objects.", name, p.file, p.line)
	}
	msg := fmt.Sprintf("%s %s accepts object parameter %s and performs direct store access (%s) without referencing the authenticated caller, owner, or tenant.%s Any logged-in user who guesses or enumerates %s may read or modify another user's record (BOLA/IDOR). Scope the query to the authenticated principal or tenant ID.",
		rt.Method, rt.shownPath(), paramList, cand.dataAccess, peerNote, paramList)
	severity := "warning"
	if isStateChanging(rt.Method) {
		severity = "error"
	}
	f := newConventionFinding(rt, RuleBolaUnscopedObjectAccess,
		"Authenticated object route accesses store without caller ownership check",
		"Derive the caller or tenant identity from the verified session/token and filter the database query (or verify record ownership) before returning or mutating the object.",
		[]string{"CWE-639"}, severity, msg)
	if cand.endLine > rt.Line {
		endLine := cand.endLine
		f.Location.EndLine = &endLine
	}
	f.Confidence = confidence
	f.Metadata["objectParams"] = cand.params
	f.Metadata["dataAccess"] = cand.dataAccess
	f.Metadata["impact"] = bolaImpact(rt)
	return f
}

// readConfinedFile reads rel under absRoot, rejecting path traversal or symlink
// escapes outside absRoot.
func readConfinedFile(absRoot, rel string) ([]byte, bool) {
	if rel == "" || filepath.IsAbs(rel) {
		return nil, false
	}
	full := filepath.Join(absRoot, filepath.FromSlash(rel))
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, false
	}
	if resolved != absRoot && !strings.HasPrefix(resolved, absRoot+string(filepath.Separator)) {
		return nil, false
	}
	raw, err := os.ReadFile(resolved)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// extractHandlerBody locates the route's handler source (signature + body) for
// Spring, Go, Express/NestJS, and Flask/FastAPI. It also returns the 1-based
// closing line in rt.File when the handler body is anchored at rt.Line (0 when
// the named handler lives elsewhere in the file or in a sibling file). Returns
// ("", 0, false) whenever the body cannot be located cleanly.
func extractHandlerBody(absRoot string, rt Route) (string, int, bool) {
	src, ok := readConfinedFile(absRoot, rt.File)
	if !ok {
		return "", 0, false
	}
	switch {
	case strings.HasPrefix(rt.Framework, "spring"):
		return extractBraceDeclFromLine(src, rt.Line)
	case rt.Framework == "flask" || rt.Framework == "fastapi":
		return extractPythonDefFromLine(src, rt.Line)
	case rt.Framework == "nestjs":
		return extractBraceDeclFromLine(src, rt.Line)
	case rt.Framework == "express":
		if body, endLine, ok := extractInlineJSFromLine(src, rt.Line); ok {
			return body, endLine, true
		}
		return extractNamedJSHandler(src, rt.Handler)
	default:
		// Go frameworks: gin, echo, fiber, chi, nethttp.
		if body, endLine, ok := extractInlineGoFromLine(src, rt.Line); ok {
			return body, endLine, true
		}
		return extractNamedGoHandler(absRoot, rt.File, src, rt.Handler)
	}
}

// lineStartOffset returns the byte offset of 1-based line in src.
func lineStartOffset(src []byte, line int) int {
	if line <= 1 {
		return 0
	}
	cur := 1
	for i, b := range src {
		if b == '\n' {
			cur++
			if cur == line {
				return i + 1
			}
		}
	}
	return -1
}

// lineNumberAt returns the 1-based line number of byte offset in src.
func lineNumberAt(src []byte, offset int) int {
	if offset < 0 {
		return 0
	}
	if offset > len(src) {
		offset = len(src)
	}
	return 1 + bytes.Count(src[:offset], []byte{'\n'})
}

// extractBalancedBlock returns src[sigStart : closeBrace+1] and the 1-based
// line of closeBrace starting from the first `{` at or after searchFrom,
// skipping strings and // or /* */ comments.
func extractBalancedBlock(src []byte, sigStart, searchFrom int) (string, int, bool) {
	open := -1
	quote := byte(0)
	for i := searchFrom; i < len(src); i++ {
		c := src[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if next, ok := skipComment(src, i); ok {
			i = next - 1
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			quote = c
			continue
		}
		if c == ';' {
			return "", 0, false // abstract/interface declaration without a body
		}
		if c == '{' {
			open = i
			break
		}
	}
	if open < 0 {
		return "", 0, false
	}
	depth := 0
	quote = 0
	for i := open; i < len(src); i++ {
		c := src[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if next, ok := skipComment(src, i); ok {
			i = next - 1
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return string(src[sigStart : i+1]), lineNumberAt(src, i), true
			}
		}
	}
	return "", 0, false
}

// extractBraceDeclFromLine extracts a Spring/NestJS annotated method starting
// at or just after rt.Line.
func extractBraceDeclFromLine(src []byte, line int) (string, int, bool) {
	start := lineStartOffset(src, line)
	if start < 0 {
		return "", 0, false
	}
	return extractBalancedBlock(src, start, start)
}

// extractPythonDefFromLine extracts the `def` / `async def` block at or after
// decorator line `line`, stopping when indentation returns to or left of `def`,
// and returns the 1-based line of the handler body's last non-blank line.
func extractPythonDefFromLine(src []byte, line int) (string, int, bool) {
	lines := strings.Split(string(src), "\n")
	if line < 1 || line > len(lines) {
		return "", 0, false
	}
	defIdx := -1
	defIndent := 0
	for i := line - 1; i < len(lines) && i < line+15; i++ {
		trimmed := strings.TrimLeft(lines[i], " \t")
		if strings.HasPrefix(trimmed, "def ") || strings.HasPrefix(trimmed, "async def ") {
			defIdx = i
			defIndent = len(lines[i]) - len(trimmed)
			break
		}
	}
	if defIdx < 0 {
		return "", 0, false
	}
	end := defIdx + 1
	lastBodyIdx := defIdx
	for end < len(lines) {
		l := lines[end]
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			end++
			continue
		}
		indent := len(l) - len(strings.TrimLeft(l, " \t"))
		if indent <= defIndent {
			break
		}
		lastBodyIdx = end
		end++
	}
	return strings.Join(lines[defIdx:end], "\n"), lastBodyIdx + 1, true
}

func extractInlineGoFromLine(src []byte, line int) (string, int, bool) {
	start := lineStartOffset(src, line)
	if start < 0 {
		return "", 0, false
	}
	endLine := start
	for endLine < len(src) && src[endLine] != '\n' {
		endLine++
	}
	idx := strings.Index(string(src[start:endLine]), "func(")
	if idx < 0 {
		idx = strings.Index(string(src[start:endLine]), "func (")
	}
	if idx < 0 {
		return "", 0, false
	}
	return extractBalancedBlock(src, start+idx, start+idx)
}

func extractInlineJSFromLine(src []byte, line int) (string, int, bool) {
	start := lineStartOffset(src, line)
	if start < 0 {
		return "", 0, false
	}
	endLine := start
	for endLine < len(src) && src[endLine] != '\n' {
		endLine++
	}
	lineText := string(src[start:endLine])
	if !strings.Contains(lineText, "=>") && !strings.Contains(lineText, "function") {
		return "", 0, false
	}
	return extractBalancedBlock(src, start, start)
}

func extractNamedJSHandler(src []byte, handler string) (string, int, bool) {
	name := trailingIdentifier(handler)
	if name == "" {
		return "", 0, false
	}
	re := regexp.MustCompile(`(?m)(?:^|\s)(?:async\s+)?(?:function\s+` + regexp.QuoteMeta(name) + `\s*\(|(?:const|let|var)\s+` + regexp.QuoteMeta(name) + `\s*=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)`)
	loc := re.FindIndex(src)
	if loc == nil {
		return "", 0, false
	}
	body, _, ok := extractBalancedBlock(src, loc[0], loc[0])
	return body, 0, ok
}

func extractNamedGoHandler(absRoot, relFile string, src []byte, handler string) (string, int, bool) {
	name := trailingIdentifier(handler)
	if name == "" {
		return "", 0, false
	}
	re := regexp.MustCompile(`(?m)^func\s+(?:\([^)]*\)\s+)?` + regexp.QuoteMeta(name) + `\s*\(`)
	if loc := re.FindIndex(src); loc != nil {
		body, _, ok := extractBalancedBlock(src, loc[0], loc[0])
		return body, 0, ok
	}
	// Check sibling non-test .go files in the same package directory.
	pkgDir := filepath.Dir(filepath.FromSlash(relFile))
	absDir := filepath.Join(absRoot, pkgDir)
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return "", 0, false
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		siblingRel := filepath.ToSlash(filepath.Join(pkgDir, e.Name()))
		if siblingRel == relFile {
			continue
		}
		sibSrc, ok := readConfinedFile(absRoot, siblingRel)
		if !ok {
			continue
		}
		if loc := re.FindIndex(sibSrc); loc != nil {
			body, _, ok := extractBalancedBlock(sibSrc, loc[0], loc[0])
			return body, 0, ok
		}
	}
	return "", 0, false
}

func trailingIdentifier(handler string) string {
	h := strings.TrimSpace(handler)
	if h == "" || strings.ContainsAny(h, " \t\n(") {
		return ""
	}
	if dot := strings.LastIndexByte(h, '.'); dot >= 0 {
		h = h[dot+1:]
	}
	for i, r := range h {
		valid := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r == '$' || (i > 0 && r >= '0' && r <= '9')
		if !valid {
			return ""
		}
	}
	return h
}
