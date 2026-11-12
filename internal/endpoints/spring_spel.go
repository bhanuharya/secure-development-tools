package endpoints

import "strings"

// Spring SpEL expressions are boolean formulas. Reading only the first role
// call overstates protection when an `or` alternative admits anonymous
// requests, so evaluate the composition over the terms we can read and mark
// everything else undecidable.

type spelKind int

const (
	spelTrue          spelKind = iota // permitAll(), true: everyone
	spelFalse                         // denyAll(), false: nobody
	spelAnonymous                     // isAnonymous(): anonymous requests allowed
	spelAuthenticated                 // isAuthenticated(): a principal is required
	spelRole                          // hasRole/hasAuthority: a role is required
	spelUnknown                       // a term we cannot read
)

type spelResult struct {
	kind     spelKind
	roles    []string
	compound bool // a boolean operator or grouping was applied
}

// evalSpel parses a @PreAuthorize/access() expression. A parse failure is an
// unreadable expression, never a permit.
func evalSpel(expr string) spelResult {
	expr = unquoteSpel(expr)
	p := spelParser{src: expr}
	res, ok := p.parseOr()
	p.skipSpace()
	if !ok || p.pos != len(p.src) {
		return spelResult{kind: spelUnknown, compound: containsSpelOperator(expr)}
	}
	return res
}

// springSpelDecision maps a formula to protection. A lone unreadable term
// keeps the historical "authenticated, medium" answer; an unreadable term
// inside a compound formula is unknown, because it may admit anonymous users.
func springSpelDecision(res spelResult) (Protection, []string, bool) {
	switch res.kind {
	case spelTrue, spelAnonymous:
		return ProtPublic, nil, true
	case spelFalse:
		return ProtDenied, nil, true
	case spelAuthenticated:
		return ProtAuthenticated, nil, true
	case spelRole:
		return ProtRole, res.roles, true
	}
	if res.compound {
		return ProtUnknown, nil, false
	}
	return ProtAuthenticated, nil, false
}

func unquoteSpel(expr string) string {
	expr = strings.TrimSpace(expr)
	if len(expr) >= 2 && (expr[0] == '"' || expr[0] == '\'') && expr[len(expr)-1] == expr[0] {
		return expr[1 : len(expr)-1]
	}
	return expr
}

func containsSpelOperator(expr string) bool {
	lower := strings.ToLower(expr)
	return strings.Contains(lower, " or ") || strings.Contains(lower, " and ") ||
		strings.Contains(lower, "||") || strings.Contains(lower, "&&") ||
		strings.Contains(expr, "!")
}

type spelParser struct {
	src string
	pos int
}

func (p *spelParser) parseOr() (spelResult, bool) {
	left, ok := p.parseAnd()
	if !ok {
		return spelResult{}, false
	}
	for {
		if !p.consumeWord("or") && !p.consume("||") {
			return left, true
		}
		right, ok := p.parseAnd()
		if !ok {
			return spelResult{}, false
		}
		left = spelOr(left, right)
	}
}

func (p *spelParser) parseAnd() (spelResult, bool) {
	left, ok := p.parseUnary()
	if !ok {
		return spelResult{}, false
	}
	for {
		if !p.consumeWord("and") && !p.consume("&&") {
			return left, true
		}
		right, ok := p.parseUnary()
		if !ok {
			return spelResult{}, false
		}
		left = spelAnd(left, right)
	}
}

func (p *spelParser) parseUnary() (spelResult, bool) {
	p.skipSpace()
	if p.consume("!") {
		res, ok := p.parseUnary()
		return spelNot(res), ok
	}
	if p.consume("(") {
		res, ok := p.parseOr()
		if !ok || !p.consume(")") {
			return spelResult{}, false
		}
		return res, true
	}
	return p.parseTerm()
}

func (p *spelParser) parseTerm() (spelResult, bool) {
	p.skipSpace()
	if p.pos >= len(p.src) {
		return spelResult{}, false
	}
	name := p.readName()
	if name == "" {
		p.pos++ // an operator or punctuation we do not understand
		return spelResult{kind: spelUnknown}, true
	}
	p.skipSpace()
	args := ""
	if p.consume("(") {
		var ok bool
		args, ok = p.readArgs()
		if !ok {
			return spelResult{}, false
		}
	}
	return spelTerm(strings.ToLower(name), args), true
}

func (p *spelParser) readName() string {
	start := p.pos
	for p.pos < len(p.src) && isSpelNameByte(p.src[p.pos]) {
		p.pos++
	}
	return p.src[start:p.pos]
}

// readArgs returns everything inside the already-consumed opening paren.
func (p *spelParser) readArgs() (string, bool) {
	start := p.pos
	depth := 1
	var quote byte
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if quote != 0 {
			if c == '\\' {
				p.pos += 2
				continue
			}
			if c == quote {
				quote = 0
			}
			p.pos++
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				args := p.src[start:p.pos]
				p.pos++
				return args, true
			}
		}
		p.pos++
	}
	return "", false
}

func (p *spelParser) skipSpace() {
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t' || p.src[p.pos] == '\n' || p.src[p.pos] == '\r') {
		p.pos++
	}
}

func (p *spelParser) consume(token string) bool {
	p.skipSpace()
	if !strings.HasPrefix(p.src[p.pos:], token) {
		return false
	}
	p.pos += len(token)
	return true
}

func (p *spelParser) consumeWord(word string) bool {
	p.skipSpace()
	rest := p.src[p.pos:]
	if len(rest) < len(word) || !strings.EqualFold(rest[:len(word)], word) {
		return false
	}
	end := len(word)
	if end < len(rest) && isSpelNameByte(rest[end]) {
		return false
	}
	p.pos += end
	return true
}

func isSpelNameByte(c byte) bool {
	return c == '_' || c == '$' || c == '#' || c == '.' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func spelTerm(name, args string) spelResult {
	switch name {
	case "permitall", "true":
		return spelResult{kind: spelTrue}
	case "denyall", "false":
		return spelResult{kind: spelFalse}
	case "isanonymous":
		return spelResult{kind: spelAnonymous}
	case "isauthenticated", "isfullyauthenticated", "isrememberme":
		return spelResult{kind: spelAuthenticated}
	case "hasrole", "hasanyrole", "hasauthority", "hasanyauthority":
		roles := springRoles(args)
		if len(roles) == 0 {
			return spelResult{kind: spelUnknown}
		}
		return spelResult{kind: spelRole, roles: roles}
	}
	return spelResult{kind: spelUnknown}
}

func spelOr(a, b spelResult) spelResult {
	res := spelResult{compound: true}
	switch {
	case a.kind == spelTrue || b.kind == spelTrue:
		res.kind = spelTrue
	case a.kind == spelFalse:
		res.kind, res.roles = b.kind, b.roles
	case b.kind == spelFalse:
		res.kind, res.roles = a.kind, a.roles
	case a.kind == spelAnonymous || b.kind == spelAnonymous:
		res.kind = spelAnonymous
	case a.kind == spelUnknown || b.kind == spelUnknown:
		res.kind = spelUnknown
	case a.kind == spelAuthenticated || b.kind == spelAuthenticated:
		res.kind = spelAuthenticated
	default:
		res.kind = spelRole
		res.roles = dedupe(append(append([]string{}, a.roles...), b.roles...))
	}
	return res
}

func spelAnd(a, b spelResult) spelResult {
	res := spelResult{compound: true}
	switch {
	case a.kind == spelFalse || b.kind == spelFalse:
		res.kind = spelFalse
	case a.kind == spelTrue:
		res.kind, res.roles = b.kind, b.roles
	case b.kind == spelTrue:
		res.kind, res.roles = a.kind, a.roles
	case a.kind == spelUnknown || b.kind == spelUnknown:
		res.kind = spelUnknown
	case a.kind == spelAnonymous && b.kind == spelAnonymous:
		res.kind = spelAnonymous
	case a.kind == spelAnonymous || b.kind == spelAnonymous:
		res.kind = spelFalse
	case a.kind == spelRole || b.kind == spelRole:
		res.kind = spelRole
		res.roles = dedupe(append(append([]string{}, a.roles...), b.roles...))
	default:
		res.kind = spelAuthenticated
	}
	return res
}

func spelNot(a spelResult) spelResult {
	res := spelResult{compound: true}
	switch a.kind {
	case spelTrue:
		res.kind = spelFalse
	case spelFalse:
		res.kind = spelTrue
	case spelAnonymous:
		res.kind = spelAuthenticated
	case spelAuthenticated, spelRole:
		res.kind = spelAnonymous // a non-principal falls here too
	default:
		res.kind = spelUnknown
	}
	return res
}
