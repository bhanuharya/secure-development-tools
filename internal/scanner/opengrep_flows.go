package scanner

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bhanuharya/secure-development-tools/internal/finding"
)

// A taint rule reports every sink a tainted value reaches. One upload whose
// original file name is written to disk and then deleted in two cleanup
// branches gave three findings for one flaw; on one measured service 37
// findings of one rule came from a handful of uploads. The value's source
// identifies the flow, so the sinks of one source are reported once: at the
// first sink, with the other lines named in the message. The kept finding's
// fingerprint is the one it had before, so baselines and review decisions
// still match it.

// taintSourceAt reads where a dataflow trace's taint source starts. Opengrep
// writes ["CliLoc", [{"start": {...}, ...}, "<code>"]] for a source in the
// same function; a source reached through a call keeps every sink apart.
func taintSourceAt(raw json.RawMessage) (int, int, bool) {
	var source []json.RawMessage
	if json.Unmarshal(raw, &source) != nil || len(source) != 2 {
		return 0, 0, false
	}
	var kind string
	if json.Unmarshal(source[0], &kind) != nil || kind != "CliLoc" {
		return 0, 0, false
	}
	var loc []json.RawMessage
	if json.Unmarshal(source[1], &loc) != nil || len(loc) == 0 {
		return 0, 0, false
	}
	var at struct {
		Start struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		} `json:"start"`
	}
	if json.Unmarshal(loc[0], &at) != nil || at.Start.Line == 0 {
		return 0, 0, false
	}
	return at.Start.Line, at.Start.Col, true
}

// collapseTaintFlows keeps the first sink of each flow (by line) and names
// the other sinks' lines in its message. Findings without a source key are
// kept unchanged, in their order.
func collapseTaintFlows(findings []*finding.Finding, sources map[*finding.Finding]string) ([]*finding.Finding, int) {
	if len(sources) == 0 {
		return findings, 0
	}
	first := map[string]*finding.Finding{}
	more := map[*finding.Finding][]int{}
	for _, f := range findings {
		key, ok := sources[f]
		if !ok {
			continue
		}
		if kept, seen := first[key]; !seen || *f.Location.StartLine < *kept.Location.StartLine {
			if seen {
				more[f] = append(more[kept], *kept.Location.StartLine)
				delete(more, kept)
			}
			first[key] = f
		} else {
			more[kept] = append(more[kept], *f.Location.StartLine)
		}
	}
	out := make([]*finding.Finding, 0, len(first))
	for _, f := range findings {
		key, ok := sources[f]
		if ok && first[key] != f {
			continue
		}
		if lines := more[f]; len(lines) > 0 {
			sort.Ints(lines)
			f.Message = strings.TrimSpace(f.Message) + " " + sameFlowSentence(lines)
		}
		out = append(out, f)
	}
	return out, len(findings) - len(out)
}

func sameFlowSentence(lines []int) string {
	parts := make([]string, len(lines))
	for i, l := range lines {
		parts[i] = strconv.Itoa(l)
	}
	if len(parts) == 1 {
		return fmt.Sprintf("The same value also reaches line %s.", parts[0])
	}
	return fmt.Sprintf("The same value also reaches lines %s.", strings.Join(parts, ", "))
}
