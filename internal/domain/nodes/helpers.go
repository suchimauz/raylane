package nodes

import (
	"encoding/json"
	"sort"

	"github.com/suchimauz/raylane/internal/capability"
)

// sortedKeys returns the keys of a string-keyed map in sorted order, for
// deterministic issue emission regardless of Go map iteration order.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedKeysOf returns the keys of a declared-field map in sorted order.
func sortedKeysOf(m map[string]capability.Field) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedKeysBool returns the keys of a bool map (trusted secret presence) in
// sorted order, for deterministic dependency resolution.
func sortedKeysBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// addIssue appends one deterministic, value-free issue.
func addIssue(res *Result, code IssueCode, field string) {
	if !code.valid() {
		return
	}
	res.Issues = append(res.Issues, Issue{Code: code, Field: field, Reason: issueReason[code]})
}

// sortIssues orders issues by field then code so results are byte-stable.
func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Field != issues[j].Field {
			return issues[i].Field < issues[j].Field
		}
		return issues[i].Code < issues[j].Code
	})
}

// asInt accepts an integral JSON number (float64 from encoding/json, or
// json.Number/int64) and refuses non-integers.
func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		if n != float64(int64(n)) {
			return 0, false
		}
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

// matchFieldPattern delegates pattern matching to the profile. The capability
// package owns the compiled regexp; nodes asks it to evaluate one string.
func matchFieldPattern(f capability.Field, s string) bool {
	return capability.MatchPattern(f, s)
}
