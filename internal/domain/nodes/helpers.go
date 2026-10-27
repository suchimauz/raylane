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

// addIssue appends one deterministic, value-free issue. The shown path comes
// from bucketIssueField, which forces a fixed generic path for structural
// bucket issues and passes through declared names for name-scoped codes only.
func addIssue(res *Result, code IssueCode, field string) {
	if !code.valid() {
		return
	}
	res.Issues = append(res.Issues, Issue{Code: code, Field: bucketIssueField(code, field), Reason: issueReason[code]})
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

// numberOutOfRange reports whether v is a JSON number (json.Number) that is
// integral in form but exceeds the representable integer range. It lets the
// integer rule distinguish "not a number at all" (typeMismatch) from "a
// number too large to represent" (boundsViolation), so a syntactically valid
// huge value like 1E400 is honestly reported as out of range rather than as
// the wrong type. Only the boolean leaves; the value is never echoed.
func numberOutOfRange(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	if _, err := n.Int64(); err == nil {
		return false // fits: not out of range
	}
	// It is a number but Int64 failed: either non-integral or out of range.
	// A non-integral number (e.g. 1.5) is a type problem for an integer field,
	// not a range problem; detect that via the float form.
	if f, err := n.Float64(); err == nil {
		// Non-integral (has a fractional part within range) → type, not range.
		return f == float64(int64(f)) // integral but overflowed → out of range
	}
	// Float64 also failed → magnitude beyond float64: definitively out of range.
	return true
}

// matchFieldPattern delegates pattern matching to the profile. The capability
// package owns the compiled regexp; nodes asks it to evaluate one string.
func matchFieldPattern(f capability.Field, s string) bool {
	return capability.MatchPattern(f, s)
}

// envelopeBucketsOverlap reports whether any name appears in more than one of
// the three submitted buckets. Only the boolean verdict leaves this function —
// the colliding names are attacker-controlled and never returned.
func envelopeBucketsOverlap(active, inactive, unknown map[string]any) bool {
	count := func(m map[string]any) int {
		hits := 0
		for n := range m {
			seen := 0
			if _, ok := active[n]; ok {
				seen++
			}
			if _, ok := inactive[n]; ok {
				seen++
			}
			if _, ok := unknown[n]; ok {
				seen++
			}
			if seen > 1 {
				hits++
			}
		}
		return hits
	}
	return count(active)+count(inactive)+count(unknown) > 0
}
