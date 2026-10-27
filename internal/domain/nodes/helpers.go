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

// numClass is the exact mathematical classification of a JSON number.
type numClass int

const (
	numFractional numClass = iota // has a nonzero fractional part (e.g. 1.5, 1e-400)
	numIntegral                   // mathematically an integer within int64
	numOutOfRange                 // mathematically an integer but beyond int64
)

// validJSONNumberLexeme reports whether s is a syntactically valid JSON number
// lexeme (RFC 8259 §6): optional leading '-', an integer part that is either
// "0" or [1-9][0-9]* (no leading zeros, no bare '+'), an optional fraction that
// is '.' followed by at least one digit, and an optional exponent that is
// [eE][+-]? followed by at least one digit. No whitespace, no trailing
// material, no NaN/Inf/hex/underscore. It is a single bounded O(len) pass and
// allocates nothing. Malformed spellings (empty, "+", "-", ".", "+0", "-.",
// ".0", "0.", "00", "-00", "01", "1.", "+443", "0443", "0e", "1e+") are rejected
// here, BEFORE any mathematical or zero classification, so a malformed lexeme
// can never be mistaken for a valid zero or integer. Leading zeros are allowed
// in the EXPONENT digits ("0E+000" is valid); only the integer part restricts
// them.
func validJSONNumberLexeme(s string) bool {
	i := 0
	n := len(s)
	if i < n && s[i] == '-' {
		i++
	}
	// Integer part: "0" alone, or [1-9][0-9]*. No leading zeros.
	if i >= n || s[i] < '0' || s[i] > '9' {
		return false // missing integer part (covers "", "+", "-", ".", "+0", "-.")
	}
	if s[i] == '0' {
		i++
		if i < n && s[i] >= '0' && s[i] <= '9' {
			return false // leading zero: "00", "01", "0443", "-00"
		}
	} else {
		for i < n && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}
	// Optional fraction: '.' followed by >= 1 digit.
	if i < n && s[i] == '.' {
		i++
		if i >= n || s[i] < '0' || s[i] > '9' {
			return false // ".", "0.", "1.", "-."
		}
		for i < n && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}
	// Optional exponent: [eE][+-]? >= 1 digit.
	if i < n && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < n && (s[i] == '-' || s[i] == '+') {
			i++
		}
		if i >= n || s[i] < '0' || s[i] > '9' {
			return false // "0e", "0e+", "0e-", "1e+", "--1"
		}
		for i < n && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}
	return i == n // reject trailing whitespace/garbage (" 0", "0 ", "1_0", "0x1")
}

// classifyJSONNumber parses a json.Number with EXACT decimal semantics — no
// float64 conversion anywhere — and reports whether it is fractional, an
// in-int64 integer, or an out-of-int64 integer. It distinguishes equivalent
// integral spellings (443, 443.0, 443e0, 4.43e2, 4430e-1) from true fractions
// and from genuinely huge magnitudes, handles the exact int64 boundaries and
// the 2^53 neighbourhood without precision loss, and is resource-safe: it does
// a single bounded left-to-right pass over the digit text and never expands
// 10^exponent, allocates digits proportional to the input, or overflows an
// exponent counter. The DIRECT validation boundary accepts json.Number values
// that bypass the canonical scanner, so the strict JSON-number lexical grammar
// (validJSONNumberLexeme) is enforced FIRST: a malformed lexeme is rejected as
// fractional (typeMismatch) before any mathematical or zero classification.
func classifyJSONNumber(s string) (int64, numClass) {
	if !validJSONNumberLexeme(s) {
		return 0, numFractional // malformed JSON number lexeme: reject, never a valid zero/integer
	}
	i := 0
	neg := false
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		neg = s[i] == '-'
		i++
	}
	// Collect the mantissa digits (integer part + fraction concatenated). The
	// value is D * 10^(exp - fracDigits) where D is these digits as an integer.
	// Trailing zeros are stripped from D and folded into the exponent, so D
	// holds only significant digits and overflow is genuine (significant digits
	// alone exceed int64), which keeps every later path exact.
	var digits []byte
	fracDigits := 0
	readDigits := func() int {
		start := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			digits = append(digits, s[i])
			i++
		}
		return i - start
	}
	_ = readDigits() // integer part
	if i < len(s) && s[i] == '.' {
		i++
		fracDigits = readDigits() // fractional part
	}
	// Exponent (bounded; never expanded into digits).
	expNeg := false
	var exp uint64
	expOverflow := false
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '-' || s[i] == '+') {
			expNeg = s[i] == '-'
			i++
		}
		es := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			dig := uint64(s[i] - '0')
			if !expOverflow {
				if exp > (1e18-dig)/10 {
					expOverflow = true // clamp: any exponent this large dominates
				} else {
					exp = exp*10 + dig
				}
			}
			i++
		}
		if i == es {
			return 0, numFractional // "e" with no digits: malformed, reject
		}
	}
	if i != len(s) {
		return 0, numFractional // trailing garbage: malformed, reject
	}

	// Strip trailing zeros; fold them into the fractional-digit count (a trailing
	// zero in the mantissa divides the value by 10 exactly once, the same as one
	// fewer fractional digit). Leading zeros are harmless for the accumulator.
	trail := 0
	for len(digits) > 0 && digits[len(digits)-1] == '0' {
		digits = digits[:len(digits)-1]
		trail++
	}
	// Zero mantissa is integral zero regardless of exponent spelling (0, 0.0,
	// 0e5, 0e-999999, 0.000e999999 all equal zero and are in range).
	if len(digits) == 0 {
		return 0, numIntegral
	}

	if expOverflow {
		if expNeg {
			// Huge negative exponent: a nonzero value is a vanishingly small
			// fraction, never integral.
			return 0, numFractional
		}
		// Huge positive exponent: a nonzero value is far beyond int64.
		return 0, numOutOfRange
	}

	// Accumulate significant digits exactly, capping past int64 magnitude.
	const umax = uint64(1) << 63 // magnitude bound for int64 (|min| = 2^63)
	var d uint64
	overflow := false
	for _, c := range digits {
		dig := uint64(c - '0')
		if !overflow {
			if d > (umax-dig)/10 {
				overflow = true
			} else {
				d = d*10 + dig
			}
		}
	}

	// value = D * 10^scale with scale = ±exp - (fracDigits - trailingZeros).
	effFrac := int64(fracDigits) - int64(trail)
	var scale int64
	if expNeg {
		scale = -int64(exp) - effFrac
	} else {
		scale = int64(exp) - effFrac
	}
	return finishIntegral(d, neg, scale, overflow)
}

// finishIntegral converts an accumulated significant-digit mantissa D (possibly
// capped with overflow set) plus base-10 exponent scale into an int64 with
// exact classification. The mathematical value is D * 10^scale. overflow means
// the significant digits alone exceeded the int64 magnitude during
// accumulation. Trailing zeros were already folded into scale by the caller, so
// D has no trailing zeros: a negative scale can only be integral when scale
// cancels leading... it cannot — D has no trailing zeros, so D * 10^scale with
// scale < 0 is integral only if the division removes nothing, i.e. it is never
// integral for scale < 0 (D not divisible by 10). No float64 is used.
func finishIntegral(d uint64, neg bool, scale int64, overflow bool) (int64, numClass) {
	const umax = uint64(1) << 63
	if scale < 0 {
		// D has no trailing zeros (they were folded into scale), so D * 10^scale
		// has a nonzero fractional part whenever scale < 0 — unless D == 0, which
		// the caller already handled. A capped D is likewise nonzero.
		return 0, numFractional
	}
	// scale >= 0 now: value = D * 10^scale.
	if overflow {
		return 0, numOutOfRange
	}
	lim := umax - 1 // max int64 = 2^63 - 1
	if neg {
		lim = umax // |min int64| = 2^63
	}
	val := d
	for k := int64(0); k < scale; k++ {
		if val > lim/10 {
			return 0, numOutOfRange
		}
		val *= 10
	}
	if val > lim {
		return 0, numOutOfRange
	}
	if neg {
		return -int64(val), numIntegral // val <= 2^63, so -val >= min int64
	}
	return int64(val), numIntegral
}

// asInt accepts an integral JSON number (float64 from encoding/json, or
// json.Number/int64) and refuses non-integers. json.Number values are parsed
// with EXACT decimal semantics (classifyJSONNumber): equivalent integral
// spellings (443.0, 443e0, 4.43e2) are accepted and fractional spellings are
// refused, with no float64 fallback.
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
		i, cls := classifyJSONNumber(string(n))
		return i, cls == numIntegral
	}
	return 0, false
}

// numberOutOfRange reports whether v is a JSON number (json.Number) that is
// integral in form but exceeds the representable integer range. It lets the
// integer rule distinguish "not a number at all / fractional" (typeMismatch)
// from "a number too large to represent" (boundsViolation), so a syntactically
// valid huge value like 1E400 is honestly reported as out of range rather than
// as the wrong type. Only the boolean leaves; the value is never echoed.
func numberOutOfRange(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	_, cls := classifyJSONNumber(string(n))
	return cls == numOutOfRange
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
