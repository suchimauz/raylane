// Maintained DIRECT-grammar behavior contract for V4-T011-INTEGRAL-NUMBER-
// LEXICAL-REJECTION. It exercises the DIRECT nodes.Validate(Input{...json.Number})
// boundary — which bypasses the canonical scanner — so malformed JSON-number
// lexemes are rejected by the validation layer itself, not by the parser.
//
// One coherent outcome: a json.Number that is not a syntactically valid JSON
// number (RFC 8259 §6) is refused as a wrong type (scalar typeMismatch /
// integer-array arrayItemViolation) with a value-free reason, BEFORE any
// mathematical or zero classification; valid spellings — including every zero
// and signed-exponent form — are still accepted/classified exactly. This
// complements the canonical ValidateDocument path (where the scanner already
// rejects malformed lexemes) and the exact-arithmetic tests in
// integral_number_test.go.

package contract_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// grammarProfile returns a synthetic full-range integer profile so that the
// value 0 and the full int64 span are in range and a grammar rejection cannot
// be confounded with a bounds rejection (the authored socks5 serverPort has
// minimum 1, which would reject valid zero on bounds).
func grammarProfile(t *testing.T) *capability.Profile {
	t.Helper()
	return integralPortProfile(t)
}

// TestDirectNumberMalformedLexemeRejected: malformed JSON-number lexemes fed
// DIRECTLY as json.Number are refused as typeMismatch (exactly one issue) — never
// accepted as a valid zero or integer.
func TestDirectNumberMalformedLexemeRejected(t *testing.T) {
	p := grammarProfile(t)
	bad := []string{
		// empty / sign-only / dot-only
		"", "+", "-", ".", "+0", "-.", ".0", "0.",
		// leading zeros
		"00", "-00", "01", "0443", "-01",
		// leading '+'
		"+443",
		// missing fraction / exponent digits
		"1.", "0e", "0e+", "0e-", "1e+", "1e-", "443e", "443E+",
		// double sign / internal garbage / whitespace
		"--1", "+-1", "1_0", "0x1", " 0", "0 ", "1\n", "NaN", "Inf", "-Inf",
		".5", "-.5", "+.5",
	}
	for _, s := range bad {
		t.Run("mal/"+s, func(t *testing.T) {
			res := nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{
				"server": "s.example", "serverPort": json.Number(s),
			}})
			if res.Status != nodes.Invalid || res.Applicable {
				t.Fatalf("malformed %q: want Invalid+not-applicable, got status=%v applicable=%v issues=%+v",
					s, res.Status, res.Applicable, res.Issues)
			}
			if len(res.Issues) != 1 || res.Issues[0].Code != nodes.IssueTypeMismatch || res.Issues[0].Field != "serverPort" {
				t.Fatalf("malformed %q: want exactly one typeMismatch@serverPort, got %+v", s, res.Issues)
			}
			assertNoCanary(t, "gram-"+s, res)
		})
	}
}

// TestDirectNumberValidLexemeAccepted: valid JSON-number spellings — including
// every zero and signed/leading-zero-exponent form — classify exactly at the
// DIRECT boundary.
func TestDirectNumberValidLexemeAccepted(t *testing.T) {
	p := grammarProfile(t)
	valid := []struct{ name, num string }{
		{"zero", "0"}, {"neg-zero", "-0"}, {"zero-dec", "0.0"}, {"neg-zero-dec", "-0.00"},
		{"zero-exp", "0e0"}, {"zero-exp-pos", "0E+000"}, {"zero-exp-neg", "0e-999999999999999999999999"},
		{"zero-frac-exp", "0.000e123456"},
		{"int", "443"}, {"int-dec", "443.0"}, {"int-exp", "443e0"}, {"int-Exp", "443E0"},
		{"frac-exp", "4.43e2"}, {"neg-int", "-443"}, {"int-max", "9223372036854775807"},
		{"int-min", "-9223372036854775808"},
		{"exp-leading-zero-digits", "443e007"}, {"neg-exp", "443e-0"}, {"plus-exp", "443e+2"},
	}
	for _, c := range valid {
		t.Run(c.name, func(t *testing.T) {
			res := nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{
				"server": "s.example", "serverPort": json.Number(c.num),
			}})
			if res.Status != nodes.Valid || !res.Applicable || len(res.Issues) != 0 {
				t.Fatalf("valid %q: want Valid, got status=%v applicable=%v issues=%+v",
					c.num, res.Status, res.Applicable, res.Issues)
			}
		})
	}
}

// TestDirectNumberIntegerArrayMalformedItem: a malformed lexeme inside an
// integer array is refused as arrayItemViolation (item shape), preserving the
// existing array vocabulary; valid alternate spellings are accepted.
func TestDirectNumberIntegerArrayMalformedItem(t *testing.T) {
	p := loadProfile(t)
	base := map[string]any{
		"endpoint": "w.example", "endpointPort": json.Number("51820"),
		"publicKey": "pub", "localAddresses": []any{"10.0.0.2/32"},
	}
	pres := map[string]bool{"privateKey": true}

	// Malformed lexeme in position 0 -> arrayItemViolation.
	for _, s := range []string{"+1", "01", "1.", "00"} {
		m := cloneMap(base)
		m["reserved"] = []any{json.Number(s), json.Number("1"), json.Number("2")}
		res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: m, SecretPresence: pres})
		if !hasIssue(res, nodes.IssueArrayItemViolation, "reserved") {
			t.Fatalf("malformed reserved element %q: want arrayItemViolation, got %+v", s, res.Issues)
		}
	}
	// Valid integral alternate spellings accepted.
	m := cloneMap(base)
	m["reserved"] = []any{json.Number("0.0"), json.Number("2.55e2"), json.Number("0e999999")}
	res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: m, SecretPresence: pres})
	if res.Status != nodes.Valid || !res.Applicable {
		t.Fatalf("valid reserved spellings: want Valid, got %+v", res.Issues)
	}
}

// TestDirectNumberGrammarResourceSafe: malformed and huge-lexeme inputs terminate
// with bounded work at the DIRECT boundary (no exponent expansion, no pathological
// allocation); a valid huge-exponent zero stays a valid zero.
func TestDirectNumberGrammarResourceSafe(t *testing.T) {
	p := grammarProfile(t)
	// Long malformed string (many digits then garbage) and huge valid exponent.
	longGarbage := strings.Repeat("9", 5000) + "x"
	hugeZero := "0e" + strings.Repeat("9", 4000)
	hugeIntegral := "1" + strings.Repeat("0", 4000) + "e-3" // 10^3997 integral, out of range

	res := nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{
		"server": "s.example", "serverPort": json.Number(longGarbage),
	}})
	if !hasIssue(res, nodes.IssueTypeMismatch, "serverPort") {
		t.Fatalf("long malformed lexeme: want typeMismatch, got %+v", res.Issues)
	}
	res = nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{
		"server": "s.example", "serverPort": json.Number(hugeZero),
	}})
	if res.Status != nodes.Valid || !res.Applicable {
		t.Fatalf("huge-exponent zero: want Valid zero, got %+v", res.Issues)
	}
	res = nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{
		"server": "s.example", "serverPort": json.Number(hugeIntegral),
	}})
	if !hasIssue(res, nodes.IssueBoundsViolation, "serverPort") {
		t.Fatalf("integral huge value: want boundsViolation, got %+v", res.Issues)
	}
}
