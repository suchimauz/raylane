// Maintained behavior contract for V4-T011-INTEGRAL-NUMBER-LEXICAL-REJECTION
// (FR-009/D-012/D-015/D-016, FR-019 numerical metadata). It executes the REAL
// capability authority and the REAL nodes.Validate/ValidateDocument against the
// authored profile AND a synthetic wide-integer metadata variant — not fixture
// linting or AST inspection.
//
// One coherent outcome: integer scalar/array consumers accept supported
// integral spellings exactly (443, 443.0, 443e0, 4.43e2, 4430e-1, 4.4300e2 are
// all the same mathematical value) and distinguish fractional (1.5, 1e-400)
// and wrong-type from true out-of-range (1E400). No float64 conversion of
// json.Number decides integral value or bounds; no exponent-expansion DoS; no
// rounding/wrapping. Submitted bytes are never rewritten and never echo.

package contract_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// integralPortProfile returns a profile whose socks5 serverPort has a wide
// integer range so the exact int64 boundaries and the 2^53 neighbourhood can be
// exercised through REAL validation (not only the helper).
func integralPortProfile(t *testing.T) *capability.Profile {
	t.Helper()
	raw := []byte(`{"profileVersion":5,"protocols":{"socks5":{"fields":{"server":{"type":"string","classification":"known"},"serverPort":{"type":"integer","classification":"known","required":true,"minimum":-9223372036854775808,"maximum":9223372036854775807}}}}}`)
	p, err := capability.Parse(raw)
	if err != nil {
		t.Fatalf("integral port profile did not parse: %v\n%s", err, raw)
	}
	return p
}

// TestIntegralNumberEquivalentSpellings: equivalent in-range integral spellings
// are all Valid with no issue, and ValidateDocument preserves the exact raw
// bytes (spelling/whitespace/nested inactive) with no echo.
func TestIntegralNumberEquivalentSpellings(t *testing.T) {
	p := loadProfile(t)
	spellings := []string{"443", "443.0", "443e0", "4.43e2", "4430e-1", "4.4300e2", "443E0", "44300e-1"}
	for _, sp := range spellings {
		t.Run(sp, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(" {\n\"protocol\":\"socks5\",\"fields\":{\"active\":{\"server\":\"s.example\",\"serverPort\":%s},\"inactive\":{\"dnsServer\":\"%s\"},\"unknown\":{}}} ", sp, "CANARY-INACTIVE-NUMBER"))
			presence := map[string]bool{}
			a, err := nodes.ValidateDocument(p, raw, presence)
			if err != nil {
				t.Fatalf("canonical syntax-valid envelope refused: %v", err)
			}
			if a.Validation != domain.ValidationValid || a.Result.Status != nodes.Valid || !a.Result.Applicable || len(a.Result.Issues) != 0 {
				t.Fatalf("integral spelling %s must be Valid, got validation=%v status=%v applicable=%v issues=%+v",
					sp, a.Validation, a.Result.Status, a.Result.Applicable, a.Result.Issues)
			}
			if !bytes.Equal(a.Document.Raw, raw) {
				t.Fatalf("exact original raw (spelling/whitespace/inactive) must be preserved")
			}
			if len(presence) != 0 {
				t.Fatalf("presence must be unchanged: %+v", presence)
			}
			pub, _ := json.Marshal(a.Result)
			if bytes.Contains(pub, []byte("CANARY-INACTIVE-NUMBER")) || bytes.Contains(pub, []byte(sp)) {
				t.Fatalf("public result echoes submitted value or canary: %s", pub)
			}
			assertNoCanary(t, "integral-"+sp, a.Result)
		})
	}
}

// TestIntegralNumberFractionalAndOutOfRange: fractional decimals (1.5, 1e-400)
// are typeMismatch; a mathematically integral value beyond range (1E400) is
// boundsViolation. Each is exactly one value-free issue on the integer field.
func TestIntegralNumberFractionalAndOutOfRange(t *testing.T) {
	p := loadProfile(t)
	cases := []struct {
		name, num string
		code      nodes.IssueCode
	}{
		{"fractional-decimal", "1.5", nodes.IssueTypeMismatch},
		{"tiny-fractional", "1e-400", nodes.IssueTypeMismatch},
		{"fractional-near-int", "443.0000000000000001", nodes.IssueTypeMismatch},
		{"huge-integral", "1E400", nodes.IssueBoundsViolation},
		{"integral-decimal-beyond-range", "99999999999999999999.0", nodes.IssueBoundsViolation},
		{"integral-exponent-beyond-range", "443e30", nodes.IssueBoundsViolation},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"protocol":"socks5","fields":{"active":{"server":"s.example","serverPort":%s},"inactive":{},"unknown":{}}}`, c.num))
			a, err := nodes.ValidateDocument(p, raw, nil)
			if err != nil {
				t.Fatalf("canonical envelope refused: %v", err)
			}
			if a.Validation != domain.ValidationInvalid || a.Result.Applicable {
				t.Fatalf("%s: want Invalid+not-applicable, got validation=%v applicable=%v issues=%+v",
					c.num, a.Validation, a.Result.Applicable, a.Result.Issues)
			}
			if len(a.Result.Issues) != 1 || a.Result.Issues[0].Code != c.code || a.Result.Issues[0].Field != "serverPort" {
				t.Fatalf("%s: want exactly one %s@serverPort, got %+v", c.num, c.code, a.Result.Issues)
			}
			assertNoCanary(t, "num-"+c.name, a.Result)
		})
	}
}

// TestIntegralNumberExactInt64Boundaries: the exact int64 boundaries and the
// 2^53 neighbourhood are accepted/overflowed exactly through REAL validation
// against a wide-range synthetic metadata variant — no float64 precision loss,
// no wrap of out-of-range values to MinInt64.
func TestIntegralNumberExactInt64Boundaries(t *testing.T) {
	p := integralPortProfile(t)
	maxI := "9223372036854775807"   // 2^63 - 1
	minI := "-9223372036854775808"  // -2^63
	overP := "9223372036854775808"  // 2^63
	overN := "-9223372036854775809" // below -2^63
	two53 := "9007199254740993"     // 2^53 + 1 (classic float64 loss)

	valid := []struct {
		name, num string
		val       int64
	}{
		{"int64-max", maxI, 9223372036854775807},
		{"int64-max-decimal", "9223372036854775807.0", 9223372036854775807},
		{"int64-min", minI, -9223372036854775808},
		{"int64-min-decimal", "-9223372036854775808.0", -9223372036854775808},
		{"int64-max-exponent", "9.223372036854775807e18", 9223372036854775807},
		{"two53-plus-one", two53, 9007199254740993},
		{"two53-plus-one-decimal", "9007199254740993.000", 9007199254740993},
	}
	for _, c := range valid {
		t.Run(c.name, func(t *testing.T) {
			res := nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{
				"server": "s.example", "serverPort": json.Number(c.num),
			}})
			if res.Status != nodes.Valid || !res.Applicable || len(res.Issues) != 0 {
				t.Fatalf("%s: want Valid, got status=%v applicable=%v issues=%+v", c.num, res.Status, res.Applicable, res.Issues)
			}
		})
	}

	outOfRange := []struct{ name, num string }{
		{"int64-max-plus-one", overP},
		{"int64-max-plus-one-decimal", "9223372036854775808.0"},
		{"int64-min-minus-one", overN},
		{"int64-min-minus-one-decimal", "-9223372036854775809.0"},
		{"way-beyond", "99999999999999999999999999"},
	}
	for _, c := range outOfRange {
		t.Run(c.name, func(t *testing.T) {
			res := nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{
				"server": "s.example", "serverPort": json.Number(c.num),
			}})
			if res.Status != nodes.Invalid || res.Applicable {
				t.Fatalf("%s: want Invalid+not-applicable, got status=%v applicable=%v issues=%+v", c.num, res.Status, res.Applicable, res.Issues)
			}
			// Must be boundsViolation (not wrapped to MinInt64 and not typeMismatch).
			if !hasIssue(res, nodes.IssueBoundsViolation, "serverPort") {
				t.Fatalf("%s: want boundsViolation@serverPort (no wrap), got %+v", c.num, res.Issues)
			}
		})
	}
}

// TestIntegralNumberHugeExponentResourceSafe: attacker-controlled huge positive
// and negative exponents and long coefficients terminate with bounded work —
// never expanding 10^exponent or allocating proportional to the exponent. Zero
// stays zero; a tiny nonzero negative-exponent value stays fractional.
func TestIntegralNumberHugeExponentResourceSafe(t *testing.T) {
	p := integralPortProfile(t)          // wide int64 range so zero is in range
	hugePos := "1e999999999999999999999" // exponent far beyond uint64
	hugeNeg := "1e-999999999999999999999"
	longCoef := strings.Repeat("9", 5000) + "e-4000"        // (10^5000-1)*10^-4000 = 10^1000 - tiny: FRACTIONAL
	integralHuge := "1" + strings.Repeat("0", 4000) + "e-3" // 10^4000 / 1000 = 10^3997: integral, out of range
	zeroHugePos := "0e999999999999999999999"
	zeroHugeNeg := "0e-999999999999999999999"

	// These must terminate quickly (bounded) and classify honestly.
	res := nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{
		"server": "s.example", "serverPort": json.Number(hugePos),
	}})
	if !hasIssue(res, nodes.IssueBoundsViolation, "serverPort") {
		t.Fatalf("huge positive exponent must be boundsViolation, got %+v", res.Issues)
	}
	res = nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{
		"server": "s.example", "serverPort": json.Number(hugeNeg),
	}})
	if !hasIssue(res, nodes.IssueTypeMismatch, "serverPort") {
		t.Fatalf("huge negative exponent nonzero value must be typeMismatch (fractional), got %+v", res.Issues)
	}
	res = nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{
		"server": "s.example", "serverPort": json.Number(longCoef),
	}})
	// (10^5000-1)*10^-4000 is not an integer -> fractional -> typeMismatch.
	if !hasIssue(res, nodes.IssueTypeMismatch, "serverPort") {
		t.Fatalf("long non-integral coefficient must be typeMismatch, got %+v", res.Issues)
	}
	res = nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{
		"server": "s.example", "serverPort": json.Number(integralHuge),
	}})
	// 10^3997 is integral but far beyond int64 -> boundsViolation (no expansion).
	if !hasIssue(res, nodes.IssueBoundsViolation, "serverPort") {
		t.Fatalf("integral huge value must be boundsViolation, got %+v", res.Issues)
	}
	for _, z := range []string{zeroHugePos, zeroHugeNeg} {
		res = nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{
			"server": "s.example", "serverPort": json.Number(z),
		}})
		if res.Status != nodes.Valid || !res.Applicable {
			t.Fatalf("zero with huge exponent %s must be Valid zero, got %+v", z, res.Issues)
		}
	}
}

// TestIntegralNumberWireGuardPorts: equivalent integral spellings on WireGuard
// endpointPort/mtu/keepAlive validate identically to their plain form; the
// reserved array accepts integral alternate spellings within 0..255.
func TestIntegralNumberWireGuardPorts(t *testing.T) {
	p := loadProfile(t)
	base := map[string]any{
		"endpoint": "w.example", "endpointPort": json.Number("51820"),
		"publicKey": "pub", "localAddresses": []any{"10.0.0.2/32"},
	}
	// Equivalent spellings for endpointPort are all valid.
	for _, sp := range []string{"51820", "51820.0", "5182e1", "518200e-1", "51820.00"} {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		m["endpointPort"] = json.Number(sp)
		res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: m, SecretPresence: map[string]bool{"privateKey": true}})
		if res.Status != nodes.Valid || !res.Applicable {
			t.Fatalf("endpointPort %s: want Valid, got %+v", sp, res.Issues)
		}
	}
	// mtu and keepAlive equivalent spellings.
	for field, sp := range map[string]string{"mtu": "1420.0", "keepAlive": "25e0"} {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		m[field] = json.Number(sp)
		res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: m, SecretPresence: map[string]bool{"privateKey": true}})
		if res.Status != nodes.Valid || !res.Applicable {
			t.Fatalf("%s %s: want Valid, got %+v", field, sp, res.Issues)
		}
	}
	// reserved array with integral alternate spellings within 0..255.
	m := map[string]any{}
	for k, v := range base {
		m[k] = v
	}
	m["reserved"] = []any{json.Number("0.0"), json.Number("2.55e2"), json.Number("0e999999")}
	res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: m, SecretPresence: map[string]bool{"privateKey": true}})
	if res.Status != nodes.Valid || !res.Applicable {
		t.Fatalf("reserved integral spellings [0.0,2.55e2,0e999999]: want Valid, got %+v", res.Issues)
	}
}

// TestIntegralNumberArrayIssueVocabulary: wrong item shape / fraction / overflow
// keeps arrayItemViolation, and a valid integer outside the byte range keeps
// reservedByteRange — no duplicate issues, existing vocabulary retained.
func TestIntegralNumberArrayIssueVocabulary(t *testing.T) {
	p := loadProfile(t)
	base := map[string]any{
		"endpoint": "w.example", "endpointPort": json.Number("51820"),
		"publicKey": "pub", "localAddresses": []any{"10.0.0.2/32"},
	}
	pres := map[string]bool{"privateKey": true}

	// Fractional element -> arrayItemViolation (3-element array passes the 0-or-3
	// cardinality rule so the item-shape finding is isolated).
	m := cloneMap(base)
	m["reserved"] = []any{json.Number("1.5"), json.Number("1"), json.Number("2")}
	res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: m, SecretPresence: pres})
	if !hasIssue(res, nodes.IssueArrayItemViolation, "reserved") {
		t.Fatalf("fractional reserved element: want arrayItemViolation, got %+v", res.Issues)
	}
	// Non-integral tiny element -> arrayItemViolation (item shape), not bounds.
	m = cloneMap(base)
	m["reserved"] = []any{json.Number("1e-400"), json.Number("1"), json.Number("2")}
	res = nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: m, SecretPresence: pres})
	if !hasIssue(res, nodes.IssueArrayItemViolation, "reserved") {
		t.Fatalf("tiny fractional reserved element: want arrayItemViolation, got %+v", res.Issues)
	}
	// Wrong shape element (object) -> arrayItemViolation.
	m = cloneMap(base)
	m["reserved"] = []any{map[string]any{"a": 1}, json.Number("1"), json.Number("2")}
	res = nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: m, SecretPresence: pres})
	if !hasIssue(res, nodes.IssueArrayItemViolation, "reserved") {
		t.Fatalf("object reserved element: want arrayItemViolation, got %+v", res.Issues)
	}
	// Integral element out of byte range (0..255) -> reservedByteRange.
	m = cloneMap(base)
	m["reserved"] = []any{json.Number("256"), json.Number("1"), json.Number("2")}
	res = nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: m, SecretPresence: pres})
	if !hasIssue(res, nodes.IssueReservedByteRange, "reserved") {
		t.Fatalf("reserved element 256: want reservedByteRange, got %+v", res.Issues)
	}
	// Overflow integral element -> arrayItemViolation (item cannot be represented).
	m = cloneMap(base)
	m["reserved"] = []any{json.Number("1E400"), json.Number("1"), json.Number("2")}
	res = nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: m, SecretPresence: pres})
	if !hasIssue(res, nodes.IssueArrayItemViolation, "reserved") {
		t.Fatalf("overflow reserved element: want arrayItemViolation, got %+v", res.Issues)
	}
}

// cloneMap copies a string-keyed any map.
func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
