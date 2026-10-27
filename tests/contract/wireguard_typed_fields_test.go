// Maintained behavior contract for FR008 typed public WireGuard fields
// (T010/T011 FR008/D049, FR009/019). It executes the REAL nodes.Validate and
// nodes.ValidateDocument against the authored profile plus synthetic declaration
// variants, classifying malformed ACTIVE public WireGuard key/address values as
// semantic Invalid/not-applicable using the EXISTING static diagnostics
// (patternViolation@publicKey, arrayItemViolation@localAddresses) while
// preserving the exact submitted bytes (no rewrite/trim/mask/canonicalize).
//
// Scope: wireguard ONLY. vless.publicKey is the REALITY key and is untouched.
// Two independently-eligible declared known/non-secret/supported fields are
// checked: publicKey (string) and localAddresses (array of string). Each field
// is independent — an ineligible/invalid publicKey must NOT suppress
// localAddresses checking and vice versa. The typed check runs AFTER the same
// field's generic shape/bounds/pattern/array checks pass, so no duplicate
// ordinary issue is produced. No metadata/profile/pin/API/IssueCode change;
// stdlib only (encoding/hex, encoding/base64, net/netip). Pure validation: no
// secret bytes read, no engine/handshake/curve claim.

package contract_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// validWireGuardKey returns a 32-byte WireGuard public key in the named encoding
// for positive fixtures: "hex" (64 hex), "std-pad", "std-raw", "url-pad",
// "url-raw", "raw-plus-eq".
func validWireGuardKey(t *testing.T, encoding string) string {
	t.Helper()
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	switch encoding {
	case "hex":
		return hex.EncodeToString(b)
	case "std-pad":
		return base64.StdEncoding.EncodeToString(b)
	case "std-raw":
		return base64.RawStdEncoding.EncodeToString(b)
	case "url-pad":
		return base64.URLEncoding.EncodeToString(b)
	case "url-raw":
		return base64.RawURLEncoding.EncodeToString(b)
	case "raw-plus-eq":
		return base64.RawStdEncoding.EncodeToString(b) + "="
	}
	t.Fatalf("unknown key encoding %q", encoding)
	return ""
}

// wgActive builds a minimal wireguard active map with the given overrides.
func wgActive(t *testing.T, overrides map[string]any) map[string]any {
	m := map[string]any{
		"endpoint":       "w.example",
		"endpointPort":   json.Number("51820"),
		"publicKey":      validWireGuardKey(t, "url-raw"),
		"localAddresses": []any{"10.0.0.2/32"},
	}
	for k, v := range overrides {
		m[k] = v
	}
	return m
}

// TestWireGuardPublicKeyFormats: the pinned accepted key shapes are Valid; the
// rejected shapes produce exactly one value-free patternViolation@publicKey.
func TestWireGuardPublicKeyFormats(t *testing.T) {
	p := loadProfile(t)
	pres := map[string]bool{"privateKey": true}

	// Positive controls: accepted encodings (hex case-insensitive; std/url; padded/raw; raw+one '=').
	for _, enc := range []string{"hex", "std-pad", "std-raw", "url-pad", "url-raw", "raw-plus-eq"} {
		t.Run("valid/"+enc, func(t *testing.T) {
			key := validWireGuardKey(t, enc)
			// uppercase hex is also accepted
			if enc == "hex" {
				key = strings.ToUpper(key)
			}
			res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"publicKey": key}), SecretPresence: pres})
			if res.Status != nodes.Valid || !res.Applicable || len(res.Issues) != 0 {
				t.Fatalf("key %s: want Valid, got %+v", enc, res.Issues)
			}
			assertNoCanary(t, "key-"+enc, res)
		})
	}

	// Negative controls: rejected shapes -> exactly one patternViolation@publicKey.
	bad := []struct{ name, key string }{
		{"placeholder-pub", "pub"},
		{"63-hex", validWireGuardKey(t, "hex")[:63]},
		{"16-byte-hex-32char", hex.EncodeToString(make([]byte, 16))},
		{"31-byte-hex", hex.EncodeToString(make([]byte, 31))},
		{"zzz", "zzz"},
		{"leading-space", " " + validWireGuardKey(t, "hex")},
		{"31-byte-b64", base64.RawURLEncoding.EncodeToString(make([]byte, 31))},
		{"33-byte-b64", base64.RawURLEncoding.EncodeToString(make([]byte, 33))},
		{"128-char-in-bounds", strings.Repeat("a", 128)},
	}
	for _, c := range bad {
		t.Run("bad/"+c.name, func(t *testing.T) {
			res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"publicKey": c.key}), SecretPresence: pres})
			if res.Status != nodes.Invalid || res.Applicable {
				t.Fatalf("key %s: want Invalid+not-applicable, got status=%v applicable=%v issues=%+v", c.name, res.Status, res.Applicable, res.Issues)
			}
			if len(res.Issues) != 1 || res.Issues[0].Code != nodes.IssuePatternViolation || res.Issues[0].Field != "publicKey" {
				t.Fatalf("key %s: want exactly one patternViolation@publicKey, got %+v", c.name, res.Issues)
			}
			assertNoCanary(t, "key-"+c.name, res)
		})
	}
}

// TestWireGuardLocalAddresses: netip.ParseAddr-or-ParsePrefix accepted forms are
// Valid; malformed items produce exactly one arrayItemViolation@localAddresses.
func TestWireGuardLocalAddresses(t *testing.T) {
	p := loadProfile(t)
	pres := map[string]bool{"privateKey": true}

	valid := []struct {
		name  string
		addrs []any
	}{
		{"cidr-v4", []any{"10.0.0.2/32"}},
		{"bare-v4", []any{"10.0.0.2"}},
		{"cidr-v6", []any{"fd59:7153:2388:b5fd::1/128"}},
		{"bare-v6", []any{"fd59:7153:2388:b5fd::1"}},
		{"host-bits-set", []any{"10.0.0.2/24"}},
		{"zone", []any{"fe80::1%eth0"}},
		{"v4-mapped", []any{"::ffff:10.0.0.2"}},
		{"mixed-valid", []any{"10.0.0.2/32", "fd59:7153:2388:b5fd::1", "10.0.0.0/24"}},
	}
	for _, c := range valid {
		t.Run("valid/"+c.name, func(t *testing.T) {
			res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"localAddresses": c.addrs}), SecretPresence: pres})
			if res.Status != nodes.Valid || !res.Applicable || len(res.Issues) != 0 {
				t.Fatalf("addrs %s: want Valid, got %+v", c.name, res.Issues)
			}
		})
	}

	bad := []struct {
		name  string
		addrs []any
	}{
		{"not-an-ip", []any{"not-an-ip"}},
		{"hostname", []any{"example.com"}},
		{"bad-prefix-len", []any{"10.0.0.2/33"}},
		{"bad-octet", []any{"10.0.0.256"}},
		{"trailing-space", []any{"10.0.0.2/32 "}},
		{"empty-item", []any{""}},
		{"mixed-valid-bad", []any{"10.0.0.2/32", "bogus"}},
		{"whitespace-item", []any{" 10.0.0.2"}},
	}
	for _, c := range bad {
		t.Run("bad/"+c.name, func(t *testing.T) {
			res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"localAddresses": c.addrs}), SecretPresence: pres})
			if res.Status != nodes.Invalid || res.Applicable {
				t.Fatalf("addrs %s: want Invalid+not-applicable, got status=%v applicable=%v issues=%+v", c.name, res.Status, res.Applicable, res.Issues)
			}
			if !hasIssue(res, nodes.IssueArrayItemViolation, "localAddresses") {
				t.Fatalf("addrs %s: want arrayItemViolation@localAddresses, got %+v", c.name, res.Issues)
			}
			assertNoCanary(t, "addrs-"+c.name, res)
		})
	}
}

// TestWireGuardFieldIndependence: an invalid publicKey must not suppress
// localAddresses checking (and vice versa); both still produce their own issue.
func TestWireGuardFieldIndependence(t *testing.T) {
	p := loadProfile(t)
	pres := map[string]bool{"privateKey": true}
	// Both fields invalid -> both issues present (no early-return coupling).
	res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{
		"publicKey":      "pub",
		"localAddresses": []any{"bogus"},
	}), SecretPresence: pres})
	if !hasIssue(res, nodes.IssuePatternViolation, "publicKey") {
		t.Fatalf("independence: want patternViolation@publicKey, got %+v", res.Issues)
	}
	if !hasIssue(res, nodes.IssueArrayItemViolation, "localAddresses") {
		t.Fatalf("independence: want arrayItemViolation@localAddresses, got %+v", res.Issues)
	}
	// Invalid publicKey but valid localAddresses -> only the key issue.
	res = nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{
		"publicKey": "pub",
	}), SecretPresence: pres})
	if len(res.Issues) != 1 || !hasIssue(res, nodes.IssuePatternViolation, "publicKey") {
		t.Fatalf("independence key-only: want one patternViolation@publicKey, got %+v", res.Issues)
	}
	// Valid publicKey but invalid localAddresses -> only the address issue.
	res = nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{
		"localAddresses": []any{"bogus"},
	}), SecretPresence: pres})
	if len(res.Issues) != 1 || !hasIssue(res, nodes.IssueArrayItemViolation, "localAddresses") {
		t.Fatalf("independence addr-only: want one arrayItemViolation@localAddresses, got %+v", res.Issues)
	}
}

// TestWireGuardTypedNoDuplicateGeneric: when the SAME field already fails a
// generic check (e.g. out-of-bounds length, wrong type, item type), the typed
// rule must NOT add a second issue for that field.
func TestWireGuardTypedNoDuplicateGeneric(t *testing.T) {
	p := loadProfile(t)
	pres := map[string]bool{"privateKey": true}
	// publicKey 129 chars (> maxLength 128): only boundsViolation, NOT patternViolation.
	longKey := strings.Repeat("a", 129)
	res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"publicKey": longKey}), SecretPresence: pres})
	if len(res.Issues) != 1 || res.Issues[0].Code != nodes.IssueBoundsViolation || res.Issues[0].Field != "publicKey" {
		t.Fatalf("long key: want one boundsViolation@publicKey (no pattern dup), got %+v", res.Issues)
	}
	// publicKey wrong type (number): only typeMismatch.
	res = nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"publicKey": json.Number("443")}), SecretPresence: pres})
	if len(res.Issues) != 1 || res.Issues[0].Code != nodes.IssueTypeMismatch || res.Issues[0].Field != "publicKey" {
		t.Fatalf("typed key: want one typeMismatch@publicKey, got %+v", res.Issues)
	}
	// localAddresses non-string item: only the generic arrayItemViolation (count 1), not a second.
	res = nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"localAddresses": []any{"10.0.0.2/32", json.Number("123")}}), SecretPresence: pres})
	if len(res.Issues) != 1 || res.Issues[0].Code != nodes.IssueArrayItemViolation || res.Issues[0].Field != "localAddresses" {
		t.Fatalf("non-string item: want one arrayItemViolation@localAddresses, got %+v", res.Issues)
	}
	// localAddresses too many items (> maxItems 16): only boundsViolation.
	many := make([]any, 17)
	for i := range many {
		many[i] = "10.0.0.2/32"
	}
	res = nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"localAddresses": many}), SecretPresence: pres})
	if len(res.Issues) != 1 || res.Issues[0].Code != nodes.IssueBoundsViolation || res.Issues[0].Field != "localAddresses" {
		t.Fatalf("too many items: want one boundsViolation@localAddresses, got %+v", res.Issues)
	}
}

// TestWireGuardTypedInactiveOnly: invalid values in INACTIVE only are not
// promoted and do not gate active validity (D-016); active stays Valid.
func TestWireGuardTypedInactiveOnly(t *testing.T) {
	p := loadProfile(t)
	pres := map[string]bool{"privateKey": true}
	// Active carries only the other (valid) fields; the typed fields appear in
	// INACTIVE only, so there is no active/inactive collision and their invalid
	// inactive values must not gate active validity.
	active := map[string]any{
		"endpoint":     "w.example",
		"endpointPort": json.Number("51820"),
	}
	res := nodes.Validate(p, nodes.Input{
		Protocol:       "wireguard",
		Active:         active,
		Inactive:       map[string]any{"publicKey": "pub", "localAddresses": []any{"bogus"}},
		SecretPresence: pres,
	})
	if res.Status != nodes.Valid || !res.Applicable || len(res.Issues) != 0 {
		t.Fatalf("inactive-only invalid typed fields: want Valid, got %+v", res.Issues)
	}
}

// TestWireGuardTypedGenericFailureStillTyped: when the OTHER field is fine but
// one field has a generic failure, the eligible field still gets its typed check
// (no whole-rule skip on an unrelated invalid field).
func TestWireGuardTypedOtherFieldStillChecked(t *testing.T) {
	p := loadProfile(t)
	pres := map[string]bool{"privateKey": true}
	// endpointPort out of bounds (generic) + invalid publicKey (typed): both reported.
	res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{
		"endpointPort": json.Number("99999"),
		"publicKey":    "pub",
	}), SecretPresence: pres})
	if !hasIssue(res, nodes.IssueBoundsViolation, "endpointPort") {
		t.Fatalf("other-field: want boundsViolation@endpointPort, got %+v", res.Issues)
	}
	if !hasIssue(res, nodes.IssuePatternViolation, "publicKey") {
		t.Fatalf("other-field: want patternViolation@publicKey, got %+v", res.Issues)
	}
}

// TestWireGuardTypedDeclarationGuards: the typed rule honors the ACTUAL field
// declaration — a secret/unsupported/wrong-type/wrong-item-type classification
// never triggers the typed check (it stays inert), and a valid value is not
// misclassified. classification=unknown stays ordinary (unreachable unless Parse
// says otherwise).
func TestWireGuardTypedDeclarationGuards(t *testing.T) {
	mk := func(fields string) *capability.Profile {
		raw := []byte(`{"profileVersion":5,"protocols":{"wireguard":{"fields":{` + fields + `}}}}`)
		p, err := capability.Parse(raw)
		if err != nil {
			t.Fatalf("guard profile parse: %v\n%s", err, raw)
		}
		return p
	}
	pres := map[string]bool{"privateKey": true}

	// publicKey declared secret -> plaintext submission refused generically; typed check inert.
	pSec := mk(`"publicKey":{"type":"string","classification":"secret","secret":true,"required":true,"minLength":1,"maxLength":128},"localAddresses":{"type":"array","classification":"known","itemType":"string","required":true,"minItems":1,"maxItems":16}`)
	res := nodes.Validate(pSec, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"publicKey": "pub"})})
	if !hasIssue(res, nodes.IssueSecretPlaintextSubmitted, "publicKey") {
		t.Fatalf("secret publicKey: want secretPlaintextSubmitted@publicKey, got %+v", res.Issues)
	}
	if hasIssue(res, nodes.IssuePatternViolation, "publicKey") {
		t.Fatalf("secret publicKey must not also emit patternViolation: %+v", res.Issues)
	}

	// publicKey declared supported=false -> unsupportedField generically; typed check inert.
	pUnsup := mk(`"publicKey":{"type":"string","classification":"known","supported":false,"required":true,"minLength":1,"maxLength":128},"localAddresses":{"type":"array","classification":"known","itemType":"string","required":true,"minItems":1,"maxItems":16}`)
	res = nodes.Validate(pUnsup, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"publicKey": "pub"}), SecretPresence: pres})
	if !hasIssue(res, nodes.IssueUnsupportedField, "publicKey") {
		t.Fatalf("unsupported publicKey: want unsupportedField@publicKey, got %+v", res.Issues)
	}
	if hasIssue(res, nodes.IssuePatternViolation, "publicKey") {
		t.Fatalf("unsupported publicKey must not also emit patternViolation: %+v", res.Issues)
	}

	// localAddresses declared itemType integer -> the string items are arrayItemViolation generically;
	// the typed netip string-item check must not fire a duplicate.
	pItem := mk(`"publicKey":{"type":"string","classification":"known","required":true,"minLength":1,"maxLength":128},"localAddresses":{"type":"array","classification":"known","itemType":"integer","required":true,"minItems":1,"maxItems":16}`)
	res = nodes.Validate(pItem, nodes.Input{Protocol: "wireguard", Active: wgActive(t, nil), SecretPresence: pres})
	if !hasIssue(res, nodes.IssueArrayItemViolation, "localAddresses") {
		t.Fatalf("integer-item localAddresses: want arrayItemViolation@localAddresses, got %+v", res.Issues)
	}
}

// TestWireGuardTypedCanonicalRawNoEcho: via ValidateDocument the submitted bytes
// are preserved exactly (spelling/whitespace) and the public result never echoes
// the submitted key/address; invalid typed data is a semantic Invalid, not an
// outer refusal.
func TestWireGuardTypedCanonicalRawNoEcho(t *testing.T) {
	p := loadProfile(t)
	pres := map[string]bool{"privateKey": true}
	raw := []byte(`{"protocol":"wireguard","fields":{"active":{"endpoint":"w.example","endpointPort":51820,"publicKey":"pub","localAddresses":["10.0.0.2/32"],"mtu":1420},"inactive":{},"unknown":{}}}`)
	a, err := nodes.ValidateDocument(p, raw, pres)
	if err != nil {
		t.Fatalf("canonical envelope refused: %v", err)
	}
	if a.Validation != domain.ValidationInvalid || a.Result.Applicable {
		t.Fatalf("invalid typed key: want Invalid+not-applicable, got validation=%v applicable=%v issues=%+v",
			a.Validation, a.Result.Applicable, a.Result.Issues)
	}
	if !hasIssue(a.Result, nodes.IssuePatternViolation, "publicKey") {
		t.Fatalf("canonical: want patternViolation@publicKey, got %+v", a.Result.Issues)
	}
	if !bytes.Equal(a.Document.Raw, raw) {
		t.Fatalf("exact original raw must be preserved")
	}
	// Value-free: the submitted placeholder key "pub" must not appear in the
	// serialized public result (the only "pub" tolerated is the declared field
	// NAME "publicKey", never the value).
	pub, _ := json.Marshal(a.Result)
	if bytes.Contains(bytes.ReplaceAll(pub, []byte("publicKey"), nil), []byte("pub")) {
		t.Fatalf("public result echoes submitted key value: %s", pub)
	}
	assertNoCanary(t, "canonical-typed", a.Result)
}
