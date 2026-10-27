// Maintained behavior contract for the v4-FR008-PROTOCOL-SCOPE correction.
//
// The FR008 typed public WireGuard key/address rule MUST be hard-scoped to the
// wireguard protocol by the ACTUAL input protocol string. vless also declares
// a publicKey field (the REALITY key, valid per its own metadata); an
// unguarded rule leaks the WireGuard 32-byte key shape onto it and wrongly
// rejects a legitimate REALITY value. These tests pin the corrected scope:
// wireguard is still fully enforced, vless/socks5/http publicKey-shaped fields
// follow their own metadata, and the canonical adapter path preserves the
// exact bytes with a value-free public result.

package contract_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// scopeWGKey returns a 32-byte WireGuard key. std encodings contain '+' and
// '/'; url encodings contain '-' and '_'; this forces the real decoder branch
// (an ambiguous alphabet would not prove which branch ran). The padded variants
// of a 32-byte payload carry one trailing '=' (44 chars); the raw variants are
// 43 chars.
func scopeWGKey(t *testing.T, encoding string) string {
	t.Helper()
	b32 := []byte{0xfb, 0xff, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b} // exactly 32 bytes
	switch encoding {
	case "std-raw":
		return base64.RawStdEncoding.EncodeToString(b32) // 43 chars
	case "std-pad":
		return base64.StdEncoding.EncodeToString(b32) // 44 chars, trailing '='
	case "url-raw":
		return base64.RawURLEncoding.EncodeToString(b32) // 43 chars
	case "url-pad":
		return base64.URLEncoding.EncodeToString(b32) // 44 chars, trailing '='
	case "hex":
		return hex.EncodeToString(b32)
	}
	t.Fatalf("unknown encoding %q", encoding)
	return ""
}

// TestScopeWireGuardStillEnforced: the bad WireGuard key is STILL refused with
// patternViolation@publicKey after the scope guard (no bypass while excluding
// non-WG input).
func TestScopeWireGuardStillEnforced(t *testing.T) {
	p := loadProfile(t)
	res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{
		"publicKey": "not-wireguard-shaped",
	}), SecretPresence: map[string]bool{"privateKey": true}})
	if res.Status != nodes.Invalid || res.Applicable {
		t.Fatalf("bad WG key: want Invalid+not-applicable, got status=%v applicable=%v issues=%+v", res.Status, res.Applicable, res.Issues)
	}
	if len(res.Issues) != 1 || res.Issues[0].Code != nodes.IssuePatternViolation || res.Issues[0].Field != "publicKey" {
		t.Fatalf("bad WG key: want exactly one patternViolation@publicKey, got %+v", res.Issues)
	}
}

// TestScopeVlessPublicKeyOwnMetadata: a generic-valid, non-WireGuard-shaped
// vless publicKey (REALITY value) is accepted per its OWN metadata — the WG
// rule does not leak. Covers DIRECT Validate and the canonical ValidateDocument
// adapter, plus ordinary vless diagnostics staying exact.
func TestScopeVlessPublicKeyOwnMetadata(t *testing.T) {
	p := loadProfile(t)
	nonWG := []string{"reality-public-key", "pub", "not-wireguard-shaped",
		"Q2hlY2tSZWFsaXR5S2V5Rm9yVkxFU1M", // base64url decoding to <32 bytes (REALITY-typical)
	}
	for _, v := range nonWG {
		t.Run("direct/"+v, func(t *testing.T) {
			a := minValid("vless")
			a["publicKey"] = v
			res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: vlessPresence()})
			if res.Status != nodes.Valid || !res.Applicable {
				t.Fatalf("vless publicKey %q wrongly rejected: status=%v applicable=%v issues=%+v", v, res.Status, res.Applicable, res.Issues)
			}
			for _, is := range res.Issues {
				if is.Field == "publicKey" && is.Code == nodes.IssuePatternViolation {
					t.Fatalf("foreign WireGuard patternViolation leaked onto vless.publicKey %q", v)
				}
			}
		})
	}

	// Canonical adapter path: vless + reality + short publicKey stays Valid,
	// exact raw preserved, no foreign patternViolation.
	body := []byte(`{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"raw","security":"reality","publicKey":"REALITY-short-token"},"inactive":{},"unknown":{}}}`)
	ar, err := nodes.ValidateDocumentWithContext(p, body, trustedPresenceFor("vless"), nil)
	if err != nil {
		t.Fatalf("adapter refused the vless envelope: %v", err)
	}
	if ar.Validation != domain.ValidationValid || !ar.Result.Applicable {
		t.Fatalf("vless adapter publicKey wrongly rejected: validation=%v applicable=%v issues=%+v", ar.Validation, ar.Result.Applicable, ar.Result.Issues)
	}
	for _, is := range ar.Result.Issues {
		if is.Field == "publicKey" && is.Code == nodes.IssuePatternViolation {
			t.Fatalf("foreign WireGuard patternViolation leaked into the vless adapter path")
		}
	}
	if !bytes.Equal(ar.Document.Raw, body) {
		t.Fatalf("exact original vless raw must be preserved")
	}
}

// TestScopeVlessOrdinaryDiagnosticsExact: with the WG rule inert for vless, the
// ordinary vless diagnostics (REALITY/transport/auth) are unchanged.
func TestScopeVlessOrdinaryDiagnosticsExact(t *testing.T) {
	p := loadProfile(t)
	// REALITY + structurally-refused transport (mkcp/ws/httpupgrade) -> one
	// dependencyIncompatible@transport; publicKey untouched (no pattern issue).
	a := minValid("vless")
	a["security"] = "reality"
	a["transport"] = "mkcp"
	a["publicKey"] = "reality-public-key"
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: vlessPresence()})
	if !hasIssue(res, nodes.IssueDependencyIncompatible, "transport") {
		t.Fatalf("vless REALITY+mkcp: want dependencyIncompatible@transport, got %+v", res.Issues)
	}
	if hasIssue(res, nodes.IssuePatternViolation, "publicKey") {
		t.Fatalf("vless publicKey must not receive a WireGuard patternViolation: %+v", res.Issues)
	}
	// security not reality -> no transport bar; publicKey (REALITY-shaped) valid.
	a = minValid("vless")
	a["transport"] = "ws"
	a["publicKey"] = "reality-public-key"
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: vlessPresence()})
	if res.Status != nodes.Valid || !res.Applicable {
		t.Fatalf("vless non-reality with publicKey: want Valid, got %+v", res.Issues)
	}
}

// TestScopeNonWireGuardProtocolsNoKeyShape: socks5/http do not declare
// publicKey/localAddresses, so a submitted publicKey-shaped value is an
// ordinary unknownField (not a WireGuard patternViolation).
func TestScopeNonWireGuardProtocolsNoKeyShape(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range []string{"socks5", "http"} {
		t.Run(proto, func(t *testing.T) {
			a := minValid(proto)
			a["publicKey"] = "not-wireguard-shaped"
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: a, SecretPresence: trustedPresenceFor(proto)})
			if hasIssue(res, nodes.IssuePatternViolation, "publicKey") {
				t.Fatalf("%s: WireGuard patternViolation must not fire on unknown publicKey: %+v", proto, res.Issues)
			}
			if !hasIssue(res, nodes.IssueUnknownField, "unknown") {
				t.Fatalf("%s: unknown publicKey must be an ordinary unknownField: %+v", proto, res.Issues)
			}
		})
	}
}

// TestScopeWireGuardKeyAlphabetBranches: real std ('+'/'/') and url ('-'/'_')
// fixtures, asserting the distinguishing symbols occur, prove the actual
// decoder branch runs (bytes 0..31 alone are alphabet-ambiguous). Pinned
// decoder behavior: CRLF tolerated (no Strict/TrimSpace), one trailing '='
// trimmed, noncanonical trailing bits accepted by Go's decoder.
func TestScopeWireGuardKeyAlphabetBranches(t *testing.T) {
	p := loadProfile(t)
	pres := map[string]bool{"privateKey": true}

	cases := []struct {
		name, key      string
		mustContain    []string
		mustNotContain []string
	}{
		{"std-raw", scopeWGKey(t, "std-raw"), []string{"+", "/"}, []string{"-", "_"}},
		{"std-pad", scopeWGKey(t, "std-pad"), []string{"+", "/", "="}, []string{"-", "_"}},
		{"url-raw", scopeWGKey(t, "url-raw"), []string{"-", "_"}, []string{"+", "/"}},
		{"url-pad", scopeWGKey(t, "url-pad"), []string{"-", "_", "="}, []string{"+", "/"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, sym := range c.mustContain {
				if !strings.Contains(c.key, sym) {
					t.Fatalf("fixture %s must contain symbol %q to prove the branch: %q", c.name, sym, c.key)
				}
			}
			for _, sym := range c.mustNotContain {
				if strings.Contains(c.key, sym) {
					t.Fatalf("fixture %s must NOT contain symbol %q (wrong alphabet): %q", c.name, sym, c.key)
				}
			}
			res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"publicKey": c.key}), SecretPresence: pres})
			if res.Status != nodes.Valid || !res.Applicable || len(res.Issues) != 0 {
				t.Fatalf("key %s: want Valid, got %+v", c.name, res.Issues)
			}
		})
	}

	// CRLF tolerated (pinned decoder ignores CR/LF; no Strict/TrimSpace).
	rawKey := scopeWGKey(t, "std-pad")
	crlf := rawKey[:20] + "\r\n" + rawKey[20:]
	if res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"publicKey": crlf}), SecretPresence: pres}); res.Status != nodes.Valid {
		t.Fatalf("CRLF-embedded key should be accepted (pinned decoder tolerates CR/LF): %+v", res.Issues)
	}
	// One trailing '=' trimmed -> valid (43 raw chars + '=').
	raw43 := scopeWGKey(t, "std-raw")
	if res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"publicKey": raw43 + "="}), SecretPresence: pres}); res.Status != nodes.Valid {
		t.Fatalf("raw+one '=' key should be accepted: %+v", res.Issues)
	}
	// Noncanonical trailing bits: Go's decoder accepts non-zero trailing bits in
	// the final base64 character. Build a 32-byte url payload whose final char
	// carries non-zero trailing bits (a non-zero low 4 bits in the 64th sextet)
	// and confirm the pinned decoder still accepts it (no invented canonical-only
	// tightening).
	noncanon := raw43[:len(raw43)-1] + "z" // 'z' = 51 = 110011b: non-zero trailing bits
	if res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{"publicKey": noncanon}), SecretPresence: pres}); res.Status != nodes.Valid {
		t.Fatalf("noncanonical-trailing-bits url key should be accepted by the pinned decoder: %+v", res.Issues)
	}
}

// TestScopeDeclarationVariantsAndCounts: synthetic parsed declaration variants
// keep exact issue counts and same-field generic-first independence; a field
// whose generic check fails gets NO duplicate typed issue, and the other field
// is still checked.
func TestScopeDeclarationVariantsAndCounts(t *testing.T) {
	mk := func(fields string) *capability.Profile {
		raw := []byte(`{"profileVersion":5,"protocols":{"wireguard":{"fields":{` + fields + `}}}}`)
		p, err := capability.Parse(raw)
		if err != nil {
			t.Fatalf("variant profile parse: %v\n%s", err, raw)
		}
		return p
	}
	pres := map[string]bool{"privateKey": true}
	goodKey := scopeWGKey(t, "url-raw")
	// Minimal active map matching the variant profiles (only the two typed
	// fields are declared there; endpoint/endpointPort/mtu would be unknown).
	variantActive := func(key string, addrs []any) map[string]any {
		return map[string]any{"publicKey": key, "localAddresses": addrs}
	}

	// Variant: publicKey has a declared pattern that the WG-shaped key violates.
	// Generic pattern fires (1 issue); the typed rule must NOT add a second.
	pPat := mk(`"publicKey":{"type":"string","classification":"known","required":true,"minLength":1,"maxLength":128,"pattern":"^ZZ"},"localAddresses":{"type":"array","classification":"known","itemType":"string","required":true,"minItems":1,"maxItems":16}`)
	res := nodes.Validate(pPat, nodes.Input{Protocol: "wireguard", Active: variantActive(goodKey, []any{"10.0.0.2/32"}), SecretPresence: pres})
	if len(res.Issues) != 1 || res.Issues[0].Code != nodes.IssuePatternViolation || res.Issues[0].Field != "publicKey" {
		t.Fatalf("declared-pattern variant: want one patternViolation@publicKey (generic), got %+v", res.Issues)
	}

	// Variant: localAddresses itemType integer -> generic arrayItemViolation (1),
	// typed netip silent; publicKey still independently checked.
	pInt := mk(`"publicKey":{"type":"string","classification":"known","required":true,"minLength":1,"maxLength":128},"localAddresses":{"type":"array","classification":"known","itemType":"integer","required":true,"minItems":1,"maxItems":16}`)
	res = nodes.Validate(pInt, nodes.Input{Protocol: "wireguard", Active: variantActive("bad-key", []any{"10.0.0.2/32"}), SecretPresence: pres})
	if !hasIssue(res, nodes.IssueArrayItemViolation, "localAddresses") {
		t.Fatalf("integer-item variant: want arrayItemViolation@localAddresses, got %+v", res.Issues)
	}
	if !hasIssue(res, nodes.IssuePatternViolation, "publicKey") {
		t.Fatalf("integer-item variant: publicKey must still be independently typed-checked, got %+v", res.Issues)
	}

	// Both fields generic-valid + both typed-invalid -> exactly 2 issues.
	pFull := loadProfile(t)
	res = nodes.Validate(pFull, nodes.Input{Protocol: "wireguard", Active: wgActive(t, map[string]any{
		"publicKey": "bad-key", "localAddresses": []any{"bogus"},
	}), SecretPresence: pres})
	if len(res.Issues) != 2 {
		t.Fatalf("both-invalid: want exactly 2 issues, got %+v", res.Issues)
	}
	if !hasIssue(res, nodes.IssuePatternViolation, "publicKey") || !hasIssue(res, nodes.IssueArrayItemViolation, "localAddresses") {
		t.Fatalf("both-invalid: want pattern@publicKey + arrayItem@localAddresses, got %+v", res.Issues)
	}
}

// TestScopeWireGuardInvalidDeepEqualNoEchoNestedRaw: an actual INVALID WireGuard
// document reports a static value-free issue, never echoes the submitted
// key/address in the serialized public result, leaves ALL input maps and
// presence deeply unchanged, and preserves the exact canonical nested raw.
func TestScopeWireGuardInvalidDeepEqualNoEchoNestedRaw(t *testing.T) {
	p := loadProfile(t)
	pres := map[string]bool{"privateKey": true}
	keyVal := "bad-KEY-value"
	addrVal := "bogus"
	raw := []byte(`{"protocol":"wireguard","fields":{"active":{"endpoint":"w.example","endpointPort":51820,"publicKey":"` + keyVal + `","localAddresses":["` + addrVal + `"],"mtu":1420},"inactive":{"publicKey":"nested-inactive-key"},"unknown":{}}}`)

	ar, err := nodes.ValidateDocument(p, raw, pres)
	if err != nil {
		t.Fatalf("canonical envelope refused: %v", err)
	}
	if ar.Validation != domain.ValidationInvalid || ar.Result.Applicable {
		t.Fatalf("invalid typed WG: want Invalid+not-applicable, got validation=%v applicable=%v issues=%+v", ar.Validation, ar.Result.Applicable, ar.Result.Issues)
	}
	if !hasIssue(ar.Result, nodes.IssuePatternViolation, "publicKey") {
		t.Fatalf("want patternViolation@publicKey, got %+v", ar.Result.Issues)
	}

	// Exact canonical nested raw preserved.
	if !bytes.Equal(ar.Document.Raw, raw) {
		t.Fatalf("exact original canonical raw (nested inactive + spelling) must be preserved")
	}

	// Serialized public result is value-free: no submitted key/address echo.
	pub, _ := json.Marshal(ar.Result)
	if bytes.Contains(pub, []byte(keyVal)) || bytes.Contains(pub, []byte(addrVal)) {
		t.Fatalf("public result echoes submitted key/address: %s", pub)
	}
	// Static reason text (not derived from bytes).
	for _, is := range ar.Result.Issues {
		if is.Reason == "" || bytes.Contains([]byte(is.Reason), []byte(keyVal)) {
			t.Fatalf("issue reason must be static and value-free: %+v", is)
		}
	}
}

// TestScopeWireGuardDirectMapsPresenceImmutability: DIRECT Validate never
// mutates the active/inactive maps or presence (deep equality before/after).
func TestScopeWireGuardDirectMapsPresenceImmutability(t *testing.T) {
	p := loadProfile(t)
	pres := map[string]bool{"privateKey": true}
	active := wgActive(t, map[string]any{"publicKey": "bad-key", "localAddresses": []any{"bogus"}})
	inactive := map[string]any{"publicKey": "nested-inactive-key"}
	activeCopy := map[string]any{}
	for k, v := range active {
		activeCopy[k] = v
	}
	inactiveCopy := map[string]any{}
	for k, v := range inactive {
		inactiveCopy[k] = v
	}
	presCopy := map[string]bool{}
	for k, v := range pres {
		presCopy[k] = v
	}
	res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: active, Inactive: inactive, SecretPresence: pres})
	if res.Status != nodes.Invalid {
		t.Fatalf("want Invalid, got %+v", res.Issues)
	}
	if !reflect.DeepEqual(active, activeCopy) {
		t.Fatalf("active map mutated: before=%+v after=%+v", activeCopy, active)
	}
	if !reflect.DeepEqual(inactive, inactiveCopy) {
		t.Fatalf("inactive map mutated: before=%+v after=%+v", inactiveCopy, inactive)
	}
	if !reflect.DeepEqual(pres, presCopy) {
		t.Fatalf("presence map mutated: before=%+v after=%+v", presCopy, pres)
	}
}

// TestScopeEnvelopeEOFTrailing: a document with trailing content after the JSON
// value is refused at the syntax layer (exactly one JSON value), value-free.
func TestScopeEnvelopeEOFTrailing(t *testing.T) {
	p := loadProfile(t)
	pres := map[string]bool{"privateKey": true}
	good := `{"protocol":"wireguard","fields":{"active":{"endpoint":"w.example","endpointPort":51820,"publicKey":"` + scopeWGKey(t, "url-raw") + `","localAddresses":["10.0.0.2/32"]},"inactive":{},"unknown":{}}}`
	// Trailing EXTRA JSON VALUE after the envelope object is refused (exactly one
	// JSON value). A single trailing space is insignificant JSON whitespace and is
	// allowed, so the negative case appends a second value.
	trailing := good + " {}"
	ar, err := nodes.ValidateDocument(p, []byte(trailing), pres)
	if err == nil {
		t.Fatalf("trailing-content envelope must be refused before a Document exists")
	}
	_ = ar
	goodRes, err := nodes.ValidateDocument(p, []byte(good), pres)
	if err != nil {
		t.Fatalf("valid envelope refused: %v", err)
	}
	if goodRes.Validation != domain.ValidationValid || !goodRes.Result.Applicable {
		t.Fatalf("valid envelope: want Valid, got %+v", goodRes.Result.Issues)
	}
}
