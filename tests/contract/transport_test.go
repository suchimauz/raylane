// Maintained behavior contract for FR-002 structural REALITY/transport
// compatibility (D-009..D-012/D-016). It executes the REAL capability authority
// and the REAL nodes.Validate/ValidateDocument against the authored VLESS
// profile AND declaration-guard partial profiles — not fixture linting or AST
// inspection.
//
// Structural fact: the REALITY security builder supports only tcp/splithttp/
// grpc transports, so the canonical transport choices mkcp, ws and httpupgrade
// are structurally incompatible with security=reality. This rule rejects exactly
// those three ACTIVE pairs — it does not validate TLS/REALITY content, keys,
// flow, or engine readiness, and it removes no transport choice, downgrades no
// security, and rewrites/drops/defaults/promotes no value. All issues are on the
// declared path "transport" and value-free.

package contract_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// vlessActive returns an otherwise-valid vless active map with the given
// transport and security, plus the required uuid trusted presence.
func vlessActive(transport, security string) map[string]any {
	return map[string]any{
		"server": "v.example", "serverPort": float64(443),
		"transport": transport, "security": security,
	}
}

func vlessPresence() map[string]bool { return map[string]bool{"uuid": true} }

// TestRealityTransportForbiddenPairs: each of the three structurally
// incompatible ACTIVE REALITY transport pairs (mkcp/ws/httpupgrade + reality)
// is Invalid + not-applicable with exactly ONE value-free
// dependencyIncompatible on the declared transport path. Both socks5/http/
// wireguard-style unaffected protocols keep their positive baseline (no blanket
// protocol effect).
func TestRealityTransportForbiddenPairs(t *testing.T) {
	p := loadProfile(t)
	for _, transport := range []string{"mkcp", "ws", "httpupgrade"} {
		res := nodes.Validate(p, nodes.Input{
			Protocol: "vless", Active: vlessActive(transport, "reality"), SecretPresence: vlessPresence(),
		})
		if res.Status != nodes.Invalid || res.Applicable {
			t.Fatalf("reality+%s: want Invalid+not-applicable, got status=%v applicable=%v issues=%+v",
				transport, res.Status, res.Applicable, res.Issues)
		}
		if !hasIssue(res, nodes.IssueDependencyIncompatible, "transport") {
			t.Fatalf("reality+%s: want dependencyIncompatible@transport, got %+v", transport, res.Issues)
		}
		assertNoCanary(t, "reality+"+transport, res)
	}
}

// TestRealityCompatibleTransportsStayValid: REALITY stays valid with the
// transports its builder supports (raw/xhttp/grpc). A positive here means only
// that the narrow structural rule accepts it — NOT that TLS/flow/key/handshake
// works.
func TestRealityCompatibleTransportsStayValid(t *testing.T) {
	p := loadProfile(t)
	for _, transport := range []string{"raw", "xhttp", "grpc"} {
		res := nodes.Validate(p, nodes.Input{
			Protocol: "vless", Active: vlessActive(transport, "reality"), SecretPresence: vlessPresence(),
		})
		if res.Status != nodes.Valid || !res.Applicable {
			t.Fatalf("reality+%s: want Valid+Applicable, got status=%v applicable=%v issues=%+v",
				transport, res.Status, res.Applicable, res.Issues)
		}
		assertNoCanary(t, "reality-ok+"+transport, res)
	}
}

// TestAllTransportsWithTLSStayValid: every one of the six transport choices
// stays valid with security=tls — the rule never removes a transport choice or
// downgrades security. This preserves all six selections.
func TestAllTransportsWithTLSStayValid(t *testing.T) {
	p := loadProfile(t)
	for _, transport := range []string{"raw", "mkcp", "ws", "grpc", "httpupgrade", "xhttp"} {
		res := nodes.Validate(p, nodes.Input{
			Protocol: "vless", Active: vlessActive(transport, "tls"), SecretPresence: vlessPresence(),
		})
		if res.Status != nodes.Valid || !res.Applicable {
			t.Fatalf("tls+%s: want Valid+Applicable, got status=%v applicable=%v issues=%+v",
				transport, res.Status, res.Applicable, res.Issues)
		}
	}
}

// TestTransportRuleOtherProtocolsUnaffected: socks5/http/wireguard set the
// correct Input.Protocol and keep their positive baseline — no invented blanket
// protocol effect. (vless is the only protocol declaring transport+security.)
func TestTransportRuleOtherProtocolsUnaffected(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range []string{"socks5", "http", "wireguard"} {
		res := nodes.Validate(p, nodes.Input{
			Protocol: proto, Active: minValid(proto), SecretPresence: trustedPresenceFor(proto),
		})
		if res.Status != nodes.Valid || !res.Applicable {
			t.Fatalf("%s baseline: want Valid+Applicable, got status=%v applicable=%v issues=%+v",
				proto, res.Status, res.Applicable, res.Issues)
		}
	}
}

// TestTransportRuleInactiveOnlySelectorsInert: transport and/or security present
// ONLY in the inactive bucket are preserved, never promoted — the cross-rule
// stays silent. A forbidden-looking inactive pair (mkcp+reality) is NOT
// rejected because the selectors are not ACTIVE; the node stays Valid with the
// inactive values retained for a possible later return.
func TestTransportRuleInactiveOnlySelectorsInert(t *testing.T) {
	p := loadProfile(t)
	active := map[string]any{"server": "v.example", "serverPort": float64(443)}
	inactive := map[string]any{"transport": "mkcp", "security": "reality"}
	res := nodes.Validate(p, nodes.Input{
		Protocol: "vless", Active: active, Inactive: inactive, SecretPresence: vlessPresence(),
	})
	if res.Status != nodes.Valid || !res.Applicable {
		t.Fatalf("inactive-only forbidden pair must stay Valid (preserved, not promoted): status=%v applicable=%v issues=%+v",
			res.Status, res.Applicable, res.Issues)
	}
	if hasIssue(res, nodes.IssueDependencyIncompatible, "transport") {
		t.Fatalf("inactive-only selectors must not trigger the cross-rule: %+v", res.Issues)
	}
	assertNoCanary(t, "inactive-only-transport", res)

	// One direction: active transport + inactive-only security.
	active2 := map[string]any{"server": "v.example", "serverPort": float64(443), "transport": "mkcp"}
	inactive2 := map[string]any{"security": "reality"}
	res2 := nodes.Validate(p, nodes.Input{
		Protocol: "vless", Active: active2, Inactive: inactive2, SecretPresence: vlessPresence(),
	})
	if hasIssue(res2, nodes.IssueDependencyIncompatible, "transport") {
		t.Fatalf("inactive-only security must not activate the cross-rule: %+v", res2.Issues)
	}

	// Truly absent BOTH buckets for a required selector keeps ordinary
	// requiredMissing (conditional silence does not promise overall Valid).
	active3 := map[string]any{"server": "v.example", "serverPort": float64(443), "transport": "mkcp"}
	res3 := nodes.Validate(p, nodes.Input{
		Protocol: "vless", Active: active3, SecretPresence: vlessPresence(),
	})
	if !hasIssue(res3, nodes.IssueRequiredMissing, "security") {
		t.Fatalf("truly-absent required security keeps ordinary requiredMissing: %+v", res3.Issues)
	}
	if hasIssue(res3, nodes.IssueDependencyIncompatible, "transport") {
		t.Fatalf("absent security must not trigger the cross-rule: %+v", res3.Issues)
	}
}

// TestRealityTransportValidateDocumentRawPreserved: a canonical ValidateDocument
// with a syntax-valid incompatible pair returns semantic Invalid/not-applicable
// (NOT an outer malformed-envelope refusal) and preserves EXACT original raw
// bytes (whitespace, numeric spelling, nested inactive values). Input maps and
// trusted presence are not mutated; the public result never echoes submitted
// values.
func TestRealityTransportValidateDocumentRawPreserved(t *testing.T) {
	p := loadProfile(t)
	doc := `{ "protocol":"vless", "fields":{ "active":{ "server":"v.example", "serverPort":443, "transport":"mkcp", "security":"reality" }, "inactive":{ "sni":"retained.example" }, "unknown":{ } } }`
	presence := vlessPresence()
	res, err := nodes.ValidateDocument(p, []byte(doc), presence)
	if err != nil {
		t.Fatalf("canonical incompatible pair must not be an envelope refusal: %v", err)
	}
	if res.Result.Status != nodes.Invalid || res.Result.Applicable {
		t.Fatalf("want semantic Invalid+not-applicable, got status=%v applicable=%v issues=%+v",
			res.Result.Status, res.Result.Applicable, res.Result.Issues)
	}
	if !hasIssue(res.Result, nodes.IssueDependencyIncompatible, "transport") {
		t.Fatalf("want dependencyIncompatible@transport, got %+v", res.Result.Issues)
	}
	if !bytes.Equal(res.Document.Raw, []byte(doc)) {
		t.Fatalf("exact original raw (whitespace/numeric/inactive) must be preserved")
	}
	// Trusted presence not mutated.
	if !presence["uuid"] || len(presence) != 1 {
		t.Fatalf("trusted presence must be unchanged: %+v", presence)
	}
	// Public result serialization is value-free: the submitted transport value
	// and canary never echo into issues.
	out, _ := json.Marshal(res.Result)
	for _, v := range []string{"mkcp", secretCanary} {
		if bytes.Contains(out, []byte(v)) {
			t.Fatalf("submitted value %q echoed into public result: %s", v, out)
		}
	}
	assertNoCanary(t, "reality-doc", res.Result)

	// CONTROL: a compatible reality pair (raw) validates and preserves raw.
	good := `{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"raw","security":"reality"},"inactive":{},"unknown":{}}}`
	res2, err2 := nodes.ValidateDocument(p, []byte(good), vlessPresence())
	if err2 != nil || res2.Result.Status != nodes.Valid || !res2.Result.Applicable {
		t.Fatalf("control raw+reality must validate: err=%v issues=%+v", err2, res2.Result.Issues)
	}
	if !bytes.Equal(res2.Document.Raw, []byte(good)) {
		t.Fatalf("control exact raw must be preserved")
	}
}

// --- Declaration-guard partial profiles (each selector independently) ---

// transportGuardProfile builds a vless-like profile with the given transport
// and security declarations so each selector's metadata is mutated
// independently (declaration authority, not the full authored profile).
func transportGuardProfile(t *testing.T, transportDecl, securityDecl string) *capability.Profile {
	t.Helper()
	fields := `"server":{"type":"string","classification":"known"},"uuid":{"type":"string","classification":"secret","secret":true}`
	if transportDecl != "" {
		fields += `,` + transportDecl
	}
	if securityDecl != "" {
		fields += `,` + securityDecl
	}
	raw := []byte(`{"profileVersion":5,"protocols":{"p":{"fields":{` + fields + `}}}}`)
	prof, err := capability.Parse(raw)
	if err != nil {
		t.Fatalf("transport guard profile did not parse: %v\n%s", err, raw)
	}
	return prof
}

const fullTransport = `"transport":{"type":"enum","classification":"known","allowedValues":["raw","mkcp","ws","grpc","httpupgrade","xhttp"]}`
const realitySecurity = `"security":{"type":"enum","classification":"known","allowedValues":["tls","reality"]}`

// transportGuardValid asserts a Valid+Applicable result (no cross-rule demand).
func transportGuardValid(t *testing.T, label string, res nodes.Result) {
	t.Helper()
	if res.Status != nodes.Valid || !res.Applicable {
		t.Fatalf("%s: want Valid+Applicable, got status=%v applicable=%v issues=%+v",
			label, res.Status, res.Applicable, res.Issues)
	}
	assertNoCanary(t, label, res)
}

// transportGuardForbidden asserts exactly one dependencyIncompatible@transport.
func transportGuardForbidden(t *testing.T, label string, res nodes.Result) {
	t.Helper()
	if res.Status != nodes.Invalid || res.Applicable {
		t.Fatalf("%s: want Invalid+not-applicable, got status=%v applicable=%v issues=%+v",
			label, res.Status, res.Applicable, res.Issues)
	}
	if !hasIssue(res, nodes.IssueDependencyIncompatible, "transport") {
		t.Fatalf("%s: want dependencyIncompatible@transport, got %+v", label, res.Issues)
	}
	assertNoCanary(t, label, res)
}

// TestTransportRuleBothSelectorsEligibilityGuard: the cross-rule fires ONLY when
// BOTH selectors are independently eligible (declared known non-secret
// supported ENUM) with active string values in their ACTUAL AllowedValues. An
// ineligible declaration (secret / wrong declared type / unsupported / missing
// / out-of-subset) is inert even for the forbidden pair — the ordinary generic
// issue remains ordinary, never an invented conditional duplicate.
func TestTransportRuleBothSelectorsEligibilityGuard(t *testing.T) {
	base := map[string]any{"server": "v.example"}
	pres := map[string]bool{"uuid": true}

	// Reference: both eligible + forbidden pair fires.
	ref := transportGuardProfile(t, fullTransport, realitySecurity)
	transportGuardForbidden(t, "both-eligible/forbidden",
		nodes.Validate(ref, nodes.Input{Protocol: "p", Active: withTransport(base, "mkcp", "reality"), SecretPresence: pres}))

	// transport declaration ineligible (each variant) -> inert for the cross-rule.
	badTransport := []struct{ label, decl string }{
		{"secret", `"transport":{"type":"enum","classification":"secret","secret":true,"allowedValues":["mkcp","reality"]}`},
		{"wrongtype", `"transport":{"type":"string","classification":"known"}`},
		{"unsupported", `"transport":{"type":"enum","classification":"known","supported":false,"allowedValues":["mkcp","reality"]}`},
		{"missing", ""}, // no transport declaration at all
		{"outofsubset", `"transport":{"type":"enum","classification":"known","allowedValues":["raw","grpc"]}`},
	}
	for _, bt := range badTransport {
		prof := transportGuardProfile(t, bt.decl, realitySecurity)
		res := nodes.Validate(prof, nodes.Input{Protocol: "p", Active: withTransport(base, "mkcp", "reality"), SecretPresence: pres})
		if hasIssue(res, nodes.IssueDependencyIncompatible, "transport") {
			t.Fatalf("ineligible transport (%s) must be inert for the cross-rule: %+v", bt.label, res.Issues)
		}
	}

	// security declaration ineligible (each variant) -> inert for the cross-rule.
	badSecurity := []struct{ label, decl string }{
		{"secret", `"security":{"type":"enum","classification":"secret","secret":true,"allowedValues":["tls","reality"]}`},
		{"wrongtype", `"security":{"type":"string","classification":"known"}`},
		{"unsupported", `"security":{"type":"enum","classification":"known","supported":false,"allowedValues":["tls","reality"]}`},
		{"missing", ""},
		{"outofsubset", `"security":{"type":"enum","classification":"known","allowedValues":["tls"]}`},
	}
	for _, bs := range badSecurity {
		prof := transportGuardProfile(t, fullTransport, bs.decl)
		res := nodes.Validate(prof, nodes.Input{Protocol: "p", Active: withTransport(base, "mkcp", "reality"), SecretPresence: pres})
		if hasIssue(res, nodes.IssueDependencyIncompatible, "transport") {
			t.Fatalf("ineligible security (%s) must be inert for the cross-rule: %+v", bs.label, res.Issues)
		}
	}

	// Wrong declared type STRING carrying a valid matching scalar is INERT for
	// the cross-rule (the normalized decision: not a generic gap). Both declared
	// as string with matching string values -> no structural demand.
	strProf := transportGuardProfile(t,
		`"transport":{"type":"string","classification":"known"}`,
		`"security":{"type":"string","classification":"known"}`)
	transportGuardValid(t, "string-typed-inert",
		nodes.Validate(strProf, nodes.Input{Protocol: "p", Active: withTransport(base, "mkcp", "reality"), SecretPresence: pres}))

	// Out-of-subset ACTIVE value stays ordinary (enumViolation), not the cross-rule.
	subTransport := `"transport":{"type":"enum","classification":"known","allowedValues":["raw","grpc","xhttp"]}`
	subProf := transportGuardProfile(t, subTransport, realitySecurity)
	res := nodes.Validate(subProf, nodes.Input{Protocol: "p", Active: withTransport(base, "vmess", "reality"), SecretPresence: pres})
	if hasIssue(res, nodes.IssueDependencyIncompatible, "transport") {
		t.Fatalf("out-of-subset active value must stay ordinary, not cross-rule: %+v", res.Issues)
	}
}

// withTransport returns a copy of base with transport and security set.
func withTransport(base map[string]any, transport, security string) map[string]any {
	m := map[string]any{}
	for k, v := range base {
		m[k] = v
	}
	m["transport"] = transport
	m["security"] = security
	return m
}
