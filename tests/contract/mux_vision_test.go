// Maintained behavior contract for v4-US1-T011-mux-vision-active-combination
// (FR-003 minimal obligation, V4-FR003-MUX-FLOW-DIRECTION-COMPATIBILITY).
//
// Pure vless VALIDATION rule (settled parent decisions FINAL): when an
// otherwise-valid VLESS draft has ACTIVE muxEnabled=true AND an ACTIVE flow
// enum value admitted by its OWN AllowedValues that is exactly
// xtls-rprx-vision OR xtls-rprx-vision-udp443 AND an ACTIVE concurrency that
// passes its OWN ordinary shape+bounds and is an exact integer >= 0, the
// draft is refused for apply with EXACTLY ONE existing static value-free
// dependencyIncompatible on the declared concurrency path -> Invalid /
// notApplicable, preserving the exact input/raw document. This is a structural
// validator fact (enabled Vision ordinary concurrency of zero becomes an
// unsafe upstream default of 8); it is NOT an engine/handshake/readiness
// certification. The future compiler/apply increment (NOT this scope) must not
// emit an enabled Vision mux with ordinary concurrency absent/0/positive and
// must block compile/apply on unresolved faithful safe emission while allowing
// exact draft SAVE.

package contract_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// muxVisionBase returns an otherwise-clean minimal VLESS active map and removes
// any mux/flow/concurrency so the caller controls the combination precisely.
func muxVisionBase() map[string]any {
	a := minValid("vless")
	delete(a, "muxEnabled")
	delete(a, "flow")
	delete(a, "concurrency")
	delete(a, "xudpConcurrency")
	return a
}

// expectMuxVisionForbidden asserts the settled forbidden-combination outcome:
// Invalid, not applicable, exactly one dependencyIncompatible on the declared
// concurrency path, no value echo in any issue reason, and the input map left
// byte-for-byte unchanged (no reset/default/auto-toggle).
func expectMuxVisionForbidden(t *testing.T, res nodes.Result, before map[string]any, after map[string]any) {
	t.Helper()
	if res.Status != nodes.Invalid || res.Applicable {
		t.Fatalf("forbidden mux+vision+concurrency>=0: want Invalid/notApplicable, got %v/%v issues=%+v",
			res.Status, res.Applicable, res.Issues)
	}
	dep := 0
	for _, is := range res.Issues {
		if is.Code == nodes.IssueDependencyIncompatible && is.Field == "concurrency" {
			dep++
		}
	}
	if dep != 1 {
		t.Fatalf("want exactly one dependencyIncompatible@concurrency, got %d issues=%+v", dep, res.Issues)
	}
	for _, is := range res.Issues {
		if is.Reason == "" || containsDigit(is.Reason) {
			t.Fatalf("issue reason must be a static closed constant, got %q", is.Reason)
		}
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("input map mutated: before=%v after=%v", before, after)
	}
}

func containsDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// A1: ACTIVE mux=true + each Vision spelling + ordinary concurrency {0,1,8,257,
// 32767} -> Invalid/notApplicable with exactly one dependencyIncompatible@
// concurrency. Negative {-32768,-1} stays Valid/applicable in otherwise-clean
// cases. Direct numeric representations int/int64/finite-integral float follow
// existing asInt semantics; canonical exact-integral spellings (8e0, 0.0, -0)
// cannot evade the rule (json.Number path).
func TestMuxVisionForbiddenCombination(t *testing.T) {
	p := loadProfile(t)
	for _, flow := range []string{"xtls-rprx-vision", "xtls-rprx-vision-udp443"} {
		for _, cv := range []any{0, 1, 8, 257, 32767} {
			a := muxVisionBase()
			a["muxEnabled"] = true
			a["flow"] = flow
			a["concurrency"] = cv
			before := cloneAnyMap(a)
			res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
			expectMuxVisionForbidden(t, res, before, a)
		}
	}
	// json.Number canonical exact-integral spellings cannot evade the rule.
	for _, raw := range []string{"8e0", "0.0", "-0"} {
		a := muxVisionBase()
		a["muxEnabled"] = true
		a["flow"] = "xtls-rprx-vision"
		a["concurrency"] = json.Number(raw)
		before := cloneAnyMap(a)
		res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
		expectMuxVisionForbidden(t, res, before, a)
	}
	// Negative concurrency {-32768,-1} stays Valid/applicable (negative disables).
	for _, cv := range []any{-32768, -1} {
		a := muxVisionBase()
		a["muxEnabled"] = true
		a["flow"] = "xtls-rprx-vision"
		a["concurrency"] = cv
		res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
		if res.Status != nodes.Valid || len(res.Issues) != 0 || !res.Applicable {
			t.Fatalf("negative concurrency %v: want Valid/zero-issues/applicable, got %v/%v issues=%+v",
				cv, res.Status, res.Applicable, res.Issues)
		}
	}
	// Tiny nonzero fraction / huge exponent use their ordinary issue, NOT the
	// conditional dependencyIncompatible (exactly zero extra conditional issue).
	for _, cv := range []any{json.Number("0.5"), json.Number("1E400")} {
		a := muxVisionBase()
		a["muxEnabled"] = true
		a["flow"] = "xtls-rprx-vision"
		a["concurrency"] = cv
		res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
		if hasIssue(res, nodes.IssueDependencyIncompatible, "concurrency") {
			t.Fatalf("fraction/out-of-range concurrency %v must NOT add the conditional issue, got %+v", cv, res.Issues)
		}
		if res.Status != nodes.Invalid {
			t.Fatalf("fraction/out-of-range concurrency %v must still be Invalid via its ordinary issue, got %v", cv, res.Status)
		}
	}
}

// A2: switch/flow/presence controls stay silent (no invented dependency), the
// input map is unchanged, and XUDP is independent (not part of the condition).
func TestMuxVisionSilentControls(t *testing.T) {
	p := loadProfile(t)
	silent := func(name string, setup func(map[string]any)) {
		t.Run(name, func(t *testing.T) {
			a := muxVisionBase()
			setup(a)
			before := cloneAnyMap(a)
			res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
			if hasIssue(res, nodes.IssueDependencyIncompatible, "concurrency") {
				t.Fatalf("%s: rule must be silent, got dependencyIncompatible@concurrency issues=%+v", name, res.Issues)
			}
			if res.Status != nodes.Valid || !res.Applicable {
				t.Fatalf("%s: want Valid/applicable, got %v/%v issues=%+v", name, res.Status, res.Applicable, res.Issues)
			}
			if !reflect.DeepEqual(before, a) {
				t.Fatalf("%s: input map mutated: before=%v after=%v", name, before, a)
			}
		})
	}
	// mux false / absent.
	silent("mux false", func(a map[string]any) { a["muxEnabled"] = false; a["flow"] = "xtls-rprx-vision"; a["concurrency"] = 8 })
	silent("mux absent", func(a map[string]any) { a["flow"] = "xtls-rprx-vision"; a["concurrency"] = 8 })
	// flow empty / absent.
	silent("flow empty", func(a map[string]any) { a["muxEnabled"] = true; a["flow"] = ""; a["concurrency"] = 8 })
	silent("flow absent", func(a map[string]any) { a["muxEnabled"] = true; a["concurrency"] = 8 })
	// concurrency absent.
	silent("concurrency absent", func(a map[string]any) { a["muxEnabled"] = true; a["flow"] = "xtls-rprx-vision" })
	// Inactive-only participants stay silent.
	t.Run("inactive only", func(t *testing.T) {
		a := muxVisionBase()
		a["muxEnabled"] = true
		a["flow"] = "xtls-rprx-vision"
		a["concurrency"] = 8
		inactive := map[string]any{"flow": "xtls-rprx-vision"}
		a["flow"] = "" // flow not active
		delete(a, "flow")
		res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, Inactive: inactive, SecretPresence: trustedPresenceFor("vless")})
		if hasIssue(res, nodes.IssueDependencyIncompatible, "concurrency") {
			t.Fatalf("inactive-only flow must keep rule silent, got %+v", res.Issues)
		}
	})

	// XUDP independent: valid XUDP {min,-1,0,8,max} and absent do not affect the
	// rule; the forbidden combination still fires regardless of XUDP.
	for _, xv := range []any{-32768, -1, 0, 8, 32767} {
		a := muxVisionBase()
		a["muxEnabled"] = true
		a["flow"] = "xtls-rprx-vision"
		a["concurrency"] = 8
		a["xudpConcurrency"] = xv
		res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
		if !hasIssue(res, nodes.IssueDependencyIncompatible, "concurrency") {
			t.Fatalf("forbidden combo with xudp=%v must still fire, got %+v", xv, res.Issues)
		}
	}
	// Negative ordinary concurrency stays Valid even with XUDP positive (M6/M7/M8
	// preserved): no invented cross-field refusal.
	a := muxVisionBase()
	a["muxEnabled"] = true
	a["flow"] = "xtls-rprx-vision"
	a["concurrency"] = -1
	a["xudpConcurrency"] = 8
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
	if res.Status != nodes.Valid || len(res.Issues) != 0 || !res.Applicable {
		t.Fatalf("negative concurrency + positive xudp: want Valid independent, got %v/%v issues=%+v", res.Status, res.Applicable, res.Issues)
	}
	// An unrelated invalid field does NOT suppress the eligible combination
	// finding (no blanket early return): serverPort out of bounds still yields
	// its own boundsViolation AND the combination dependencyIncompatible.
	a = muxVisionBase()
	a["muxEnabled"] = true
	a["flow"] = "xtls-rprx-vision"
	a["concurrency"] = 8
	a["serverPort"] = 70000
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
	if !hasIssue(res, nodes.IssueDependencyIncompatible, "concurrency") {
		t.Fatalf("eligible combination must fire alongside an unrelated invalid field, got %+v", res.Issues)
	}
	if !hasIssue(res, nodes.IssueBoundsViolation, "serverPort") {
		t.Fatalf("unrelated invalid field must keep its own issue, got %+v", res.Issues)
	}
}

// A3: each participant's OWN declaration guard on a real trusted custom
// profile, and the rule never leaks into a non-vless protocol.
func TestMuxVisionCustomAuthorityGuards(t *testing.T) {
	base := func(fields string) string {
		return `{"profileVersion":6,"protocols":{"vless":{"fields":` + fields + `},` +
			`"custom":{"fields":{"server":{"type":"string","classification":"known","required":true},` +
			`"muxEnabled":{"type":"boolean","classification":"known"},` +
			`"flow":{"type":"enum","classification":"known","allowedValues":["","xtls-rprx-vision","xtls-rprx-vision-udp443"]},` +
			`"concurrency":{"type":"integer","classification":"known","minimum":-32768,"maximum":32767}}}}}`
	}
	// A valid participant declaration set (the positive custom-profile control:
	// the rule DOES fire on a custom vless profile reusing the names).
	valid := `{"server":{"type":"string","classification":"known","required":true},` +
		`"muxEnabled":{"type":"boolean","classification":"known"},` +
		`"flow":{"type":"enum","classification":"known","allowedValues":["","xtls-rprx-vision","xtls-rprx-vision-udp443"]},` +
		`"concurrency":{"type":"integer","classification":"known","minimum":-32768,"maximum":32767}}`

	// Positive custom-profile control: identical vless declarations on a custom
	// profile DO fire the rule (it is authority-driven, not hardcoded to the
	// authored profile bytes).
	t.Run("custom vless profile fires rule", func(t *testing.T) {
		cp := parseProfileT(t, base(valid))
		a := map[string]any{"server": "v.example", "muxEnabled": true, "flow": "xtls-rprx-vision", "concurrency": 8}
		res := nodes.Validate(cp, nodes.Input{Protocol: "vless", Active: a, SecretPresence: map[string]bool{}})
		if !hasIssue(res, nodes.IssueDependencyIncompatible, "concurrency") {
			t.Fatalf("custom vless profile must fire the rule, got %+v", res.Issues)
		}
	})

	// Non-vless custom protocol with identical declarations never receives the rule.
	t.Run("non-vless never receives rule", func(t *testing.T) {
		cp := parseProfileT(t, base(valid))
		a := map[string]any{
			"server": "c.example", "muxEnabled": true, "flow": "xtls-rprx-vision", "concurrency": 8,
		}
		res := nodes.Validate(cp, nodes.Input{Protocol: "custom", Active: a, SecretPresence: map[string]bool{}})
		if hasIssue(res, nodes.IssueDependencyIncompatible, "concurrency") || res.Status != nodes.Valid {
			t.Fatalf("custom protocol must never receive the vless rule, got %v issues=%+v", res.Status, res.Issues)
		}
	})

	// Per-participant guards on a custom VLESS profile: remove/invalidate each
	// participant's declaration and the rule stays silent.
	guard := func(name, fields string) {
		t.Run(name, func(t *testing.T) {
			cp := parseProfileT(t, base(fields))
			a := map[string]any{
				"server": "v.example", "muxEnabled": true, "flow": "xtls-rprx-vision", "concurrency": 8,
			}
			res := nodes.Validate(cp, nodes.Input{Protocol: "vless", Active: a, SecretPresence: map[string]bool{}})
			if hasIssue(res, nodes.IssueDependencyIncompatible, "concurrency") {
				t.Fatalf("%s: rule must be silent, got %+v", name, res.Issues)
			}
		})
	}
	// muxEnabled absent from declaration.
	guard("mux absent decl", `{"server":{"type":"string","classification":"known","required":true},`+
		`"flow":{"type":"enum","classification":"known","allowedValues":["","xtls-rprx-vision"]},`+
		`"concurrency":{"type":"integer","classification":"known","minimum":-32768,"maximum":32767}}`)
	// muxEnabled declared secret -> ineligible (and plaintext smuggle refused).
	guard("mux secret decl", `{"server":{"type":"string","classification":"known","required":true},`+
		`"muxEnabled":{"type":"boolean","classification":"secret","secret":true},`+
		`"flow":{"type":"enum","classification":"known","allowedValues":["","xtls-rprx-vision"]},`+
		`"concurrency":{"type":"integer","classification":"known","minimum":-32768,"maximum":32767}}`)
	// muxEnabled supported=false -> ineligible.
	guard("mux supported false", `{"server":{"type":"string","classification":"known","required":true},`+
		`"muxEnabled":{"type":"boolean","classification":"known","supported":false},`+
		`"flow":{"type":"enum","classification":"known","allowedValues":["","xtls-rprx-vision"]},`+
		`"concurrency":{"type":"integer","classification":"known","minimum":-32768,"maximum":32767}}`)
	// muxEnabled wrong declared type (string, not boolean).
	guard("mux wrong type", `{"server":{"type":"string","classification":"known","required":true},`+
		`"muxEnabled":{"type":"string","classification":"known"},`+
		`"flow":{"type":"enum","classification":"known","allowedValues":["","xtls-rprx-vision"]},`+
		`"concurrency":{"type":"integer","classification":"known","minimum":-32768,"maximum":32767}}`)
	// concurrency narrowed bounds 1..4: 0 is an ordinary boundsViolation with NO
	// conditional duplicate; 1 is admitted and the condition applies.
	t.Run("narrowed concurrency bounds", func(t *testing.T) {
		narrow := `{"server":{"type":"string","classification":"known","required":true},` +
			`"muxEnabled":{"type":"boolean","classification":"known"},` +
			`"flow":{"type":"enum","classification":"known","allowedValues":["","xtls-rprx-vision"]},` +
			`"concurrency":{"type":"integer","classification":"known","minimum":1,"maximum":4}}`
		cp := parseProfileT(t, base(narrow))
		// 0: ordinary boundsViolation, no conditional issue.
		a := map[string]any{"server": "v.example", "muxEnabled": true, "flow": "xtls-rprx-vision", "concurrency": 0}
		res := nodes.Validate(cp, nodes.Input{Protocol: "vless", Active: a, SecretPresence: map[string]bool{}})
		if hasIssue(res, nodes.IssueDependencyIncompatible, "concurrency") {
			t.Fatalf("concurrency=0 under narrowed bounds must NOT add the conditional issue, got %+v", res.Issues)
		}
		if !hasIssue(res, nodes.IssueBoundsViolation, "concurrency") {
			t.Fatalf("concurrency=0 under narrowed bounds must keep its ordinary boundsViolation, got %+v", res.Issues)
		}
		// 1: admitted by narrowed bounds, condition applies.
		a["concurrency"] = 1
		res = nodes.Validate(cp, nodes.Input{Protocol: "vless", Active: a, SecretPresence: map[string]bool{}})
		if !hasIssue(res, nodes.IssueDependencyIncompatible, "concurrency") {
			t.Fatalf("concurrency=1 under narrowed bounds must trigger the condition, got %+v", res.Issues)
		}
	})
	// flow enum subset excluding Vision: the rule is silent (ordinary enum issue).
	t.Run("flow subset excludes vision", func(t *testing.T) {
		sub := `{"server":{"type":"string","classification":"known","required":true},` +
			`"muxEnabled":{"type":"boolean","classification":"known"},` +
			`"flow":{"type":"enum","classification":"known","allowedValues":[""]},` +
			`"concurrency":{"type":"integer","classification":"known","minimum":-32768,"maximum":32767}}`
		cp := parseProfileT(t, base(sub))
		a := map[string]any{"server": "v.example", "muxEnabled": true, "flow": "xtls-rprx-vision", "concurrency": 8}
		res := nodes.Validate(cp, nodes.Input{Protocol: "vless", Active: a, SecretPresence: map[string]bool{}})
		if hasIssue(res, nodes.IssueDependencyIncompatible, "concurrency") {
			t.Fatalf("flow outside own enum subset must keep the rule silent, got %+v", res.Issues)
		}
	})
}

// A4: the canonical ValidateDocument envelope round-trips a forbidden pair as
// a SEMANTIC refusal (successful syntax parse) with the exact raw bytes
// retained and ValidationInvalid — not ErrMalformedJSON, not a dropped draft.
// The safe projection keeps the ordinary allowlisted scalars (server/numerics)
// while secret/opaque/unknown canaries never appear in the error-checked
// marshaled Result/issues/projection. Malformed/trailing JSON is still
// syntax-refused.
func TestMuxVisionEnvelopeAndProjection(t *testing.T) {
	p := loadProfile(t)
	// Deliberate whitespace + escaped string + numeric lexemes in the envelope.
	raw := []byte(`{
  "protocol": "vless",
  "fields": {
    "active": {
      "server": "v.example",
      "serverPort": 443,
      "transport": "ws",
      "security": "tls",
      "muxEnabled": true,
      "flow": "xtls-rprx-vision",
      "concurrency": 8
    },
    "inactive": {},
    "unknown": {}
  }
}`)
	ar, err := nodes.ValidateDocument(p, raw, trustedPresenceFor("vless"))
	if err != nil {
		t.Fatalf("forbidden pair must be a SEMANTIC refusal, not a syntax error: %v", err)
	}
	if !bytes.Equal(ar.Document.Raw, raw) {
		t.Fatalf("exact raw bytes must be preserved\n got: %q\nwant: %q", ar.Document.Raw, raw)
	}
	if ar.Validation != domain.ValidationInvalid || ar.Result.Status != nodes.Invalid || ar.Result.Applicable {
		t.Fatalf("want ValidationInvalid/Invalid/notApplicable, got %v/%v/%v", ar.Validation, ar.Result.Status, ar.Result.Applicable)
	}
	if !hasIssue(ar.Result, nodes.IssueDependencyIncompatible, "concurrency") {
		t.Fatalf("want dependencyIncompatible@concurrency, got %+v", ar.Result.Issues)
	}

	// Noecho: marshal the result + issues; no attacker-controlled value (server
	// host, the flow spelling, the concurrency number) may appear. Known safe
	// scalars stay in the PROJECTION (anti-overredaction), not the closed issue
	// text.
	reser, err := json.Marshal(ar.Result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, canary := range []string{"v.example", "xtls-rprx-vision", "xtls-rprx-vision-udp443"} {
		if bytes.Contains(reser, []byte(canary)) {
			t.Fatalf("closed result echoes attacker-controlled value %q: %s", canary, reser)
		}
	}

	// Safe projection keeps the ordinary allowlisted scalars (server/numerics),
	// secret presence stays a boolean, and the unsafe concurrency value is still
	// a known scalar (allowlisted) — present as a safe scalar, not a secret.
	proj, err := p.ProjectNodeFields("vless",
		map[string]any{"server": "v.example", "serverPort": int64(443), "transport": "ws", "security": "tls", "muxEnabled": true, "flow": "xtls-rprx-vision", "concurrency": int64(8)},
		trustedPresenceFor("vless"), map[string]bool{})
	if err != nil {
		t.Fatalf("projection: %v", err)
	}
	if proj.Active["server"] != "v.example" || proj.Active["concurrency"] != int64(8) {
		t.Fatalf("projection must retain known safe scalars, got active=%+v", proj.Active)
	}

	// Malformed / trailing JSON is still a syntax refusal (ErrMalformedJSON),
	// never falsely semantic-green.
	if _, err := nodes.ValidateDocument(p, []byte(`{"protocol":"vless","fields":{}} trailing`), trustedPresenceFor("vless")); err == nil {
		t.Fatalf("trailing JSON must be a syntax refusal")
	}
}

// parseProfileT parses a trusted custom profile from raw JSON, failing the test
// on any parse error (the bytes are test-authored, not attacker-controlled).
func parseProfileT(t *testing.T, raw string) *capability.Profile {
	t.Helper()
	p, err := capability.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse custom profile: %v\n%s", err, raw)
	}
	return p
}

// cloneAnyMap copies a map[string]any one level (values are scalars here).
func cloneAnyMap(a map[string]any) map[string]any {
	out := make(map[string]any, len(a))
	for k, v := range a {
		out[k] = v
	}
	return out
}
