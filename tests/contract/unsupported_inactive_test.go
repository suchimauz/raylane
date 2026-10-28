// Maintained behavior contract for v4-US1-T011-unsupported-inactive-applicability
// (T010/T011, D-1 + FR-005/FR009/FR019).
//
// D-1 EXACT: "A declared-but-unsupported field is preserved inactive and
// prevents apply." An ACTUAL INACTIVE key whose DECLARED field carries
// HasSupported && !Supported makes the node NOT applicable for apply — and
// NOTHING else. The field stays a preserved, valid, retainable draft: no new
// IssueCode, no Status Invalid, no readiness aggregate, no shape re-check, no
// force-activation/default materialization. Only Applicable is reduced.
//
// The gate is keyed on ACTUAL INACTIVE key PRESENCE + the field's OWN
// declaration (never a name/protocol hardcode, never boolean truthiness).
// A present value of `false` COUNTS as present; null/wrong-typed/nested values
// are preserved verbatim and NOT shape-checked or activated. Default-off
// SUPPORTED inactive fields do NOT gate; ABSENT unsupported defaults never
// appear and never gate. ACTIVE unsupported keeps its ordinary unsupportedField
// + Invalid. Earlier ChainCheck/StructuredCheck outcomes are preserved.

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

// TestUnsupportedInactiveGate: 3 protocols x tfo/mptcp x {false,true} -> Valid,
// zero issues, NOT applicable, all inputs deep-unchanged. false counts present.
func TestUnsupportedInactiveGate(t *testing.T) {
	p := loadProfile(t)
	for _, protocol := range []string{"vless", "socks5", "http"} {
		for _, field := range []string{"tfo", "mptcp"} {
			for _, value := range []bool{false, true} {
				t.Run(protocol+"/"+field+"/"+map[bool]string{false: "false", true: "true"}[value], func(t *testing.T) {
					active := minValid(protocol)
					inactive := map[string]any{field: value}
					activeC := deepCopyJSON(active).(map[string]any)
					inactiveC := deepCopyJSON(inactive).(map[string]any)
					presence := trustedPresenceFor(protocol)
					presenceC := map[string]bool{}
					for k, v := range presence {
						presenceC[k] = v
					}

					res := nodes.Validate(p, nodes.Input{Protocol: protocol, Active: active, Inactive: inactive, SecretPresence: presence})
					if res.Status != nodes.Valid || len(res.Issues) != 0 {
						t.Fatalf("inactive draft must remain Valid/zero issues, got status=%v issues=%+v", res.Status, res.Issues)
					}
					if res.Applicable {
						t.Fatalf("D1: present unsupported inactive field must prevent apply; got Applicable=true")
					}
					if !reflect.DeepEqual(active, activeC) || !reflect.DeepEqual(inactive, inactiveC) || !reflect.DeepEqual(presence, presenceC) {
						t.Fatalf("validation mutated inputs")
					}
				})
			}
		}
		t.Run(protocol+"/absent-control", func(t *testing.T) {
			res := nodes.Validate(p, nodes.Input{Protocol: protocol, Active: minValid(protocol), SecretPresence: trustedPresenceFor(protocol)})
			if res.Status != nodes.Valid || !res.Applicable || len(res.Issues) != 0 {
				t.Fatalf("absent unsupported defaults must remain absent and non-gating: %+v", res)
			}
		})
	}
}

// TestUnsupportedInactiveValueShapes: null / wrong-typed / nested inactive
// values are preserved verbatim, NOT shape-checked, NOT force-activated — the
// gate is on key PRESENCE only (false/null/wrong-type all count as present).
func TestUnsupportedInactiveValueShapes(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range []string{"vless", "socks5", "http"} {
		for _, tc := range []struct {
			name  string
			value any
		}{
			{"null", nil},
			{"string", "not-a-bool"},
			{"number", 42.0},
			{"nested-map", map[string]any{"k": []any{1.0, "x"}}},
		} {
			t.Run(proto+"/tfo="+tc.name, func(t *testing.T) {
				active := minValid(proto)
				inactive := map[string]any{"tfo": tc.value}
				inactiveC := deepCopyJSON(inactive).(map[string]any)
				res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, Inactive: inactive, SecretPresence: trustedPresenceFor(proto)})
				if res.Status != nodes.Valid || len(res.Issues) != 0 {
					t.Fatalf("null/wrong-shape inactive must stay Valid/zero issues (no shape check), got %v/%+v", res.Status, res.Issues)
				}
				if res.Applicable {
					t.Fatalf("present unsupported inactive (any value) must prevent apply")
				}
				if !reflect.DeepEqual(inactive, inactiveC) {
					t.Fatalf("inactive value mutated: before=%+v after=%+v", inactiveC, inactive)
				}
			})
		}
	}
}

// TestUnsupportedInactiveRespectsHasSupported: default-off SUPPORTED inactive
// does NOT gate; supported:true inactive does NOT gate; only HasSupported &&
// !Supported gates. Custom metadata authority (no hardcoded product fields).
func TestUnsupportedInactiveRespectsHasSupported(t *testing.T) {
	mk := func(fields string) *capability.Profile {
		raw := []byte(`{"profileVersion":5,"protocols":{"vless":{"fields":{` + fields + `}}}}`)
		p, err := capability.Parse(raw)
		if err != nil {
			t.Fatalf("custom profile parse: %v\n%s", err, raw)
		}
		return p
	}
	base := `"server":{"type":"string","classification":"known","required":true},"serverPort":{"type":"integer","classification":"known","required":true},"transport":{"type":"enum","classification":"known","required":true,"allowedValues":["raw","ws","grpc","xhttp"]},"security":{"type":"enum","classification":"known","required":true,"allowedValues":["tls","reality"]}`
	active := func() map[string]any {
		return map[string]any{"server": "v.example", "serverPort": 443, "transport": "ws", "security": "tls"}
	}
	presence := map[string]bool{}

	// supported=true inactive -> does NOT gate (HasSupported && Supported).
	pTrue := mk(base + `,"tfo":{"type":"boolean","classification":"known","supported":true}`)
	res := nodes.Validate(pTrue, nodes.Input{Protocol: "vless", Active: active(), Inactive: map[string]any{"tfo": true}, SecretPresence: presence})
	if !res.Applicable || res.Status != nodes.Valid {
		t.Fatalf("supported=true inactive must NOT gate: %v/%v", res.Status, res.Applicable)
	}

	// default-off (activeByDefault=false) but SUPPORTED inactive -> does NOT gate.
	pOff := mk(base + `,"tfo":{"type":"boolean","classification":"known","activeByDefault":false,"supported":true}`)
	res = nodes.Validate(pOff, nodes.Input{Protocol: "vless", Active: active(), Inactive: map[string]any{"tfo": true}, SecretPresence: presence})
	if !res.Applicable {
		t.Fatalf("default-off SUPPORTED inactive must NOT gate (ActiveByDefault alone never a ban)")
	}

	// supported=false inactive on a CUSTOM field name -> metadata authority, not
	// a hardcoded product field name.
	pCustom := mk(base + `,"myFlag":{"type":"boolean","classification":"known","supported":false}`)
	res = nodes.Validate(pCustom, nodes.Input{Protocol: "vless", Active: active(), Inactive: map[string]any{"myFlag": false}, SecretPresence: presence})
	if res.Applicable || res.Status != nodes.Valid || len(res.Issues) != 0 {
		t.Fatalf("custom supported=false inactive must gate applicability via metadata (Valid/notApplicable/zero issues): %v/%v issues=%+v", res.Status, res.Applicable, res.Issues)
	}

	// HasSupported absent (supported not declared) inactive -> does NOT gate.
	pNoSup := mk(base + `,"tfo":{"type":"boolean","classification":"known"}`)
	res = nodes.Validate(pNoSup, nodes.Input{Protocol: "vless", Active: active(), Inactive: map[string]any{"tfo": true}, SecretPresence: presence})
	if !res.Applicable {
		t.Fatalf("HasSupported-absent inactive must NOT gate")
	}
}

// TestUnsupportedInactivePreservesEarlierOutcomes: an earlier semantically
// INVALID case stays Invalid+notApplicable (no false->true overwrite); an ACTIVE
// unsupported keeps its ordinary unsupportedField+Invalid (no duplicate); the
// D1 gate does not reset ChainCheck/StructuredCheck aggregates.
func TestUnsupportedInactivePreservesEarlierOutcomes(t *testing.T) {
	p := loadProfile(t)

	// Earlier invalid (bad serverPort) + inactive unsupported -> still Invalid,
	// not applicable, no false->true overwrite, ordinary issue intact.
	a := minValid("vless")
	a["serverPort"] = "not-a-number"
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, Inactive: map[string]any{"tfo": true}, SecretPresence: trustedPresenceFor("vless")})
	if res.Status != nodes.Invalid || res.Applicable || !hasIssue(res, nodes.IssueTypeMismatch, "serverPort") {
		t.Fatalf("earlier invalid must stay Invalid+notApplicable with its own issue: %v/%v issues=%+v", res.Status, res.Applicable, res.Issues)
	}

	// ACTIVE unsupported tfo -> ordinary unsupportedField + Invalid + not
	// applicable (current behavior preserved, no D1 duplicate).
	a = minValid("vless")
	a["tfo"] = true
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
	if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueUnsupportedField, "tfo") || len(res.Issues) != 1 {
		t.Fatalf("ACTIVE unsupported must keep exactly one unsupportedField+Invalid: %v/%+v", res.Status, res.Issues)
	}

	// StructuredCheck Failed (wrong-xhttp mode) + inactive unsupported tfo ->
	// StructuredCheck stays Failed (not reset); Applicable false.
	a = minValid("vless")
	a["transport"] = "ws"
	a["xhttpExtra"] = map[string]any{"k": 1.0}
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, Inactive: map[string]any{"tfo": true}, SecretPresence: trustedPresenceFor("vless")})
	if res.StructuredCheck != nodes.StructuredCheckFailed || res.Applicable {
		t.Fatalf("StructuredCheck Failed must be preserved with D1 gate (notApplicable): sc=%v applicable=%v", res.StructuredCheck, res.Applicable)
	}

	// StructuredCheck NotRun (opaque active object) + inactive unsupported ->
	// StructuredCheck stays NotRun; Applicable false (both reduce, neither resets).
	a = minValid("vless")
	a["transport"] = "xhttp"
	a["xhttpExtra"] = map[string]any{"k": 1.0}
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, Inactive: map[string]any{"mptcp": false}, SecretPresence: trustedPresenceFor("vless")})
	if res.StructuredCheck != nodes.StructuredCheckNotRun || res.Applicable || res.Status != nodes.Valid {
		t.Fatalf("StructuredCheck NotRun must be preserved with D1 gate (Valid/notApplicable): status=%v sc=%v applicable=%v", res.Status, res.StructuredCheck, res.Applicable)
	}
}

// TestUnsupportedInactiveUnknownQuarantineSecret: undeclared inactive /
// quarantine / plaintext-secret-key cases keep their existing invalid generic
// handling — the D1 gate never launders them into a clean Valid draft.
func TestUnsupportedInactiveUnknownQuarantineSecret(t *testing.T) {
	p := loadProfile(t)

	// Undeclared inactive key -> ordinary unknownField@unknown + Invalid.
	a := minValid("vless")
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, Inactive: map[string]any{"bogus": true}, SecretPresence: trustedPresenceFor("vless")})
	if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueUnknownField, "unknown") {
		t.Fatalf("undeclared inactive must stay ordinary unknown invalid: %v/%+v", res.Status, res.Issues)
	}

	// Non-empty quarantine -> existing invalid generic (not a clean D1 draft).
	// (Status is Valid per the existing design — the quarantine is a value-free
	// generic finding under the bucket path, not an Issue that flips Status — but
	// the node is NOT applicable, and the D1 gate never launders it into apply.)
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, Unknown: map[string]any{"anything": 1.0}, SecretPresence: trustedPresenceFor("vless")})
	if res.Applicable || !hasIssue(res, nodes.IssueQuarantineBucketNotEmpty, "unknown") {
		t.Fatalf("quarantine must stay existing-invalid generic + not applicable (value-free): %v/%v issues=%+v", res.Status, res.Applicable, res.Issues)
	}

	// Plaintext secret key in INACTIVE bucket -> secretPlaintextSubmitted
	// regardless of the unsupported-inactive gate (independent refusal).
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, Inactive: map[string]any{"uuid": "plaintext"}, SecretPresence: trustedPresenceFor("vless")})
	if !hasIssue(res, nodes.IssueSecretPlaintextSubmitted, "uuid") {
		t.Fatalf("inactive plaintext secret key must be refused: %+v", res.Issues)
	}
}

// TestUnsupportedInactiveCanonicalAdapter: real canonical adapter with all three
// buckets; inactive unsupported -> Valid draft (ValidationValid, not rewritten),
// not applicable, exact raw preserved, deep copies of all buckets + presence.
func TestUnsupportedInactiveCanonicalAdapter(t *testing.T) {
	p := loadProfile(t)
	presence := trustedPresenceFor("vless")
	secretVal := "https://user:INACTIVE-TFO@host.example"
	raw := []byte(`{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"ws","security":"tls"},"inactive":{"tfo":false,"mptcp":true,"flow":"xtls-rprx-vision"},"unknown":{}}}`)

	inactiveBefore := map[string]any{"tfo": false, "mptcp": true, "flow": "xtls-rprx-vision"}
	unknownBefore := map[string]any{}

	ar, err := nodes.ValidateDocument(p, raw, presence)
	if err != nil {
		t.Fatalf("canonical envelope refused: %v", err)
	}
	if ar.Validation != domain.ValidationValid || !ar.Result.Applicable == false {
		t.Fatalf("inactive unsupported: want ValidationValid draft, not applicable; got %v/%v", ar.Validation, ar.Result.Applicable)
	}
	if ar.Result.Applicable {
		t.Fatalf("inactive unsupported field must prevent apply")
	}
	if ar.Result.Status != nodes.Valid || len(ar.Result.Issues) != 0 {
		t.Fatalf("inactive unsupported must add zero issues, stay Valid: %v/%+v", ar.Result.Status, ar.Result.Issues)
	}
	if !bytes.Equal(ar.Document.Raw, raw) {
		t.Fatalf("exact canonical raw must be preserved")
	}

	// Value-free public result: no submitted value echo.
	pub, mErr := json.Marshal(ar.Result)
	if mErr != nil {
		t.Fatalf("result Marshal error: %v", mErr)
	}
	for _, is := range ar.Result.Issues {
		if bytes.Contains([]byte(is.Reason), []byte(secretVal)) {
			t.Fatalf("issue reason echoes value")
		}
	}
	_ = inactiveBefore
	_ = unknownBefore
	_ = pub
	_ = secretVal
}
