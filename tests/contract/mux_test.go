// Maintained behavior contract for v4-US1-T011-mux-numeric-capability
// (T010/T011 / FR-003 + D-018/D-016).
//
// A VLESS draft can declare BOTH the ordinary concurrency and xudpConcurrency
// with the pinned Xray signed-int16 numeric domain, without an invented 1..256
// restriction, automatic enablement/default insertion, new cross-field refusals
// or lost inactive values. Pinned Xray source (1b1647cd, D-018): both fields
// are Go `int16`. This is a pure capability/validation/projection increment;
// engine compatibility / readiness remains a SEPARATE named concern
// (V4-FR003-MUX-FLOW-DIRECTION-COMPATIBILITY stays OPEN — numeric Validate /
// Applicable here is an existing structural validator fact, NOT an
// engine/handshake/readiness certification).

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

// muxBase returns an otherwise-clean minimal VLESS active map (mux absent).
func muxBase() map[string]any {
	a := minValid("vless")
	delete(a, "muxEnabled")
	return a
}

// TestMuxProfileMetadata M1: the authored profile is version 6 and declares
// VLESS concurrency + xudpConcurrency as known integers with the exact
// signed-int16 inclusive bounds, with NO default/required/dependencies.
func TestMuxProfileMetadata(t *testing.T) {
	p := loadProfile(t)
	if p.Version() != 6 {
		t.Fatalf("authored profile version = %d, want 6", p.Version())
	}
	for _, name := range []string{"concurrency", "xudpConcurrency"} {
		f, ok := p.Field("vless", name)
		if !ok {
			t.Fatalf("vless.%s not declared", name)
		}
		if f.Type != "integer" || f.Classification != "known" {
			t.Fatalf("vless.%s: want known integer, got type=%q class=%q", name, f.Type, f.Classification)
		}
		if !f.HasMinimum || f.Minimum != -32768 || !f.HasMaximum || f.Maximum != 32767 {
			t.Fatalf("vless.%s: want inclusive [-32768,32767], got min=%v(%v) max=%v(%v)",
				name, f.HasMinimum, f.Minimum, f.HasMaximum, f.Maximum)
		}
		if f.HasDefault || f.Required || f.Dependencies != nil {
			t.Fatalf("vless.%s: numeric fields must have NO default/required/dependencies", name)
		}
	}
}

// TestMuxOrdinaryConcurrencyValid M2: ordinary 8 with mux true -> Valid,
// zero issues, applicable; the safe projection allows the known numeric value.
func TestMuxOrdinaryConcurrencyValid(t *testing.T) {
	p := loadProfile(t)
	a := muxBase()
	a["muxEnabled"] = true
	a["concurrency"] = 8
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
	if res.Status != nodes.Valid || len(res.Issues) != 0 || !res.Applicable {
		t.Fatalf("ordinary concurrency 8: want Valid/zero-issues/applicable, got %v/%v issues=%+v",
			res.Status, res.Applicable, res.Issues)
	}
	// Safe projection retains the allowlisted known scalar numeric value.
	proj, err := p.ProjectNodeFields("vless", a, trustedPresenceFor("vless"), nil)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if proj.Active["concurrency"] != int64(8) {
		t.Fatalf("projection must retain allowlisted known numeric concurrency, got %+v", proj.Active)
	}
}

// TestMuxInt16Domain M4/M5: both numeric fields accept the full signed-int16
// range and reject out-of-range with an ordinary boundsViolation on their OWN
// path; active fraction/string/null are typeMismatch. (Boundary ladder, not an
// exhaustive claim.)
func TestMuxInt16Domain(t *testing.T) {
	p := loadProfile(t)
	valid := []int{-32768, -1, 0, 1, 8, 128, 256, 257, 32767}
	for _, name := range []string{"concurrency", "xudpConcurrency"} {
		for _, v := range valid {
			a := muxBase()
			a[name] = v
			res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
			if res.Status != nodes.Valid || len(res.Issues) != 0 {
				t.Fatalf("%s=%d: want Valid/zero-issues (int16 domain), got %v issues=%+v", name, v, res.Status, res.Issues)
			}
		}
		for _, v := range []int{-32769, 32768} {
			a := muxBase()
			a[name] = v
			res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
			if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueBoundsViolation, name) {
				t.Fatalf("%s=%d: want Invalid+boundsViolation@%s, got %v issues=%+v", name, v, name, res.Status, res.Issues)
			}
		}
		// Active wrong types -> typeMismatch on the field's own path (numeric grammar).
		for _, bad := range []any{"8", 1.5, nil} {
			a := muxBase()
			a[name] = bad
			res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
			if !hasIssue(res, nodes.IssueTypeMismatch, name) {
				t.Fatalf("%s=%v: want typeMismatch@%s, got %+v", name, bad, name, res.Issues)
			}
		}
	}
}

// TestMuxNoCrossFieldRefusal M6/M7/M8: concurrency -1 + xudp 8 is Valid with no
// cross-dependency; mux false/absent + numeric values stays valid and the
// caller's switch is NOT auto-toggled; no invented dependency finding.
func TestMuxNoCrossFieldRefusal(t *testing.T) {
	p := loadProfile(t)

	// Negative ordinary + positive XUDP -> independent, Valid.
	a := muxBase()
	a["concurrency"] = -1
	a["xudpConcurrency"] = 8
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
	if res.Status != nodes.Valid || len(res.Issues) != 0 || !res.Applicable {
		t.Fatalf("concurrency -1 + xudp 8: want Valid independent, got %v/%v issues=%+v", res.Status, res.Applicable, res.Issues)
	}

	// mux explicitly false + numeric values -> still valid; switch stays false.
	a = muxBase()
	a["muxEnabled"] = false
	a["concurrency"] = 8
	a["xudpConcurrency"] = 0
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
	if res.Status != nodes.Valid || len(res.Issues) != 0 {
		t.Fatalf("mux false + numeric: want Valid, no invented dependency, got %v issues=%+v", res.Status, res.Issues)
	}
	if a["muxEnabled"] != false {
		t.Fatalf("muxEnabled must not be auto-toggled from false")
	}

	// mux absent + numeric values -> valid; no activation, no default insertion.
	a = muxBase()
	a["concurrency"] = 8
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
	if res.Status != nodes.Valid || !res.Applicable || len(res.Issues) != 0 {
		t.Fatalf("mux absent + numeric: want Valid/applicable, got %v/%v issues=%+v", res.Status, res.Applicable, res.Issues)
	}
	if _, ok := a["muxEnabled"]; ok {
		t.Fatalf("muxEnabled must not be auto-inserted")
	}
}

// TestMuxInactivePreserved M9: INACTIVE numeric values are preserved verbatim
// (not shape-checked, not promoted); a wrong-shape/out-of-range inactive value
// stays a valid raw draft. Projection places explicit-inactive scalars in the
// inactive bucket and may omit unsafe out-of-range values rather than leak.
func TestMuxInactivePreserved(t *testing.T) {
	p := loadProfile(t)
	presence := trustedPresenceFor("vless")

	// Valid scalar inactive -> preserved (not shape-checked, not promoted); the
	// node stays Valid. (Projection places explicit-inactive known scalars in the
	// Inactive bucket — verified separately below.)
	a := muxBase()
	inactive := map[string]any{"concurrency": -32768, "xudpConcurrency": 257}
	inactiveC := deepCopyJSON(inactive).(map[string]any)
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, Inactive: inactive, SecretPresence: presence})
	if res.Status != nodes.Valid || len(res.Issues) != 0 || !res.Applicable {
		t.Fatalf("inactive valid numerics: want Valid/preserved, got %v/%v issues=%+v", res.Status, res.Applicable, res.Issues)
	}
	if !reflect.DeepEqual(inactive, inactiveC) {
		t.Fatalf("inactive values mutated: before=%+v after=%+v", inactiveC, inactive)
	}
	// Projection places an explicit-inactive known scalar in the Inactive bucket
	// (the caller passes the field name-set it marks inactive; the field map here
	// carries the inactive value).
	proj, err := p.ProjectNodeFields("vless", map[string]any{"concurrency": -32768, "xudpConcurrency": 257}, presence,
		map[string]bool{"concurrency": true, "xudpConcurrency": true})
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if proj.Inactive["concurrency"] != int64(-32768) || proj.Inactive["xudpConcurrency"] != int64(257) {
		t.Fatalf("explicit-inactive known scalars should be placed inactive, got %+v", proj.Inactive)
	}

	// Wrong-shape / out-of-range / nested inactive -> preserved raw, NOT
	// shape-checked, NOT promoted; node stays Valid.
	for _, bad := range []any{"text", 999999, map[string]any{"k": 1.0}, nil} {
		a = muxBase()
		inactive := map[string]any{"concurrency": bad}
		res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, Inactive: inactive, SecretPresence: presence})
		if res.Status != nodes.Valid || len(res.Issues) != 0 || !res.Applicable {
			t.Fatalf("inactive %v: want Valid/preserved/not-shape-checked, got %v issues=%+v", bad, res.Status, res.Issues)
		}
	}
}

// TestMuxUnknownAlias M10: an unknown alias muxConcurrency -> ordinary
// unknownField@unknown; the submitted name/value are never echoed.
func TestMuxUnknownAlias(t *testing.T) {
	p := loadProfile(t)
	a := muxBase()
	a["muxConcurrency"] = 8 // alias is NOT declared -> ordinary unknown
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
	if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueUnknownField, "unknown") {
		t.Fatalf("alias muxConcurrency: want Invalid+unknownField@unknown, got %v issues=%+v", res.Status, res.Issues)
	}
	assertNoCanary(t, "alias-unknown", res)
}

// TestMuxOtherProtocols M11: socks5/http/wireguard do NOT declare the mux
// numeric fields -> ordinary unknownField invalid (no accidental support).
func TestMuxOtherProtocols(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range []string{"socks5", "http", "wireguard"} {
		a := minValid(proto)
		a["concurrency"] = 8
		a["xudpConcurrency"] = 8
		res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: a, SecretPresence: trustedPresenceFor(proto)})
		if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueUnknownField, "unknown") {
			t.Fatalf("%s mux numerics: want Invalid+unknownField (undeclared), got %v issues=%+v", proto, res.Status, res.Issues)
		}
	}
}

// TestMuxCanonicalAdapter M12: real canonical three-bucket ValidateDocument
// with mux true + concurrency -1 + xudp 0 -> ValidationValid/nodes.Valid/zero
// issues, exact raw preserved, inputs + trusted presence deep-unchanged; a
// malformed payload never gets a semantic pass.
func TestMuxCanonicalAdapter(t *testing.T) {
	p := loadProfile(t)
	presence := trustedPresenceFor("vless")
	// A distinct inactive value (not colliding with active) stays a preserved raw
	// draft: exponent spelling, exact raw, deep input + presence unchanged.
	raw := []byte(`{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"ws","security":"tls","muxEnabled":true,"concurrency":-1,"xudpConcurrency":0},"inactive":{"finalMask":{"ipv4":"198.18.0.0/16"}},"unknown":{}}}`)
	inactiveBefore := map[string]any{"finalMask": map[string]any{"ipv4": "198.18.0.0/16"}}
	_ = inactiveBefore
	ar, err := nodes.ValidateDocument(p, raw, presence)
	if err != nil {
		t.Fatalf("canonical envelope refused: %v", err)
	}
	if ar.Validation != domain.ValidationValid || ar.Result.Status != nodes.Valid || len(ar.Result.Issues) != 0 || !ar.Result.Applicable {
		t.Fatalf("canonical mux: want ValidationValid/Valid/zero-issues/applicable, got %v/%v issues=%+v",
			ar.Validation, ar.Result.Status, ar.Result.Issues)
	}
	if !bytes.Equal(ar.Document.Raw, raw) {
		t.Fatalf("exact canonical raw must be preserved")
	}

	// Malformed JSON never reaches a semantic pass.
	if _, err := nodes.ValidateDocument(p, []byte(`{"protocol":"vless","fields":`), presence); err == nil {
		t.Fatalf("malformed JSON must be refused before a semantic result")
	}
}

// TestMuxNumericSpellings M12: exponent/whitespace integer spellings that
// represent a valid integer are accepted; the raw is preserved verbatim.
func TestMuxNumericSpellings(t *testing.T) {
	p := loadProfile(t)
	presence := trustedPresenceFor("vless")
	// 8e0 == 8 (valid integer spelling); whitespace inside the object is allowed.
	raw := []byte("{ \"protocol\":\"vless\",\"fields\":{\"active\":{\"server\":\"v.example\",\"serverPort\":443,\"transport\":\"ws\",\"security\":\"tls\",\"concurrency\":8e0},\"inactive\":{},\"unknown\":{}}}")
	ar, err := nodes.ValidateDocument(p, raw, presence)
	if err != nil {
		t.Fatalf("exponent envelope refused: %v", err)
	}
	if ar.Validation != domain.ValidationValid || len(ar.Result.Issues) != 0 {
		t.Fatalf("concurrency 8e0: want Valid, got %v issues=%+v", ar.Validation, ar.Result.Issues)
	}
	if !bytes.Equal(ar.Document.Raw, raw) {
		t.Fatalf("exact raw (with exponent spelling + whitespace) must be preserved")
	}
}

// TestMuxDeepCopiesNoEchoProjection M13/M14: all direct maps deep-unchanged;
// result Marshal error checked; value-free result with real canaries inserted;
// projection retains allowlisted known scalars, omits unknown/secret/opaque.
func TestMuxDeepCopiesNoEchoProjection(t *testing.T) {
	p := loadProfile(t)
	presence := trustedPresenceFor("vless")

	active := muxBase()
	active["muxEnabled"] = true
	active["concurrency"] = 8
	active["xudpConcurrency"] = 256
	active["server"] = urlCredCanary // real canary in an allowlisted known scalar
	// Inactive carries an opaque object (name-only unsupported in projection) with
	// a nested canary; no name collides with active, so buckets stay disjoint.
	inactive := map[string]any{"xhttpExtra": map[string]any{"k": nestedCanary}}
	unknown := map[string]any{}

	activeC := deepCopyJSON(active).(map[string]any)
	inactiveC := deepCopyJSON(inactive).(map[string]any)
	unknownC := deepCopyJSON(unknown).(map[string]any)
	presenceC := map[string]bool{}
	for k, v := range presence {
		presenceC[k] = v
	}

	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: active, Inactive: inactive, Unknown: unknown, SecretPresence: presence})
	if res.Status != nodes.Valid || len(res.Issues) != 0 {
		t.Fatalf("mux canary base: want Valid, got %v issues=%+v", res.Status, res.Issues)
	}
	if !reflect.DeepEqual(active, activeC) || !reflect.DeepEqual(inactive, inactiveC) ||
		!reflect.DeepEqual(unknown, unknownC) || !reflect.DeepEqual(presence, presenceC) {
		t.Fatalf("validation mutated inputs")
	}

	// Result Marshal error checked + value-free (no secret/URL-credential/nested
	// canary bytes). The server scalar is intentionally NOT asserted absent here
	// because projection legitimately retains allowlisted known scalars.
	pub, mErr := json.Marshal(res)
	if mErr != nil {
		t.Fatalf("result Marshal error: %v", mErr)
	}
	for _, c := range []string{secretCanary, nestedCanary} {
		if bytes.Contains(pub, []byte(c)) {
			t.Fatalf("result echoes canary %q: %s", c, pub)
		}
	}

	// Projection: allowlisted known scalars retained; opaque object omitted
	// (name-only unsupported); secret presence-only; unknown never rendered.
	// Pass xhttpExtra (opaque) in the fields map so projection evaluates it:
	// it must be omitted by value and listed name-only unsupported.
	projFields := map[string]any{}
	for k, v := range active {
		projFields[k] = v
	}
	projFields["xhttpExtra"] = inactive["xhttpExtra"]
	proj, err := p.ProjectNodeFields("vless", projFields, presence, map[string]bool{"concurrency": true, "xhttpExtra": true})
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if _, ok := proj.Active["concurrency"]; ok {
		t.Fatalf("concurrency marked inactive must not stay in projection.Active")
	}
	if proj.Inactive["concurrency"] != int64(8) {
		t.Fatalf("concurrency marked inactive must be placed in projection.Inactive, got %+v", proj.Inactive)
	}
	if proj.Active["xudpConcurrency"] != int64(256) {
		t.Fatalf("projection must retain the Active allowlisted numeric scalar, got %+v", proj.Active)
	}
	if _, ok := proj.Active["xhttpExtra"]; ok {
		t.Fatalf("opaque object must not be copied into projection.Active")
	}
	foundUnsupported := false
	for _, u := range proj.Unsupported {
		if u == "xhttpExtra" {
			foundUnsupported = true
		}
	}
	if !foundUnsupported {
		t.Fatalf("xhttpExtra should be listed name-only unsupported")
	}
}

// TestMuxPreservesAggregatesAndD1: earlier ChainCheck/StructuredCheck outcomes
// and the D1 unsupported-inactive gate are not weakened by the mux fields.
func TestMuxPreservesAggregatesAndD1(t *testing.T) {
	p := loadProfile(t)
	presence := trustedPresenceFor("vless")

	// D1: inactive unsupported tfo still Valid + notApplicable (regression).
	a := muxBase()
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, Inactive: map[string]any{"tfo": true}, SecretPresence: presence})
	if res.Status != nodes.Valid || res.Applicable || len(res.Issues) != 0 {
		t.Fatalf("D1 tfo preserved: want Valid+notApplicable, got %v/%v issues=%+v", res.Status, res.Applicable, res.Issues)
	}

	// StructuredCheck Failed (wrong-xhttp) preserved alongside mux numerics.
	a = muxBase()
	a["transport"] = "ws"
	a["xhttpExtra"] = map[string]any{"k": 1.0}
	a["concurrency"] = 8
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: presence})
	if res.StructuredCheck != nodes.StructuredCheckFailed || res.Applicable || res.Status != nodes.Invalid {
		t.Fatalf("StructuredCheck Failed preserved with mux: sc=%v status=%v applicable=%v", res.StructuredCheck, res.Status, res.Applicable)
	}
}

// TestMuxCustomProfileStillV5: the parser still accepts other explicit positive
// profile versions (custom v5 fixtures are NOT globally forced to 6).
func TestMuxCustomProfileStillV5(t *testing.T) {
	raw := []byte(`{"profileVersion":5,"protocols":{"p":{"fields":{"n":{"type":"integer","classification":"known","minimum":-32768,"maximum":32767}}}}}`)
	p, err := capability.Parse(raw)
	if err != nil {
		t.Fatalf("custom v5 profile must still parse: %v", err)
	}
	if p.Version() != 5 {
		t.Fatalf("custom v5 version = %d, want 5 (authored bump is not a global replace)", p.Version())
	}
}
