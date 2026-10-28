// Package contract_test is the table-driven behavior contract for the
// T011-A node validation seam. It executes the REAL capability authority and
// the REAL nodes.Validate/ValidateDocument against the authored profile —
// not fixture linting. RED→GREEN: these cases fail before the seam exists and
// pass after.
package contract_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// secretCanary / unknownCanary / urlCredCanary are canaries that must NEVER
// appear in any serialized result, projection, issue, diagnostic or log.
const (
	secretCanary  = "CANARY-SECRET-VALUE-5d4c"
	unknownCanary = "CANARY-UNKNOWN-FIELD-88"
	nestedCanary  = "CANARY-NESTED-LEAF-71"
	urlCredCanary = "https://user:CANARY-URL-PASS@host.example"
	// validWGHexKey is a valid 32-byte WireGuard public key (64 hex chars) used by
	// positive validation fixtures. It is NOT a canary and may appear in fixtures.
	validWGHexKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)

func loadProfile(t *testing.T) *capability.Profile {
	t.Helper()
	raw, err := os.ReadFile("../../contracts/capability-profile.json")
	if err != nil {
		t.Fatalf("read authored profile: %v", err)
	}
	p, err := capability.Parse(raw)
	if err != nil {
		t.Fatalf("Parse(authored): %v", err)
	}
	if p.Version() != 6 {
		t.Fatalf("profile version = %d, want 6", p.Version())
	}
	return p
}

// minValid returns the minimal VALID active field map for each protocol, with
// the required secrets satisfied by trusted presence (not values).
func minValid(protocol string) map[string]any {
	switch protocol {
	case "vless":
		return map[string]any{
			"server": "v.example", "serverPort": float64(443),
			"transport": "ws", "security": "tls",
		}
	case "socks5":
		return map[string]any{"server": "s.example", "serverPort": float64(1080)}
	case "http":
		return map[string]any{"server": "h.example", "serverPort": float64(8443)}
	case "wireguard":
		return map[string]any{
			"endpoint": "w.example", "endpointPort": float64(51820),
			"publicKey": validWGHexKey, "localAddresses": []any{"10.0.0.2/32"},
		}
	}
	return nil
}

// trustedPresenceFor returns the trusted sealed-secret presence a valid node of
// this protocol needs (its required secrets present, by store state not value).
func trustedPresenceFor(protocol string) map[string]bool {
	switch protocol {
	case "vless":
		return map[string]bool{"uuid": true}
	case "wireguard":
		return map[string]bool{"privateKey": true}
	}
	return map[string]bool{}
}

func hasIssue(res nodes.Result, code nodes.IssueCode, field string) bool {
	for _, is := range res.Issues {
		if is.Code == code && is.Field == field {
			return true
		}
	}
	return false
}

// serializeFailsIfCanary serializes the result and fails if any canary leaked.
func assertNoCanary(t *testing.T, label string, v any) {
	t.Helper()
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(v); err != nil {
		t.Fatalf("%s: encode: %v", label, err)
	}
	for _, canary := range []string{secretCanary, unknownCanary, nestedCanary, urlCredCanary} {
		if bytes.Contains(buf.Bytes(), []byte(canary)) {
			t.Fatalf("%s: canary %q leaked into serialized result: %s", label, canary, buf.String())
		}
	}
}

// TestMinimalValidFourProtocols: the canonical minimal case for EACH of the
// four selected protocols actually calls Validate and is Valid + Applicable.
func TestMinimalValidFourProtocols(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range []string{"vless", "socks5", "http", "wireguard"} {
		t.Run(proto, func(t *testing.T) {
			res := nodes.Validate(p, nodes.Input{
				Protocol:       proto,
				Active:         minValid(proto),
				SecretPresence: trustedPresenceFor(proto),
			})
			if res.Status != nodes.Valid {
				t.Fatalf("minimal valid %s got issues: %+v", proto, res.Issues)
			}
			if !res.Applicable {
				t.Fatalf("minimal valid %s not applicable", proto)
			}
			assertNoCanary(t, proto+" result", res)
		})
	}
}

// TestRequiredMissing: dropping a required KNOWN field invalidates the node.
func TestRequiredMissing(t *testing.T) {
	p := loadProfile(t)
	cases := []struct{ proto, drop string }{
		{"vless", "server"},
		{"vless", "security"},
		{"socks5", "serverPort"},
		{"http", "server"},
		{"wireguard", "publicKey"},
		{"wireguard", "localAddresses"},
	}
	for _, c := range cases {
		t.Run(c.proto+"/"+c.drop, func(t *testing.T) {
			active := minValid(c.proto)
			delete(active, c.drop)
			res := nodes.Validate(p, nodes.Input{Protocol: c.proto, Active: active, SecretPresence: trustedPresenceFor(c.proto)})
			if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueRequiredMissing, c.drop) {
				t.Fatalf("want requiredMissing on %s, got %+v", c.drop, res.Issues)
			}
			if res.Applicable {
				t.Fatalf("invalid node must not be applicable")
			}
		})
	}
}

// TestRequiredSecretMissing: a required secret with NO trusted sealed presence
// is invalid — the client cannot assert presence with a value or a bool.
func TestRequiredSecretMissing(t *testing.T) {
	p := loadProfile(t)
	res := nodes.Validate(p, nodes.Input{
		Protocol: "vless",
		Active:   minValid("vless"),
		// uuid present in active as a plaintext value, but NO trusted presence:
		// a submitted plaintext secret is not accepted as presence.
		SecretPresence: map[string]bool{"uuid": false},
	})
	if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueRequiredSecretMissing, "uuid") {
		t.Fatalf("want requiredSecretMissing on uuid, got %+v", res.Issues)
	}
	// Even if the client smuggles the secret value into active, it must not
	// satisfy presence and must not leak.
	res2 := nodes.Validate(p, nodes.Input{
		Protocol:       "vless",
		Active:         map[string]any{"server": "v", "serverPort": float64(1), "transport": "raw", "security": "tls", "uuid": secretCanary},
		SecretPresence: map[string]bool{"uuid": false},
	})
	if !hasIssue(res2, nodes.IssueRequiredSecretMissing, "uuid") {
		t.Fatalf("plaintext secret value must not satisfy presence: %+v", res2.Issues)
	}
	assertNoCanary(t, "secret-smuggle", res2)
}

// TestUnknownProtocolFailsClosed: an undeclared protocol is invalid AND not
// applicable — never "pass everything".
func TestUnknownProtocolFailsClosed(t *testing.T) {
	p := loadProfile(t)
	res := nodes.Validate(p, nodes.Input{Protocol: "shadowsocks", Active: map[string]any{"server": "x"}})
	if res.Status != nodes.Invalid || res.Applicable {
		t.Fatalf("unknown protocol must be invalid+inapplicable: %+v", res)
	}
}

// TestUnknownFieldBucketed: an attacker-controlled unknown name is reported
// under the generic bucket path, never echoing the raw name or value.
func TestUnknownFieldBucketed(t *testing.T) {
	p := loadProfile(t)
	active := minValid("socks5")
	active[unknownCanary] = urlCredCanary // attacker-controlled name AND value
	res := nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: active})
	if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueUnknownField, "unknown") {
		t.Fatalf("want unknownField bucketed, got %+v", res.Issues)
	}
	for _, u := range res.Unknown {
		if u != "unknown" {
			t.Fatalf("unknown bucket must be the generic path, got %q", u)
		}
	}
	assertNoCanary(t, "unknown-field", res)
}

// TestTypeEnumBounds: wrong type, enum violation and integer bounds fail with
// static field diagnostics and original bytes unchanged (adapter-level).
func TestTypeEnumBounds(t *testing.T) {
	p := loadProfile(t)
	// serverPort wrong type
	res := nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{"server": "s", "serverPort": "not-a-number"}})
	if !hasIssue(res, nodes.IssueTypeMismatch, "serverPort") {
		t.Fatalf("want typeMismatch on serverPort, got %+v", res.Issues)
	}
	// vless security enum: 'none' removed in v2 → enumViolation; tls/reality valid.
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: map[string]any{"server": "v", "serverPort": float64(1), "transport": "raw", "security": "none"}, SecretPresence: map[string]bool{"uuid": true}})
	if !hasIssue(res, nodes.IssueEnumViolation, "security") {
		t.Fatalf("vless security 'none' must be enumViolation in v2, got %+v", res.Issues)
	}
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: map[string]any{"server": "v", "serverPort": float64(1), "transport": "raw", "security": "reality"}, SecretPresence: map[string]bool{"uuid": true}})
	if res.Status != nodes.Valid {
		t.Fatalf("vless security 'reality' must be valid, got %+v", res.Issues)
	}
	// integer bounds: serverPort out of range
	res = nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: map[string]any{"server": "s", "serverPort": float64(70000)}})
	if !hasIssue(res, nodes.IssueBoundsViolation, "serverPort") {
		t.Fatalf("want boundsViolation on serverPort, got %+v", res.Issues)
	}
}

// TestWireGuardReserved: omitted / empty / 3-byte reserved are valid; 1/2/4
// elements, out-of-range bytes, non-integer and nested values are invalid.
func TestWireGuardReserved(t *testing.T) {
	p := loadProfile(t)
	base := func() map[string]any { return minValid("wireguard") }
	validCases := map[string]any{
		"omitted": nil, // not set
		"empty":   []any{},
		"3bytes":  []any{float64(1), float64(2), float64(255)},
	}
	for name, val := range validCases {
		t.Run("valid/"+name, func(t *testing.T) {
			active := base()
			if val != nil {
				active["reserved"] = val
			}
			res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: active, SecretPresence: trustedPresenceFor("wireguard")})
			if res.Status != nodes.Valid {
				t.Fatalf("reserved %s must be valid, got %+v", name, res.Issues)
			}
		})
	}
	invalidCases := map[string]struct {
		val  any
		code nodes.IssueCode
	}{
		"one-element":       {[]any{float64(1)}, nodes.IssueBoundsViolation},
		"two-element":       {[]any{float64(1), float64(2)}, nodes.IssueBoundsViolation},
		"four-element":      {[]any{float64(1), float64(2), float64(3), float64(4)}, nodes.IssueBoundsViolation},
		"byte-out-range":    {[]any{float64(1), float64(2), float64(256)}, nodes.IssueReservedByteRange},
		"byte-negative":     {[]any{float64(1), float64(2), float64(-1)}, nodes.IssueReservedByteRange},
		"non-integer":       {[]any{float64(1), "x", float64(2)}, nodes.IssueArrayItemViolation},
		"nested-array":      {[]any{float64(1), []any{float64(2)}, float64(3)}, nodes.IssueArrayItemViolation},
		"nested-object":     {[]any{float64(1), map[string]any{"a": float64(1)}, float64(3)}, nodes.IssueArrayItemViolation},
		"wrong-type-scalar": {"000000", nodes.IssueTypeMismatch},
	}
	for name, c := range invalidCases {
		t.Run("invalid/"+name, func(t *testing.T) {
			active := base()
			active["reserved"] = c.val
			res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: active, SecretPresence: trustedPresenceFor("wireguard")})
			if !hasIssue(res, c.code, "reserved") {
				t.Fatalf("reserved %s want code %s, got %+v", name, c.code, res.Issues)
			}
			if res.Applicable {
				t.Fatalf("invalid reserved must make node inapplicable")
			}
		})
	}
}

// TestDependenciesEnforced: mldsa65Seed requires security — present without
// security is a dependency finding; the chain reflects authored metadata.
func TestDependenciesEnforced(t *testing.T) {
	p := loadProfile(t)
	// mldsa65Seed present in active but security absent → dependencyMissing.
	active := map[string]any{
		"server": "v", "serverPort": float64(1), "transport": "raw",
		// security omitted
	}
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: active, SecretPresence: map[string]bool{"uuid": true, "mldsa65Seed": true}})
	if !hasIssue(res, nodes.IssueDependencyMissing, "mldsa65Seed") {
		t.Fatalf("want dependencyMissing on mldsa65Seed, got %+v", res.Issues)
	}
	// With security present, the dependency is satisfied.
	active["security"] = "tls"
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: active, SecretPresence: map[string]bool{"uuid": true, "mldsa65Seed": true}})
	if hasIssue(res, nodes.IssueDependencyMissing, "mldsa65Seed") {
		t.Fatalf("dependency must be satisfied when security present: %+v", res.Issues)
	}
}

// TestInactivePreserved: an explicitly-inactive declared field retains its
// value and does not by itself invalidate the active node; reactivation keeps
// the value.
func TestInactivePreserved(t *testing.T) {
	p := loadProfile(t)
	// tfo declared, stored inactive with a value; active node stays valid.
	res := nodes.Validate(p, nodes.Input{
		Protocol:       "vless",
		Active:         minValid("vless"),
		Inactive:       map[string]any{"tfo": true, "muxEnabled": false},
		SecretPresence: trustedPresenceFor("vless"),
	})
	if res.Status != nodes.Valid {
		t.Fatalf("inactive stored values must not invalidate active node: %+v", res.Issues)
	}
}

// TestDefaultAbsenceNotMaterialized: an absent field with an authored default
// stays ABSENT — validation never rewrites the submitted map or inserts the
// default. We prove this by validating an input missing mtu and confirming the
// input map is unchanged (no mtu key inserted).
func TestDefaultAbsenceNotMaterialized(t *testing.T) {
	p := loadProfile(t)
	active := minValid("wireguard")
	before, _ := json.Marshal(active)
	res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: active, SecretPresence: trustedPresenceFor("wireguard")})
	if res.Status != nodes.Valid {
		t.Fatalf("wireguard minimal valid: %+v", res.Issues)
	}
	after, _ := json.Marshal(active)
	if !bytes.Equal(before, after) {
		t.Fatalf("Validate mutated the submitted map: before=%s after=%s", before, after)
	}
	if _, ok := active["mtu"]; ok {
		t.Fatalf("Validate inserted an absent defaulted field (mtu) — defaults must not materialize")
	}
}

// TestAdapterMalformedJSON: malformed JSON → domain.ErrMalformedJSON, no
// Document, no replacement.
func TestAdapterMalformedJSON(t *testing.T) {
	p := loadProfile(t)
	_, err := nodes.ValidateDocument(p, []byte("{not json"), nil)
	if !errors.Is(err, domain.ErrMalformedJSON) {
		t.Fatalf("want ErrMalformedJSON, got %v", err)
	}
}

// TestAdapterPreservesOriginalBytes: a semantically invalid but syntactically
// valid envelope keeps EXACT original bytes, marks ValidationInvalid, and does
// not mutate or default anything.
func TestAdapterPreservesOriginalBytes(t *testing.T) {
	p := loadProfile(t)
	original := []byte(`{"protocol":"socks5","fields":{"active":{"server":"s.example","serverPort":70000},"inactive":{},"unknown":{}}}`)
	got, err := nodes.ValidateDocument(p, original, nil)
	if err != nil {
		t.Fatalf("envelope should decode (semantic invalid, not parse error): %v", err)
	}
	if got.Validation != domain.ValidationInvalid {
		t.Fatalf("want ValidationInvalid, got %v", got.Validation)
	}
	if !bytes.Equal(got.Document.Raw, original) {
		t.Fatalf("original bytes not preserved:\n got=%s\nwant=%s", got.Document.Raw, original)
	}
	if !hasIssue(got.Result, nodes.IssueBoundsViolation, "serverPort") {
		t.Fatalf("want boundsViolation on serverPort, got %+v", got.Result.Issues)
	}
}

// TestAdapterNotEnvelope: valid JSON that is not a node envelope maps to an
// invalid draft (ErrNotANodeEnvelope), never to a parse error.
func TestAdapterNotEnvelope(t *testing.T) {
	p := loadProfile(t)
	got, err := nodes.ValidateDocument(p, []byte(`{"just":"an object"}`), nil)
	if !errors.Is(err, nodes.ErrNotANodeEnvelope) {
		t.Fatalf("want ErrNotANodeEnvelope, got %v", err)
	}
	if got.Validation != domain.ValidationInvalid {
		t.Fatalf("want ValidationInvalid for non-envelope, got %v", got.Validation)
	}
}

// TestAdapterNonObjectRootsEnvelope is QA2-F1: a syntactically valid JSON
// value whose ROOT is not an object (array, empty array, string, number,
// bool) still passed the syntax hard gate, so it is a non-canonical ENVELOPE
// — never malformed JSON. It must map to ErrNotANodeEnvelope with
// ValidationInvalid, not applicable, and the EXACT original bytes preserved
// (the draft survives for a possible later fix); it must NOT lose its bytes
// to ErrMalformedJSON.
func TestAdapterNonObjectRootsEnvelope(t *testing.T) {
	p := loadProfile(t)
	roots := []string{
		`[1,2,3]`,
		`[]`,
		`"hello"`,
		`5`,
		`true`,
		`null`,
	}
	for _, raw := range roots {
		t.Run("root="+raw, func(t *testing.T) {
			original := []byte(raw)
			got, err := nodes.ValidateDocument(p, original, nil)
			if !errors.Is(err, nodes.ErrNotANodeEnvelope) {
				t.Fatalf("root %s: want ErrNotANodeEnvelope, got %v", raw, err)
			}
			if errors.Is(err, domain.ErrMalformedJSON) {
				t.Fatalf("root %s: valid non-object JSON must NOT be malformed", raw)
			}
			if got.Validation != domain.ValidationInvalid {
				t.Fatalf("root %s: want ValidationInvalid, got %v", raw, got.Validation)
			}
			if got.Result.Applicable {
				t.Fatalf("root %s: non-envelope must not be applicable", raw)
			}
			if !bytes.Equal(got.Document.Raw, original) {
				t.Fatalf("root %s: exact original bytes not preserved:\n got=%s\nwant=%s", raw, got.Document.Raw, original)
			}
		})
	}
}

// TestAdapterBigNumbersNotMalformed is QA2-F2 at the adapter boundary: a
// canonical envelope carrying a syntactically valid number that exceeds
// float64 (serverPort:1E400) passed the syntax gate, so it must be validated
// semantically (a value-free finding) — never mislabeled malformed and never
// losing its bytes. The node is invalid on the out-of-range port, with the
// exact original preserved.
func TestAdapterBigNumbersNotMalformed(t *testing.T) {
	p := loadProfile(t)
	raw := `{"protocol":"socks5","fields":{"active":{"server":"s.example","serverPort":1E400},"inactive":{},"unknown":{}}}`
	original := []byte(raw)
	got, err := nodes.ValidateDocument(p, original, nil)
	if errors.Is(err, domain.ErrMalformedJSON) {
		t.Fatalf("big number must not be malformed: %v", err)
	}
	if got.Validation != domain.ValidationInvalid {
		t.Fatalf("want ValidationInvalid for out-of-range port, got %v", got.Validation)
	}
	if !bytes.Equal(got.Document.Raw, original) {
		t.Fatalf("exact original bytes not preserved:\n got=%s\nwant=%s", got.Document.Raw, original)
	}
	// The out-of-range port must surface as a real semantic finding.
	if !hasIssue(got.Result, nodes.IssueBoundsViolation, "serverPort") {
		t.Fatalf("want boundsViolation on serverPort, got %+v", got.Result.Issues)
	}
}

// TestAdapterMalformedNeverReplaces: a malformed payload never replaces a
// previously saved state — the adapter returns no Document at all.
func TestAdapterMalformedNeverReplaces(t *testing.T) {
	p := loadProfile(t)
	res, err := nodes.ValidateDocument(p, []byte("{{{"), nil)
	if err == nil || !errors.Is(err, domain.ErrMalformedJSON) {
		t.Fatalf("malformed must be ErrMalformedJSON, got %v", err)
	}
	if len(res.Document.Raw) != 0 {
		t.Fatalf("malformed payload must produce no Document bytes")
	}
}

// TestAdapterTrailingClosersStayMalformed is a QA3-A1 regression guard for the
// NODE ADAPTER path. The adapter's syntax gate (domain.ParseDocument →
// json.Valid) already rejects trailing closers, and the shared-scanner EOF
// fix must not silently weaken that: a canonical-looking envelope followed by
// a trailing closer is malformed JSON with NO Document, never an envelope and
// never a preserved draft. This pins the adapter independently of the
// capability-side EOF fix.
func TestAdapterTrailingClosersStayMalformed(t *testing.T) {
	p := loadProfile(t)
	base := `{"protocol":"socks5","fields":{"active":{"server":"s.example","serverPort":1080},"inactive":{},"unknown":{}}}`
	for _, suf := range []string{"}", "]", "}}", "]}", " {}", " 5"} {
		t.Run("suffix="+suf, func(t *testing.T) {
			res, err := nodes.ValidateDocument(p, []byte(base+suf), nil)
			if err == nil || !errors.Is(err, domain.ErrMalformedJSON) {
				t.Fatalf("envelope+%q must be ErrMalformedJSON, got %v", suf, err)
			}
			if errors.Is(err, nodes.ErrNotANodeEnvelope) {
				t.Fatalf("envelope+%q must NOT be demoted to a non-envelope", suf)
			}
			if len(res.Document.Raw) != 0 {
				t.Fatalf("trailing closer must produce no Document bytes, got %d", len(res.Document.Raw))
			}
		})
	}
	// The same envelope WITHOUT trailing content still parses as an envelope
	// (semantic validation runs, not a syntax refusal).
	got, err := nodes.ValidateDocument(p, []byte(base), nil)
	if err != nil {
		t.Fatalf("clean envelope must decode (semantic, not parse error): %v", err)
	}
	if got.Validation != domain.ValidationValid {
		t.Fatalf("clean minimal socks5 envelope must be valid, got %v", got.Validation)
	}
}

// TestParseDocumentStillNotRun: the existing syntax-only gate still returns
// ValidationNotRun — validation is never implied by parsing.
func TestParseDocumentStillNotRun(t *testing.T) {
	doc, err := domain.ParseDocument([]byte(`{"protocol":"socks5","fields":{"active":{},"inactive":{},"unknown":{}}}`))
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	if doc.Validation != domain.ValidationNotRun {
		t.Fatalf("ParseDocument must stay NotRun, got %v", doc.Validation)
	}
}

// TestSecretAndUnknownCanariesAbsent: even with nested objects, credential
// URLs and odd field names submitted, no canary value reaches the serialized
// result, projection or diagnostics.
func TestSecretAndUnknownCanariesAbsent(t *testing.T) {
	p := loadProfile(t)
	active := minValid("vless")
	active["xhttpExtra"] = map[string]any{"deep": map[string]any{"leaf": nestedCanary}}
	active[urlCredCanary] = nestedCanary
	active[unknownCanary] = map[string]any{"credentialURL": urlCredCanary}
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: active, SecretPresence: trustedPresenceFor("vless")})
	// xhttpExtra is a declared object with no leaf allowlist: the validator
	// does not recurse into it, and the unknown fields are bucketed.
	assertNoCanary(t, "canaries", res)
	// The projection (via capability) also omits object fields and unknowns.
	proj, err := p.ProjectNodeFields("vless", active, map[string]bool{"uuid": true}, nil)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	assertNoCanary(t, "projection", proj)
	for _, u := range proj.Unsupported {
		if strings.Contains(u, "CANARY") {
			t.Fatalf("unsupported name leaked canary: %q", u)
		}
	}
}

// TestSecretPlaintextNeverSatisfiesRequired: a required SECRET can only be
// satisfied by TRUSTED sealed presence. A plaintext value placed in the
// active map is a smuggle attempt: it must NOT satisfy the requirement, the
// node stays invalid, and the plaintext never appears in the result.
func TestSecretPlaintextNeverSatisfiesRequired(t *testing.T) {
	p := loadProfile(t)
	active := minValid("vless")
	active["uuid"] = secretCanary // plaintext smuggle, NO trusted presence
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: active})
	if !hasIssue(res, nodes.IssueRequiredSecretMissing, "uuid") {
		t.Fatalf("plaintext uuid must not satisfy the required secret: %+v", res.Issues)
	}
	if res.Status != nodes.Invalid || res.Applicable {
		t.Fatalf("plaintext secret smuggle must leave the node invalid/inapplicable")
	}
	assertNoCanary(t, "plaintext-smuggle result", res)
}

// TestTrustedPresenceDrivesDependencies: a sealed-only secret (no key in any
// field map) is REAL semantic presence for dependency rules — mldsa65Seed
// sealed without security still yields dependencyMissing, and the plaintext
// map-key form does not silently count for a secret that has no sealed value.
func TestTrustedPresenceDrivesDependencies(t *testing.T) {
	p := loadProfile(t)
	active := minValid("vless") // security=tls present: dependency satisfied
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: active,
		SecretPresence: map[string]bool{"uuid": true, "mldsa65Seed": true}})
	if hasIssue(res, nodes.IssueDependencyMissing, "mldsa65Seed") {
		t.Fatalf("sealed secret dependency must be satisfied by present security: %+v", res.Issues)
	}
	// Flip: security dropped from active AND inactive → dependencyMissing on
	// the sealed-only secret (this is the assertion buj observed failing).
	activeNoSec := map[string]any{"server": "v.example", "serverPort": float64(443), "transport": "ws"}
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: activeNoSec,
		SecretPresence: map[string]bool{"uuid": true, "mldsa65Seed": true}})
	if !hasIssue(res, nodes.IssueDependencyMissing, "mldsa65Seed") {
		t.Fatalf("sealed mldsa65Seed must require security even without a plaintext value: %+v", res.Issues)
	}
}

// TestCopyImmutability: the Field snapshot cannot mutate the authority.
// Mutating returned slices/dependency structs must not change what the next
// consumer reads — the loaded authority is stable for its whole lifetime.
func TestCopyImmutability(t *testing.T) {
	p := loadProfile(t)
	f1, ok := p.Field("vless", "mldsa65Seed")
	if !ok {
		t.Fatal("mldsa65Seed not declared")
	}
	if f1.Dependencies == nil || len(f1.Dependencies.Requires) != 1 {
		t.Fatalf("expected requires=[security], got %+v", f1.Dependencies)
	}
	f1.Dependencies.Requires[0] = "MUTATED"
	f1.AllowedValues = append(f1.AllowedValues, "MUTATED")
	f2, _ := p.Field("vless", "mldsa65Seed")
	if len(f2.Dependencies.Requires) != 1 || f2.Dependencies.Requires[0] != "security" {
		t.Fatalf("caller mutated the authority through a Field snapshot: %+v", f2.Dependencies)
	}
	// Enum snapshot mutation likewise cannot poison the authority.
	e1, _ := p.Field("vless", "security")
	if len(e1.AllowedValues) == 0 {
		t.Fatal("security enum expected")
	}
	before := append([]string(nil), e1.AllowedValues...)
	e1.AllowedValues[0] = "MUTATED"
	e2, _ := p.Field("vless", "security")
	if e2.AllowedValues[0] != before[0] {
		t.Fatalf("enum slice aliased into the caller: %v", e2.AllowedValues)
	}
}

// TestStrictProfileMetadataRejections: the maintained parser fails closed on
// malformed authority metadata — duplicate keys, trailing content, unknown
// metadata keys, invalid defaults and dangling dependency targets — with the
// typed ErrProfileRejected and a static, value-free reason (no raw echo).
func TestStrictProfileMetadataRejections(t *testing.T) {
	wrap := func(fields string) []byte {
		return []byte(`{"profileVersion":2,"protocols":{"probe":{"fields":{` + fields + `}}}}`)
	}
	cases := map[string][]byte{
		"duplicate-key": []byte(`{"profileVersion":2,"profileVersion":2,"protocols":{"probe":{"fields":{"a":{"type":"string","classification":"known"}}}}}`),
		"trailing-json": wrap(`"a":{"type":"string","classification":"known"}`),
	}
	cases["trailing-json"] = append(cases["trailing-json"], []byte(" {}")...)
	cases["unknown-meta"] = wrap(`"a":{"type":"string","classification":"known","bogusMeta":true}`)
	cases["invalid-default"] = wrap(`"a":{"type":"integer","classification":"known","default":"x"}`)
	cases["secret-default"] = wrap(`"a":{"type":"string","classification":"secret","secret":true,"default":"s"}`)
	cases["dep-target-missing"] = wrap(`"a":{"type":"string","classification":"known","dependencies":{"requires":["ghost"],"incompatibleWith":[]}}`)
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := capability.Parse(raw)
			if !errors.Is(err, capability.ErrProfileRejected) {
				t.Fatalf("%s: want ErrProfileRejected, got %v", name, err)
			}
			// The reason must stay static/generic: the canary names above must
			// never appear in the error text.
			if strings.Contains(err.Error(), "bogusMeta") || strings.Contains(err.Error(), "ghost") {
				t.Fatalf("%s: error echoed raw metadata: %v", name, err)
			}
		})
	}
}

// TestInactiveParticipatesInDependencies: an inactive declared field is
// PRESERVED presence for dependency resolution — moving `security` from
// active to inactive must not fabricate dependencyMissing on the sealed
// mldsa65Seed, while the inactive value stays out of the active shape check.
func TestInactiveParticipatesInDependencies(t *testing.T) {
	p := loadProfile(t)
	active := map[string]any{"server": "v.example", "serverPort": float64(443), "transport": "ws"}
	res := nodes.Validate(p, nodes.Input{
		Protocol:       "vless",
		Active:         active,
		Inactive:       map[string]any{"security": "reality"},
		SecretPresence: map[string]bool{"uuid": true, "mldsa65Seed": true},
	})
	if hasIssue(res, nodes.IssueDependencyMissing, "mldsa65Seed") {
		t.Fatalf("inactive security must count as presence: %+v", res.Issues)
	}
	// And the reverse: nothing anywhere -> dependencyMissing stands.
	res = nodes.Validate(p, nodes.Input{
		Protocol:       "vless",
		Active:         active,
		SecretPresence: map[string]bool{"uuid": true, "mldsa65Seed": true},
	})
	if !hasIssue(res, nodes.IssueDependencyMissing, "mldsa65Seed") {
		t.Fatalf("missing security must yield dependencyMissing: %+v", res.Issues)
	}
}
