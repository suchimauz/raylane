// Maintained regression for v4-US1-T012 known-field scalar integrity (forward
// correction of RETURN b572703). These durable, repository-owned tests are
// discovered by ordinary `go test` and detect removal of the raw scalar gate
// or the derived-content guard. They use REAL ValidateDocument + real
// CreateNodeAtomic + cold keyless ReadNodeSafe + test-only preservation
// decrypt; no mocks, stubs, AST/hash-only checks, or new production getters.

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
	"github.com/suchimauz/raylane/internal/store"
)

const scalarBase = `"server":"v.example","serverPort":443,"transport":"ws","security":"tls"`

// scalarFields builds the three-bucket fields JSON. Fragment arguments are
// passed WITHOUT a leading comma; the empty fragment is omitted (an empty
// object must not gain a leading comma).
func scalarFields(active, inactive, unknown string) string {
	return `{"active":{` + scalarBase + withComma(active) +
		`},"inactive":{` + commaEntry(inactive) +
		`},"unknown":{` + commaEntry(unknown) + `}}`
}

// withComma separates an additional member from the base members of the
// active bucket (the base is never empty, so the comma belongs here).
func withComma(entry string) string {
	if entry == "" {
		return ""
	}
	return "," + entry
}

// commaEntry renders a non-empty object member fragment; an empty fragment
// renders nothing. Object members are separated (not terminated) by commas,
// so the FIRST member inside a bucket must NOT be prefixed — a leading comma
// (`{,}`) is invalid JSON and a wrong fixture would fail on the syntax gate
// instead of exercising the rule under test. Callers pass fragments without
// a leading comma.
func commaEntry(entry string) string {
	if entry == "" {
		return ""
	}
	return entry
}

// readScalarDerived reads nodes.doc and returns the parsed version/protocol/
// active/inactive for the scalar-envelope assertions.
func readScalarDerived(t *testing.T, s *store.Store, nodeID string) (version int, protocol string, active, inactive map[string]json.RawMessage) {
	t.Helper()
	var doc string
	if err := s.DB().QueryRowContext(context.Background(), `SELECT doc FROM nodes WHERE id = ?`, nodeID).Scan(&doc); err != nil {
		t.Fatalf("read derived doc: %v", err)
	}
	var d struct {
		Version  int                        `json:"version"`
		Protocol string                     `json:"protocol"`
		Active   map[string]json.RawMessage `json:"active"`
		Inactive map[string]json.RawMessage `json:"inactive"`
	}
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("derived doc JSON: %v", err)
	}
	return d.Version, d.Protocol, d.Active, d.Inactive
}

// TestScalarEnvelope_Noncanonical is the core maintained regression: an
// otherwise-valid complete VLESS node (with the required sealed uuid) whose
// protocol/fields carry a NON-SCALAR string/key at some depth saves as an
// actual SEMANTIC malformedEnvelope Invalid draft — never a lossy Valid, never
// a syntax/component zero-write. Asserts the exact adapter verdict, ONE static
// malformedEnvelope@envelope issue, empty derived maps even with unrelated
// known fields, independently scalar-safe known protocol only, no value echo,
// sealed exact originals, cold whole-history/current-presence reproduction.
func TestScalarEnvelope_Noncanonical(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		fields   string
		known    bool // protocol is a declared profile protocol
	}{
		// known SNI value: high / low / raw-invalid-UTF8 surrogate.
		{"known-sni-high", `"vless"`, scalarFields(`"sni":"a\ud800b"`, "", ""), true},
		{"known-sni-low", `"vless"`, scalarFields(`"sni":"a\udc00b"`, "", ""), true},
		{"known-sni-raw-invalid", `"vless"`, scalarFields(`"sni":"a`+string([]byte{0xff})+`b"`, "", ""), true},
		// active unknown key with a surrogate escape.
		{"active-unknown-key", `"vless"`, scalarFields(`"PRIVATE_KEY_\ud800":"PRIVATE_FIELD_VALUE"`, "", ""), true},
		// inactive known value with an unpaired surrogate ESCAPE and an
		// inactive key carrying raw invalid UTF-8. Raw invalid bytes make the
		// whole payload SYNTAX-invalid to encoding/json — the syntax gate
		// (ErrMalformedJSON, zero-write) legitimately wins there — while the
		// escape form is syntax-valid and must reach the semantic gate.
		{"inactive-known-value", `"vless"`, scalarFields("", `"sni":"a\ud800b"`, ""), true},
		{"inactive-key-raw-invalid", `"vless"`, scalarFields("", `"PRIVATE_KEY_`+string([]byte{0xff})+`":1`, ""), true},
		// unknown bucket nested array with a surrogate value.
		{"unknown-nested-array", `"vless"`, scalarFields("", "", `"PRIVATE_UNKNOWN":{"nested":["a\ud800b"]}`), true},
		// opaque known object key with a low surrogate.
		{"opaque-object-key", `"vless"`, scalarFields(`"xhttpExtra":{"PRIVATE_KEY_\udc00":"PRIVATE_OPAQUE_VALUE"}`, "", ""), true},
		// known array (alpn) with a surrogate element.
		{"array-known-string", `"vless"`, scalarFields(`"alpn":["h2","a\ud800b"]`, "", ""), true},
		// bad protocol (escape / raw) — no typed secrets (unknown protocol).
		{"bad-protocol-escape", `"vl\ud800ess"`, scalarFields("", "", ""), false},
		{"bad-protocol-raw", `"vl` + string([]byte{0xff}) + `ess"`, scalarFields("", "", ""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			kdir := keyDir(t)
			keyPath := writeKeyFile(t, kdir, "master.key", validTestKey(), 0o600)
			w, r, s, _ := newManagedStore(t)
			defer s.Close()

			in := vlessInput()
			in.ProtocolBytes = []byte(tc.protocol)
			in.FieldsBytes = []byte(tc.fields)
			if tc.known {
				in.Secrets = append(in.Secrets, replaceSecret("uuid", "SCALAR_ENVELOPE_TYPED_SECRET"))
			}
			env := []byte(`{"protocol":` + tc.protocol + `,"fields":` + tc.fields + `}`)

			// (1) The REAL adapter over the original bytes yields a SEMANTIC
			// noncanonical Invalid (not a syntax refusal, not a lossy Valid).
			// Raw invalid UTF-8 bytes are SYNTAX-invalid to encoding/json itself
			// (verified maintained behavior: the decoder refuses a lone raw 0xFF
			// inside a string), so those payloads legitimately stop at the
			// syntax gate with ErrMalformedJSON and the store's static
			// zero-write — the sealed originals are never rewritten, never
			// lossily stored. ESCAPE-form non-scalars are syntax-VALID and must
			// reach the semantic malformedEnvelope Invalid draft below.
			rawSyntax := rawInvalidUTF8Rejected(env)
			authority, err := store.OpenNodeAuthority(profileBytes(t))
			if err != nil {
				t.Fatal(err)
			}
			ar, aerr := nodes.ValidateDocument(authority.Profile(), env, map[string]bool{"uuid": true})
			if rawSyntax {
				if !errors.Is(aerr, domain.ErrMalformedJSON) {
					t.Fatalf("raw invalid UTF-8 must stay the syntax gate ErrMalformedJSON, got %v", aerr)
				}
				before := tableCounts(t, s)
				_, serr := w.CreateNodeAtomic(ctx, in)
				if !errors.Is(serr, domain.ErrMalformedJSON) {
					t.Fatalf("raw invalid UTF-8 store path must be the syntax refusal, got %v", serr)
				}
				if after := tableCounts(t, s); !countsEqual(before, after) {
					t.Fatal("raw invalid UTF-8 syntax refusal must be zero-write")
				}
				return
			}
			if !errors.Is(aerr, nodes.ErrNotANodeEnvelope) || ar.Validation != domain.ValidationInvalid ||
				ar.Result.Status != nodes.Invalid || ar.Result.Applicable {
				t.Fatalf("adapter must return semantic noncanonical Invalid/notApplicable, not syntax/lossy: err=%v verdict=%v/%v applicable=%v",
					aerr, ar.Validation, ar.Result.Status, ar.Result.Applicable)
			}
			if len(ar.Result.Issues) != 1 || ar.Result.Issues[0].Code != nodes.IssueMalformedEnvelope ||
				ar.Result.Issues[0].Field != "envelope" {
				t.Fatalf("adapter must emit exactly ONE static malformedEnvelope@envelope, got %+v", ar.Result.Issues)
			}

			// (2) The store SAVES the Invalid draft (never aborts).
			out, err := w.CreateNodeAtomic(ctx, in)
			if err != nil {
				t.Fatalf("noncanonical scalar envelope must SAVE Invalid, not refuse: %v", err)
			}
			if out.Validation.Status != nodes.Invalid || out.Validation.Applicable ||
				len(out.Validation.Issues) != 1 || out.Validation.Issues[0].Code != nodes.IssueMalformedEnvelope ||
				out.Validation.Issues[0].Field != "envelope" {
				t.Fatalf("saved result not faithful malformedEnvelope Invalid/notApplicable: %+v", out.Validation)
			}

			// (3) BOTH derived maps EMPTY even though unrelated known fields are
			// present; protocol retained ONLY when independently scalar-safe+known.
			version, protocol, active, inactive := readScalarDerived(t, s, out.NodeID)
			if version != 1 || len(active) != 0 || len(inactive) != 0 {
				t.Fatalf("noncanonical scalar envelope must have BOTH EMPTY derived maps")
			}
			wantProtocol := ""
			if tc.known {
				wantProtocol = "vless"
			}
			if protocol != wantProtocol {
				t.Fatalf("only independently scalar-safe known protocol may remain, got %q want %q", protocol, wantProtocol)
			}

			// (4) No submitted value/name/secret leaks into any artifact.
			for _, canary := range []string{"PRIVATE_FIELD_VALUE", "PRIVATE_OPAQUE_VALUE", "PRIVATE_UNKNOWN", "SCALAR_ENVELOPE_TYPED_SECRET"} {
				if bytes.Contains([]byte(protocol+string(marshalRawMap(active))+string(marshalRawMap(inactive))), []byte(canary)) {
					t.Fatalf("derived doc echoes %q", canary)
				}
			}

			// (5) Preservation holds the EXACT original components (sealed); the
			// typed secret value is NOT copied in.
			plain, err := store.OpenPreservationForTests(ctx, s, keyPath, out.NodeID)
			if err != nil {
				t.Fatalf("preservation: %v", err)
			}
			wantPres := []byte(`{"protocol":` + tc.protocol + `,"fields":` + tc.fields + `}`)
			if !bytes.Equal(plain, wantPres) {
				t.Fatalf("preservation must hold EXACT original components\n got: %s\nwant: %s", plain, wantPres)
			}
			if bytes.Contains(plain, []byte("SCALAR_ENVELOPE_TYPED_SECRET")) {
				t.Fatalf("typed secret value leaked into preservation")
			}

			// (6) Cold keyless reader reproduces the SAME whole historical verdict
			// and current presence, byte-equal marshaled result.
			cold, err := r.ReadNodeSafe(ctx, out.NodeID)
			if err != nil {
				t.Fatalf("cold keyless read: %v", err)
			}
			coldJSON, err := nodes.MarshalResultJSON(cold.Validation)
			if err != nil {
				t.Fatal(err)
			}
			warmJSON, err := nodes.MarshalResultJSON(out.Validation)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(coldJSON, warmJSON) {
				t.Fatalf("cold whole-history verdict changed:\nwarm=%s\ncold=%s", warmJSON, coldJSON)
			}
			if cold.Validation.Status != nodes.Invalid {
				t.Fatalf("cold must keep Invalid, got %v", cold.Validation.Status)
			}
			if tc.known && !cold.SecretPresence["uuid"] {
				t.Fatalf("cold must keep current uuid presence, got %+v", cold.SecretPresence)
			}
		})
	}
}

// rawInvalidUTF8Rejected reports whether encoding/json itself refuses raw as
// syntax (the gate domain.ParseDocument applies before anything else runs).
// This pins the ACTUAL decoder behavior the syntax gate inherits, instead of
// assuming raw invalid UTF-8 is syntax-legal.
func rawInvalidUTF8Rejected(raw []byte) bool {
	return !json.Valid(raw)
}

func marshalRawMap(m map[string]json.RawMessage) []byte {
	b, _ := json.Marshal(m)
	return b
}

// TestScalarEnvelope_LegalControls pins that LEGAL scalar content keeps its
// actual values/outcomes: a valid surrogate PAIR, literal/escaped U+FFFD, BMP
// and non-BMP literals, an escaped backslash, ordinary escapes, and a legal
// unknown protocol string all stay accepted (Valid / prior Invalid semantics
// unchanged); ordinary inactive semantic errors are not reclassified; and the
// legal unknown bucket still quarantines Invalid WITHOUT this malformedEnvelope
// gate.
func TestScalarEnvelope_LegalControls(t *testing.T) {
	ctx := context.Background()
	// Valid pair / U+FFFD / escapes → Valid draft with the real values.
	controls := []struct {
		name     string
		sniValue string // raw JSON string for the sni value
	}{
		{"valid-surrogate-pair", `"a\ud83d\ude00b"`},
		{"literal-ufffd", `"a` + string([]byte{0xef, 0xbf, 0xbd}) + `b"`},
		{"escaped-ufffd", `"a\ufffdb"`},
		{"bmp-ordinary", `"h2,example"`},
		{"escaped-backslash", `"a\\ud800b"`}, // backslash + "ud800", NOT a surrogate escape
		{"ordinary-escape", `"a\nb"`},
	}
	for _, tc := range controls {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			w, _, s, _ := newManagedStore(t)
			defer s.Close()
			in := vlessInput(replaceSecret("uuid", "ctrl-uuid"))
			in.FieldsBytes = []byte(scalarFields(`"sni":`+tc.sniValue, "", ""))
			out, err := w.CreateNodeAtomic(ctx, in)
			if err != nil {
				t.Fatalf("legal scalar control must save: %v", err)
			}
			if out.Validation.Status != nodes.Valid {
				t.Fatalf("legal scalar control must be Valid, got %v", out.Validation.Status)
			}
			// The REAL value (not a lossy replacement) reaches the derived doc.
			_, _, active, _ := readScalarDerived(t, s, out.NodeID)
			var sni string
			if err := json.Unmarshal(active["sni"], &sni); err != nil {
				t.Fatalf("sni not preserved as real value: %v", err)
			}
			if strings.Contains(sni, string([]byte{0xef, 0xbf, 0xbd})) && tc.name != "literal-ufffd" && tc.name != "escaped-ufffd" {
				t.Fatalf("control %s lossy-replaced to U+FFFD: %q", tc.name, sni)
			}
		})
	}

	// Legal UNKNOWN protocol string → prior Invalid (unknown protocol), NOT
	// this malformedEnvelope gate, no echo.
	t.Run("unknown-protocol-prior-invalid", func(t *testing.T) {
		w, _, s, _ := newManagedStore(t)
		defer s.Close()
		in := vlessInput()
		in.ProtocolBytes = []byte(`"nosuchproto"`)
		out, err := w.CreateNodeAtomic(ctx, in)
		if err != nil {
			t.Fatalf("unknown protocol string must SAVE Invalid, not refuse: %v", err)
		}
		if out.Validation.Status != nodes.Invalid || out.Validation.Applicable {
			t.Fatalf("unknown protocol must be Invalid/notApplicable, got %v/%v", out.Validation.Status, out.Validation.Applicable)
		}
		_, protocol, _, _ := readScalarDerived(t, s, out.NodeID)
		if protocol != "" {
			t.Fatalf("unknown protocol must not be retained in derived doc, got %q", protocol)
		}
	})

	// Legal unknown bucket (undeclared name) still quarantine-Invalid (NOT
	// malformedEnvelope) when everything is scalar.
	t.Run("unknown-bucket-quarantine-not-malformed", func(t *testing.T) {
		w, _, s, _ := newManagedStore(t)
		defer s.Close()
		in := vlessInput(replaceSecret("uuid", "quar-uuid"))
		in.FieldsBytes = []byte(scalarFields("", "", `"undeclared":"value"`))
		out, err := w.CreateNodeAtomic(ctx, in)
		if err != nil {
			t.Fatalf("unknown bucket must SAVE: %v", err)
		}
		for _, iss := range out.Validation.Issues {
			if iss.Code == nodes.IssueMalformedEnvelope {
				t.Fatalf("legal scalar unknown bucket must NOT be malformedEnvelope, got %+v", out.Validation.Issues)
			}
		}
	})
}

// TestScalarEnvelope_RefusalZeroWrite pins that the scalar gate does NOT weaken
// any existing static refusal: malformed-hex escape (syntax-invalid), trailing
// content, an invalid typed label, a null label, and a refused typed secret
// each still refuse with ZERO writes across all seven tables.
func TestScalarEnvelope_RefusalZeroWrite(t *testing.T) {
	ctx := context.Background()
	// malformed \u escape (bad hex) is SYNTAX-invalid → store zero-write.
	t.Run("malformed-hex-syntax-zero-write", func(t *testing.T) {
		w, _, s, _ := newManagedStore(t)
		defer s.Close()
		before := tableCounts(t, s)
		_, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{
			ProtocolBytes: []byte(`"vless"`),
			FieldsBytes:   []byte(scalarFields(`"sni":"a\ud80Zb"`, "", "")),
			Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "x")},
		})
		if err == nil {
			t.Fatal("malformed-hex escape must be a syntax zero-write refusal")
		}
		if after := tableCounts(t, s); !countsEqual(before, after) {
			t.Fatal("malformed-hex refusal must be zero-write across all tables")
		}
	})
	// invalid typed label (unpaired surrogate escape) still static zero-write.
	t.Run("invalid-label-zero-write", func(t *testing.T) {
		w, _, s, _ := newManagedStore(t)
		defer s.Close()
		before := tableCounts(t, s)
		in := vlessInput(replaceSecret("uuid", "y"))
		in.LabelBytes = []byte(`"` + `\ud800` + `"`)
		_, err := w.CreateNodeAtomic(ctx, in)
		if err == nil {
			t.Fatal("unpaired-surrogate label must refuse")
		}
		if after := tableCounts(t, s); !countsEqual(before, after) {
			t.Fatal("label refusal must be zero-write across all tables")
		}
	})
}
