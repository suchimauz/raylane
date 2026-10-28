// Maintained behavior contract for v4-US1-T012-atomic-saveable-secure-draft-repair
// (FR-009/FR-019 + D1, faithful atomic persistence prerequisite, BEFORE HTTP).
//
// ONE functional outcome: newly created managed drafts are SAVEABLE on all
// syntax-valid semantic mistakes, while sensitive/original material is stored
// ONLY in protected ciphertext and the derived plaintext nodes.doc contains
// only actual allowlisted safe values or fixed value-free metadata. Typed
// secret and component refusals remain zero-write.
//
// These tests cover five coherent repairs (F1..F5) as maintained behavior,
// written test-first. They use real product APIs in owned isolated DBs with
// synthetic canaries; no real credential is exposed.

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/suchimauz/raylane/internal/domain/nodes"
	"github.com/suchimauz/raylane/internal/store"
)

// fieldsDoc builds a fields component string from the three buckets verbatim.
func fieldsDoc(active, inactive, unknown string) string {
	return `{"active":` + active + `,"inactive":` + inactive + `,"unknown":` + unknown + `}`
}

// readDerivedDoc reads the persisted nodes.doc plaintext row (the derived safe
// document whose at-rest invariant is under test) for a created node.
func readDerivedDoc(t *testing.T, s *store.Store, nodeID string) string {
	t.Helper()
	var doc string
	if err := s.DB().QueryRowContext(context.Background(), `SELECT doc FROM nodes WHERE id = ?`, nodeID).Scan(&doc); err != nil {
		t.Fatalf("read nodes.doc: %v", err)
	}
	return doc
}

// --- F1: derived nodes.doc must contain ONLY allowlisted safe values ---------

// F1_A: plaintext field-secret smuggling (active + inactive), undeclared active
// name, and a nested known-invalid object payload must stay ONLY in sealed
// preservation; the public projection hides them AND nodes.doc must NOT retain
// them in plaintext. Unknown-bucket canary stays excluded. Safe known scalars
// remain in nodes.doc; object-typed known fields appear as name-only markers.
func TestRepair_DerivedDocExcludesSensitive(t *testing.T) {
	ctx := context.Background()
	w, _, s, _ := newManagedStore(t)
	defer s.Close()

	// uuid is a DECLARED secret; smuggling its plaintext as an active + inactive
	// field value must not reach nodes.doc. "evil" is undeclared. xhttpExtra is
	// a declared known OBJECT field whose private leaf must not be retained.
	fields := fieldsDoc(
		`{"server":"v.example","serverPort":443,"transport":"ws","security":"tls","uuid":"CANARY-ACTIVE","evil":"CANARY-UNKNOWN-ACTIVE","xhttpExtra":{"privateLeaf":"CANARY-LEAF"}}`,
		`{"uuid":"CANARY-INACTIVE"}`,
		`{"zzz":"CANARY-UNKNOWN"}`,
	)
	out, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{
		ProtocolBytes: []byte(`"vless"`),
		FieldsBytes:   []byte(fields),
		Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "typed-uuid-value")},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	doc := readDerivedDoc(t, s, out.NodeID)
	for _, canary := range []string{"CANARY-ACTIVE", "CANARY-INACTIVE", "CANARY-UNKNOWN-ACTIVE", "CANARY-LEAF", "CANARY-UNKNOWN", "typed-uuid-value"} {
		if bytes.Contains([]byte(doc), []byte(canary)) {
			t.Fatalf("nodes.doc leaks %q in plaintext: %s", canary, doc)
		}
	}
	// Safe known scalars remain; an EXISTING ACTIVE known object renders as a
	// FIXED name-only marker ({}): no private leaf is retained, the historical
	// fact that the object was present is kept without any nested content.
	var parsed struct {
		Active   map[string]any `json:"active"`
		Inactive map[string]any `json:"inactive"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("derived doc must be JSON: %v (%s)", err, doc)
	}
	if parsed.Active["server"] != "v.example" || parsed.Active["serverPort"] == nil {
		t.Fatalf("safe known scalars must remain in nodes.doc, got active=%+v", parsed.Active)
	}
	if leaf, leaked := parsed.Active["xhttpExtra"].(map[string]any); leaked {
		if _, hasPrivate := leaf["privateLeaf"]; hasPrivate || len(leaf) != 0 {
			t.Fatalf("object known field must be a name-only fixed marker, got %v", leaf)
		}
	} else {
		t.Fatalf("existing active known object must appear as a name-only marker, got %v", parsed.Active["xhttpExtra"])
	}
}

// --- F2: exact reserved sentinel VALUE must refuse (zero writes) -------------

// F2_A: a replace whose VALUE is exactly __RAYLANE_SECRET_UNCHANGED_V1__ is
// refused with the static ErrSecretOp (no echo, zero writes across all seven
// managed tables). Mask-like and other non-exact strings remain legitimate.
func TestRepair_SentinelExactValueRefused(t *testing.T) {
	ctx := context.Background()
	w, _, s, _ := newManagedStore(t)
	before := tableCounts(t, s)

	_, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{
		ProtocolBytes: []byte(`"vless"`),
		FieldsBytes:   []byte(vlessFieldsJSON),
		Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "__RAYLANE_SECRET_UNCHANGED_V1__")},
	})
	if !errors.Is(err, store.ErrSecretOp) {
		t.Fatalf("exact sentinel VALUE must refuse with ErrSecretOp, got %v", err)
	}
	after := tableCounts(t, s)
	for tbl, n := range before {
		if after[tbl] != n {
			t.Fatalf("sentinel refusal must be zero-write; table %s %d -> %d", tbl, n, after[tbl])
		}
	}

	// Non-exact mask-like and ordinary values remain legitimate.
	for _, v := range []string{"••••", "********", "x__RAYLANE_SECRET_UNCHANGED_V1__y", "ordinary"} {
		out, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{
			ProtocolBytes: []byte(`"vless"`),
			FieldsBytes:   []byte(vlessFieldsJSON),
			Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", v)},
		})
		if err != nil {
			t.Fatalf("non-exact value %q must be accepted, got %v", v, err)
		}
		if !out.SecretPresence["uuid"] {
			t.Fatalf("non-exact value %q must yield uuid presence true", v)
		}
	}
}

// --- F3: huge canonical JSON numbers must SAVE (no float64 gate) -------------

// F3_A: 1E400 and a very large integer in active/inactive/unknown must pass the
// structural component gate and SAVE (faithful ordinary issue / valid-inactive
// semantics), with exact sealed bytes — not be refused before the validator by
// a float64 conversion.
func TestRepair_HugeNumbersSaveable(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		fields string
	}{
		{"active 1E400", fieldsDoc(`{"server":"v.example","serverPort":443,"transport":"ws","security":"tls","concurrency":1E400}`, `{}`, `{}`)},
		{"inactive 1E400", fieldsDoc(`{"server":"v.example","serverPort":443,"transport":"ws","security":"tls"}`, `{"concurrency":1E400}`, `{}`)},
		{"unknown 1E400", fieldsDoc(`{"server":"v.example","serverPort":443,"transport":"ws","security":"tls"}`, `{}`, `{"concurrency":1E400}`)},
		{"active huge int", fieldsDoc(`{"server":"v.example","serverPort":443,"transport":"ws","security":"tls","concurrency":123456789012345678901234567890}`, `{}`, `{}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r, s, _ := newManagedStore(t)
			defer s.Close()
			out, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{
				ProtocolBytes: []byte(`"vless"`),
				FieldsBytes:   []byte(tc.fields),
				Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "n-"+tc.name)},
			})
			if err != nil {
				t.Fatalf("huge number must SAVE (not be refused by float gate): %v", err)
			}
			// Exact original component bytes are sealed unchanged (no float loss,
			// no reserialization): the preservation container still holds the
			// exact huge-number lexeme.
			kp := writeKeyFile(t, keyDir(t), "master.key", validTestKey(), 0o600)
			plain, err := store.OpenPreservationForTests(ctx, s, kp, out.NodeID)
			if err != nil {
				t.Fatalf("preservation oracle: %v", err)
			}
			if !bytes.Contains(plain, []byte(tc.fields)) {
				t.Fatalf("sealed preservation must hold the exact original fields bytes\n got: %s\nwant substring: %s", plain, tc.fields)
			}
			// Cold keyless read returns the same historical verdict + presence and
			// does not recompute history.
			cold, err := r.ReadNodeSafe(ctx, out.NodeID)
			if err != nil {
				t.Fatalf("cold read: %v", err)
			}
			if cold.Revision != 1 || cold.SecretPresence["uuid"] != true {
				t.Fatalf("cold revision/presence mismatch: rev=%v presence=%+v", cold.Revision, cold.SecretPresence)
			}
		})
	}
}

// --- F4: semantic non-canonical envelope must SAVE Invalid, malformed refuses -

// F4_A: syntactically valid JSON with inner duplicate keys (active, nested
// unknown, escaped-decoded) yields the adapter's faithful Invalid/
// notApplicable + ErrNotANodeEnvelope and the store SAVES the draft (exact
// original bytes sealed, derived maps empty, known protocol preserved for
// cold-read presence). Malformed syntax / trailing content still refuses with
// zero writes.
func TestRepair_SemanticEnvelopeSavesInvalid(t *testing.T) {
	ctx := context.Background()
	dupActive := `{"protocol":"vless","fields":{"active":{"server":"a","server":"b"},"inactive":{},"unknown":{}}}`
	dupNested := `{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"ws","security":"tls"},"inactive":{},"unknown":{"k":{"x":1,"x":2}}}}`
	dupEscaped := `{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"ws","security":"tls","ser\u0076er":"dup"},"inactive":{},"unknown":{}}}`

	for _, raw := range []string{dupActive, dupNested, dupEscaped} {
		w, r, s, _ := newManagedStore(t)
		out, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{
			ProtocolBytes: []byte(`"vless"`),
			FieldsBytes:   []byte(raw),
			Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "dup-uuid")},
		})
		if err != nil {
			t.Fatalf("semantic duplicate envelope must SAVE, not abort: %v", err)
		}
		if out.Validation.Status != nodes.Invalid || out.Validation.Applicable {
			t.Fatalf("duplicate envelope must be Invalid/notApplicable, got %v/%v", out.Validation.Status, out.Validation.Applicable)
		}
		// Derived doc has empty active/inactive (ambiguity not laundered), known protocol kept.
		doc := readDerivedDoc(t, s, out.NodeID)
		var parsed struct {
			Protocol string         `json:"protocol"`
			Active   map[string]any `json:"active"`
			Inactive map[string]any `json:"inactive"`
		}
		if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
			t.Fatalf("derived doc JSON: %v", err)
		}
		if parsed.Protocol != "vless" || len(parsed.Active) != 0 || len(parsed.Inactive) != 0 {
			t.Fatalf("ambiguous envelope must keep known protocol + empty derived maps, got %s", doc)
		}
		// Cold keyless reader: same historical fact + current uuid presence.
		cold, err := r.ReadNodeSafe(ctx, out.NodeID)
		if err != nil {
			t.Fatalf("cold read: %v", err)
		}
		if cold.Validation.Status != nodes.Invalid || !cold.SecretPresence["uuid"] {
			t.Fatalf("cold must preserve Invalid + uuid presence, got %v/%+v", cold.Validation.Status, cold.SecretPresence)
		}
		s.Close()
	}

	// Malformed syntax / trailing still refuse with zero writes.
	w, _, s, _ := newManagedStore(t)
	before := tableCounts(t, s)
	if _, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{
		ProtocolBytes: []byte(`"vless"`),
		FieldsBytes:   []byte(`{"active":{},"inactive":{},"unknown":{}} trailing`),
		Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "trailing")},
	}); err == nil {
		t.Fatalf("trailing JSON must refuse")
	}
	after := tableCounts(t, s)
	for tbl, n := range before {
		if after[tbl] != n {
			t.Fatalf("malformed refusal must be zero-write; table %s %d -> %d", tbl, n, after[tbl])
		}
	}
	s.Close()
}

// --- F5: empty label accepted exactly; null/non-string/>256 refused ----------

// F5_A: the optional label has max 256 and NO min, so empty string is accepted
// exactly; absent stays absent; null / non-string / >256 runes are refused with
// zero writes (null must NOT be silently admitted via json.Unmarshal).
func TestRepair_LabelEmptyAccepted(t *testing.T) {
	ctx := context.Background()

	// Empty string accepted; preservation keeps it exactly (label:"" present,
	// absence vs empty vs null stay distinguishable); cold read works.
	w, r, s, _ := newManagedStore(t)
	out, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{
		ProtocolBytes: []byte(`"vless"`),
		FieldsBytes:   []byte(vlessFieldsJSON),
		LabelBytes:    []byte(`""`),
		Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "empty-label-uuid")},
	})
	if err != nil {
		t.Fatalf("empty label must be accepted: %v", err)
	}
	// Exact preservation: the sealed container keeps the empty-label bytes verbatim.
	kp := writeKeyFile(t, keyDir(t), "master.key", validTestKey(), 0o600)
	plain, err := store.OpenPreservationForTests(ctx, s, kp, out.NodeID)
	if err != nil {
		t.Fatalf("preservation oracle: %v", err)
	}
	if !bytes.Contains(plain, []byte(`"label":""`)) && !bytes.Contains(plain, []byte(`"label": ""`)) {
		t.Fatalf("sealed preservation must retain the empty label component exactly: %s", plain)
	}
	cold, err := r.ReadNodeSafe(ctx, out.NodeID)
	if err != nil || cold.Validation.Status != nodes.Valid {
		t.Fatalf("empty-label node must cold-read Valid, got %v/%v", err, cold.Validation.Status)
	}
	s.Close()

	// Absent label accepted (control).
	w2, _, s2, _ := newManagedStore(t)
	if _, err := w2.CreateNodeAtomic(ctx, store.NodeCreateInput{
		ProtocolBytes: []byte(`"vless"`),
		FieldsBytes:   []byte(vlessFieldsJSON),
		Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "absent-label-uuid")},
	}); err != nil {
		t.Fatalf("absent label must be accepted: %v", err)
	}
	s2.Close()

	// 256 runes accepted; 257 refused; null refused; non-string refused.
	runes256 := make([]byte, 256)
	for i := range runes256 {
		runes256[i] = 'a'
	}
	label256, _ := json.Marshal(string(runes256))
	w3, _, s3, _ := newManagedStore(t)
	if _, err := w3.CreateNodeAtomic(ctx, store.NodeCreateInput{
		ProtocolBytes: []byte(`"vless"`),
		FieldsBytes:   []byte(vlessFieldsJSON),
		LabelBytes:    label256,
		Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "l256-uuid")},
	}); err != nil {
		t.Fatalf("256-rune label must be accepted: %v", err)
	}
	s3.Close()

	for name, lb := range map[string]string{
		"null":      `null`,
		"nonstring": `123`,
		"257runes":  string(mustJSON(t, string(make([]byte, 257)))),
		"malformed": `"unterminated`,
	} {
		w4, _, s4, _ := newManagedStore(t)
		before := tableCounts(t, s4)
		_, err := w4.CreateNodeAtomic(ctx, store.NodeCreateInput{
			ProtocolBytes: []byte(`"vless"`),
			FieldsBytes:   []byte(vlessFieldsJSON),
			LabelBytes:    []byte(lb),
			Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "bad-label-uuid")},
		})
		switch name {
		case "257runes", "null", "nonstring", "malformed":
			if err == nil {
				t.Fatalf("%s label must refuse", name)
			}
			after := tableCounts(t, s4)
			for tbl, n := range before {
				if after[tbl] != n {
					t.Fatalf("%s refusal must be zero-write; table %s %d -> %d", name, tbl, n, after[tbl])
				}
			}
		}
		s4.Close()
	}
}

func mustJSON(t *testing.T, s string) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
