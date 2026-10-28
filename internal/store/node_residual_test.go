// Maintained behavior contract for v4-US1-T012-secure-draft-residual-correction
// (forward correction of RETURN 8307e8a). These tests pin the corrected
// behaviors that independent parent/review/testing acceptance found failing on
// 8307e8a, and preserve the already-improved behaviors (sentinel, numeric gate,
// envelope SAVE, empty label). Real product APIs in owned isolated DBs.

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain/nodes"
	"github.com/suchimauz/raylane/internal/store"
)

// readDocRaw returns the persisted nodes.doc plaintext for a node.
func readDocRaw(t *testing.T, s *store.Store, nodeID string) string {
	t.Helper()
	var doc string
	if err := s.DB().QueryRowContext(context.Background(), `SELECT doc FROM nodes WHERE id=?`, nodeID).Scan(&doc); err != nil {
		t.Fatalf("read doc: %v", err)
	}
	return doc
}

// --- C1: cross-bucket colliding names must not leak into derived plaintext ---

// A name present in BOTH the active bucket and another bucket (inactive or
// unknown) is ambiguous; its VALUE must be EXCLUDED from the derived plaintext
// (both the active canary value and the inactive/unknown value), while
// UNRELATED safe known fields in the same node are preserved.
func TestCorrect_CrossBucketCollisionExcluded(t *testing.T) {
	ctx := context.Background()
	cases := map[string]string{
		// active + inactive collision: neither value may reach nodes.doc.
		"active-inactive": `{"active":{"server":"safe.example","serverPort":443,"transport":"ws","security":"tls","sni":"CANARY-ACTIVE-VALUE"},"inactive":{"sni":"CANARY-INACTIVE-VALUE"},"unknown":{}}`,
		// active + unknown (quarantine) collision: neither value may reach.
		"active-unknown": `{"active":{"server":"safe.example","serverPort":443,"transport":"ws","security":"tls","sni":"CANARY-ACTIVE-VALUE"},"inactive":{},"unknown":{"sni":"CANARY-UNKNOWN-VALUE"}}`,
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			w, _, s, _ := newManagedStore(t)
			defer s.Close()
			out, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{
				ProtocolBytes: []byte(`"vless"`),
				FieldsBytes:   []byte(fields),
				Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "coll-uuid")},
			})
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			doc := readDocRaw(t, s, out.NodeID)
			for _, canary := range []string{"CANARY-ACTIVE-VALUE", "CANARY-INACTIVE-VALUE", "CANARY-UNKNOWN-VALUE"} {
				if strings.Contains(doc, canary) {
					t.Fatalf("cross-bucket colliding value %q leaked into derived plaintext: %s", canary, doc)
				}
			}
			// Unrelated safe known scalar preserved; the colliding name itself is
			// excluded from BOTH derived active and inactive maps.
			var d struct {
				Active   map[string]any `json:"active"`
				Inactive map[string]any `json:"inactive"`
			}
			if err := json.Unmarshal([]byte(doc), &d); err != nil {
				t.Fatalf("doc JSON: %v", err)
			}
			if d.Active["server"] != "safe.example" {
				t.Fatalf("unrelated safe known field must be preserved, got active=%+v", d.Active)
			}
			if _, ok := d.Active["sni"]; ok {
				t.Fatalf("ambiguous colliding name laundered into derived active: %s", doc)
			}
			if _, ok := d.Inactive["sni"]; ok {
				t.Fatalf("ambiguous colliding name laundered into derived inactive: %s", doc)
			}
		})
	}
}

// --- C2: duplicate canonical envelope keys -> ALL derived maps empty ---------

// Duplicate keys in the canonical fields object (active / inactive / bucket)
// are a NON-CANONICAL envelope: the adapter yields its faithful
// malformedEnvelope Invalid draft (SAVEABLE), and the derived active/inactive
// maps must be EMPTY (no last-key-wins laundering) with the known protocol kept.
func TestCorrect_DuplicateCanonicalFieldsEmptyDerived(t *testing.T) {
	ctx := context.Background()
	cases := map[string]string{
		"duplicate-active":       `{"active":{"server":"first-canary","server":"last-canary"},"inactive":{},"unknown":{}}`,
		"duplicate-inactive":     `{"active":{},"inactive":{"concurrency":0,"concurrency":1},"unknown":{}}`,
		"duplicate-decoded-name": `{"active":{"server":"first-canary","\u0073erver":"last-canary"},"inactive":{},"unknown":{}}`,
		"duplicate-bucket":       `{"active":{},"active":{"server":"last-canary"},"inactive":{},"unknown":{}}`,
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			w, _, s, _ := newManagedStore(t)
			defer s.Close()
			in := store.NodeCreateInput{
				ProtocolBytes: []byte(`"vless"`),
				FieldsBytes:   []byte(fields),
				Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "dup-uuid")},
			}
			out, err := w.CreateNodeAtomic(ctx, in)
			if err != nil {
				t.Fatalf("non-canonical envelope must SAVE, not abort: %v", err)
			}
			if out.Validation.Status != nodes.Invalid || out.Validation.Applicable ||
				len(out.Validation.Issues) != 1 || out.Validation.Issues[0].Code != nodes.IssueMalformedEnvelope {
				t.Fatalf("want Invalid/notApplicable/one malformedEnvelope, got %v/%v %+v",
					out.Validation.Status, out.Validation.Applicable, out.Validation.Issues)
			}
			doc := readDocRaw(t, s, out.NodeID)
			var d struct {
				Protocol string                     `json:"protocol"`
				Active   map[string]json.RawMessage `json:"active"`
				Inactive map[string]json.RawMessage `json:"inactive"`
			}
			if err := json.Unmarshal([]byte(doc), &d); err != nil {
				t.Fatalf("doc JSON: %v", err)
			}
			if d.Protocol != "vless" {
				t.Fatalf("known captured protocol lost: %s", doc)
			}
			if len(d.Active) != 0 || len(d.Inactive) != 0 {
				t.Fatalf("duplicate canonical fields must produce EMPTY derived maps (no last-wins): %s", doc)
			}
			for _, c := range []string{"first-canary", "last-canary"} {
				if strings.Contains(doc, c) {
					t.Fatalf("duplicate canary retained in derived plaintext: %s", doc)
				}
			}
		})
	}
}

// --- C3: strict label UTF-8 + unpaired surrogate refusal ---------------------

// A label with invalid raw UTF-8 or an UNPAIRED Unicode surrogate is refused
// (zero writes). Legal U+FFFD, the escaped \ufffd, and a valid surrogate PAIR
// are accepted. Absence / "" / 256 runes stay accepted exactly; null /
// non-string / >256 stay refused. ASCII JSON \uXXXX escapes are validated
// for surrogate pairing BEFORE the lossy decode.
func TestCorrect_LabelStrictUnicode(t *testing.T) {
	ctx := context.Background()
	// Raw invalid UTF-8 (incl. the CESU-8-style surrogate encodings \xed\xa0\x80,
	// which are NOT valid UTF-8 and decode to U+FFFD) and ASCII \uXXXX escapes
	// with an UNPAIRED / wrongly-ordered surrogate are refused. A valid surrogate
	// PAIR escape (\ud83d\ude00) is a real scalar (U+1F600) and is accepted.
	refuse := map[string][]byte{
		"invalid-raw-UTF8":       {'"', 0xff, '"'},
		"cesu8-high-surrogate":   {'"', 0xed, 0xa0, 0x80, '"'},       // invalid UTF-8 (U+D800 enc)
		"cesu8-low-surrogate":    {'"', 0xed, 0xb0, 0x80, '"'},       // invalid UTF-8 (U+DC00 enc)
		"escaped-lone-high":      []byte(`"` + `\ud800` + `"`),       // unpaired high surrogate
		"escaped-lone-low":       []byte(`"` + `\udc00` + `"`),       // unpaired low surrogate
		"escaped-high-then-high": []byte(`"` + `\ud800\ud801` + `"`), // no low half
		"escaped-reversed":       []byte(`"` + `\ude00\ud83d` + `"`), // low before high
		"escaped-high-then-BMP":  []byte(`"` + `\ud800\u0041` + `"`), // high then non-surrogate
	}
	for name, lb := range refuse {
		t.Run("refuse/"+name, func(t *testing.T) {
			w, _, s, _ := newManagedStore(t)
			defer s.Close()
			before := tableCounts(t, s)
			_, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{
				ProtocolBytes: []byte(`"vless"`),
				FieldsBytes:   []byte(vlessFieldsJSON),
				LabelBytes:    lb,
				Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "lbl-uuid")},
			})
			if err == nil {
				t.Fatalf("%s label must refuse", name)
			}
			if after := tableCounts(t, s); !countsEqual(before, after) {
				t.Fatalf("%s refusal must be zero-write", name)
			}
		})
	}
	accept := map[string][]byte{
		"u-fffd-literal":       {'"', 0xef, 0xbf, 0xbd, '"'}, // U+FFFD replacement char
		"escaped-ufffd":        []byte(`"` + `\ufffd` + `"`),
		"valid-surrogate-pair": []byte(`"` + `\ud83d\ude00` + `"`), // U+1F600 (real scalar via pair)
		"literal-non-BMP":      {'"', 0xf0, 0x9f, 0x98, 0x80, '"'}, // U+1F600 literal
		"escaped-backslash":    []byte(`"` + `\\ud800` + `"`),      // backslash + "ud800", NOT a surrogate escape
		"empty":                []byte(`""`),
	}
	for name, lb := range accept {
		t.Run("accept/"+name, func(t *testing.T) {
			w, _, s, _ := newManagedStore(t)
			defer s.Close()
			if _, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{
				ProtocolBytes: []byte(`"vless"`),
				FieldsBytes:   []byte(vlessFieldsJSON),
				LabelBytes:    lb,
				Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "lbl-acc-uuid")},
			}); err != nil {
				t.Fatalf("%s label must be accepted: %v", name, err)
			}
		})
	}
}

func countsEqual(a, b map[string]int) bool {
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// --- C4: protocol component must be an explicit JSON string ------------------

// protocol:null (or any non-string) WITHOUT typed secrets is a static
// zero-write component refusal; it must not be coerced into an empty-string
// protocol and SAVE. A legal unknown/nonempty JSON STRING still flows to the
// faithful validator (Invalid SAVE), never this gate.
func TestCorrect_ProtocolExplicitString(t *testing.T) {
	ctx := context.Background()
	// null / array protocol -> static refusal, zero writes.
	for name, pb := range map[string][]byte{"null": []byte(`null`), "array": []byte(`[]`)} {
		t.Run("refuse/"+name, func(t *testing.T) {
			w, _, s, _ := newManagedStore(t)
			defer s.Close()
			before := tableCounts(t, s)
			out, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{ProtocolBytes: pb, FieldsBytes: []byte(vlessFieldsJSON)})
			if err == nil || !outIsZero(out) {
				t.Fatalf("%s protocol must refuse with zero outcome, got err=%v out=%+v", name, err, out)
			}
			if after := tableCounts(t, s); !countsEqual(before, after) {
				t.Fatalf("%s protocol refusal must be zero-write", name)
			}
		})
	}
	// A legal unknown JSON STRING protocol still reaches the validator (Invalid
	// SAVE, not the component gate).
	t.Run("unknown-string-saves-invalid", func(t *testing.T) {
		w, _, s, _ := newManagedStore(t)
		defer s.Close()
		out, err := w.CreateNodeAtomic(ctx, store.NodeCreateInput{
			ProtocolBytes: []byte(`"nosuchproto"`),
			FieldsBytes:   []byte(vlessFieldsJSON),
		})
		if err != nil {
			t.Fatalf("unknown string protocol must SAVE Invalid, not refuse: %v", err)
		}
		if out.Validation.Status != nodes.Invalid {
			t.Fatalf("unknown string protocol must be Invalid, got %v", out.Validation.Status)
		}
	})
}

func outIsZero(o store.NodeOutcome) bool {
	return o.NodeID == "" && o.Revision == 0 && o.Validation.Status == 0 &&
		o.SecretPresence == nil && o.Projection.Active == nil && o.Projection.Inactive == nil &&
		o.Projection.Secrets == nil && o.Projection.Unsupported == nil
}

// --- C5: submitted known-object name fact restored (any present value) -------

// A PRESENT declared known-object field under its original ACTIVE bucket yields
// exactly one name-only Unsupported fact, for ANY submitted value ({} / null /
// string / [] / a real object) — never the value. This is the pre-repair
// (bde816a) accepted behavior; the marker representation must not alter it.
// An ABSENT object key stays absent (no Unsupported).
func TestCorrect_ObjectNameUnsupportedRestored(t *testing.T) {
	p, err := capability.Parse(profileBytes(t))
	if err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	for _, value := range []string{`{}`, `null`, `"PRIVATE_OBJECT_CANARY"`, `[]`, `{"private":"PRIVATE_OBJECT_CANARY"}`} {
		t.Run("projector/"+value, func(t *testing.T) {
			var decoded any
			if err := json.Unmarshal([]byte(value), &decoded); err != nil {
				t.Fatal(err)
			}
			direct, err := p.ProjectNodeFields("vless", map[string]any{"xhttpExtra": decoded}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(direct.Unsupported) != 1 || direct.Unsupported[0] != "xhttpExtra" {
				t.Fatalf("direct projector must yield name-only Unsupported for present object, got %v", direct.Unsupported)
			}
		})
	}
	// Absent object key -> no Unsupported.
	t.Run("projector/absent", func(t *testing.T) {
		direct, err := p.ProjectNodeFields("vless", map[string]any{"server": "v.example"}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range direct.Unsupported {
			if u == "xhttpExtra" {
				t.Fatalf("absent object key must not yield Unsupported, got %v", direct.Unsupported)
			}
		}
	})
	// Atomic path: submitted active object name fact survives create + safe read.
	ctx := context.Background()
	w, r, s, _ := newManagedStore(t)
	defer s.Close()
	in := store.NodeCreateInput{
		ProtocolBytes: []byte(`"vless"`),
		FieldsBytes:   []byte(`{"active":{"server":"v.example","serverPort":443,"transport":"xhttp","security":"tls","xhttpExtra":{"private":"CANARY"}},"inactive":{},"unknown":{}}`),
		Secrets:       []store.NodeSecretUpdate{replaceSecret("uuid", "obj-uuid")},
	}
	out, err := w.CreateNodeAtomic(ctx, in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(out.Projection.Unsupported) != 1 || out.Projection.Unsupported[0] != "xhttpExtra" {
		t.Fatalf("atomic safe read must yield name-only Unsupported, got %v", out.Projection.Unsupported)
	}
	// Cold read preserves the name fact; no private leaf ever surfaces.
	cold, err := r.ReadNodeSafe(ctx, out.NodeID)
	if err != nil {
		t.Fatalf("cold read: %v", err)
	}
	found := false
	for _, u := range cold.Projection.Unsupported {
		if u == "xhttpExtra" {
			found = true
		}
	}
	if !found {
		t.Fatalf("cold read must preserve object name fact, got %v", cold.Projection.Unsupported)
	}
	reser, _ := json.Marshal(cold.Projection)
	if bytes.Contains(reser, []byte("CANARY")) {
		t.Fatalf("object private leaf must never surface: %s", reser)
	}
}
