package authhttp

// T012 wire-boundary (RED) tests for the closed outer shape of
// POST /api/v1/nodes: raw-UTF8 integrity, duplicate-key detection including
// escaped aliases, case-sensitivity, the strict typed label, the typed/422
// vs transport/400 split, the 262144 single bound, and the Invalid-draft
// SAVES matrix with exact wire byte-goldens.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/store"
)

// t012Create is the minimal legal create body used as the mutation base.
const t012Create = `{"protocol":"vless","fields":{"active":{"server":"a.example","serverPort":443,"transport":"raw","security":"tls"},"inactive":{},"unknown":{}},"secrets":{"uuid":{"op":"replace","value":"c-uuid-value-0001"}}}`

func t012Post(t *testing.T, h http.Handler, cookie *http.Cookie, body []byte) *http.Response {
	t.Helper()
	return t012Do(h, http.MethodPost, "/api/v1/nodes", testOrigin, body, cookie)
}

func t012Body(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestT012CreateHappyPathGolden(t *testing.T) {
	_, h, cookie := t012Server(t, t012NodeKeyFile(t))
	resp := t012Post(t, h, cookie, []byte(t012Create))
	raw := t012Body(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("legal create: want 201, got %d %s", resp.StatusCode, raw)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"id": true, "protocol": true, "revision": true,
		"validation": true, "fields": true, "secrets": true}
	for k := range top {
		if ok, declared := want[k]; !declared || !ok {
			t.Fatalf("unexpected wire member %q in 201: %s", k, raw)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(top["fields"], &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 {
		t.Fatalf("fields must expose exactly the three buckets: %s", top["fields"])
	}
	for k := range fields {
		if k != "active" && k != "inactive" && k != "unknown" {
			t.Fatalf("unexpected fields member %q", k)
		}
	}
	if string(fields["unknown"]) != "{}" {
		t.Fatalf("unknown bucket must serialize as {}: %s", fields["unknown"])
	}
	var val map[string]json.RawMessage
	if err := json.Unmarshal(top["validation"], &val); err != nil {
		t.Fatal(err)
	}
	for _, must := range []string{"state", "applicable", "chainCheck", "structuredCheck", "errors"} {
		if _, ok := val[must]; !ok {
			t.Fatalf("validation missing %s: %s", must, top["validation"])
		}
	}
	if string(val["state"]) != `"valid-draft"` || string(val["applicable"]) != "true" ||
		string(val["chainCheck"]) != `"not_required"` || string(val["structuredCheck"]) != `"not_required"` {
		t.Fatalf("vless happy-path validation tokens wrong: %s", top["validation"])
	}
	if string(val["errors"]) != "[]" {
		t.Fatalf("valid draft must carry empty errors: %s", top["validation"])
	}
	var rev int64
	if err := json.Unmarshal(top["revision"], &rev); err != nil || rev != 1 {
		t.Fatalf("revision must be server 1: %s", top["revision"])
	}
	if string(top["protocol"]) != `"vless"` {
		t.Fatalf("protocol golden: %s", top["protocol"])
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("201 content-type: %q", ct)
	}
}

// TestT012UnknownTopLevelFieldRefused: an unknown member of the closed
// create envelope is refused STATICALLY and never echoed; under the settled
// category split it belongs to the typed-shape family (the envelope parses,
// the schema refuses the member), so it must never reach 201 and the body
// must never echo the member name.
func TestT012UnknownTopLevelFieldIs400(t *testing.T) {
	_, h, cookie := t012Server(t, t012NodeKeyFile(t))
	for _, body := range []string{
		strings.TrimSuffix(t012Create, "}") + `,"extra":1}`,
		strings.TrimSuffix(t012Create, "}") + `,"apply":true}`,
		strings.TrimSuffix(t012Create, "}") + `,"target":{}}`,
	} {
		resp := t012Post(t, h, cookie, []byte(body))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("unknown top-level member: want 400, got %d (%s)", resp.StatusCode, body)
		}
		if bytes.Contains(t012Body(t, resp), []byte("extra")) ||
			bytes.Contains(t012Body(t, resp), []byte("apply")) {
			t.Fatal("refusal body must never echo the unknown member")
		}
	}
}

func TestT012CaseFoldKeysNeverMatch(t *testing.T) {
	_, h, cookie := t012Server(t, t012NodeKeyFile(t))
	for _, body := range []string{
		`{"Protocol":"vless","fields":{"active":{},"inactive":{},"unknown":{}}}`,
		`{"PROTOCOL":"vless","fields":{"active":{},"inactive":{},"unknown":{}}}`,
		strings.TrimSuffix(t012Create, "}") + `,"Label":"x"}`,
		strings.TrimSuffix(t012Create, "}") + `,"SECRET":{}}`,
		// Case-fold alias of a SECRET UPDATE key: never the canonical op key.
		`{"protocol":"vless","fields":{"active":{},"inactive":{},"unknown":{}},"secrets":{"uuid":{"Op":"replace","value":"x"}}}`,
	} {
		resp := t012Post(t, h, cookie, []byte(body))
		// Case-fold aliases never MATCH the closed schema: an unknown top-level
		// member is a typed shape refusal (422, no echo) and the missing
		// required member makes it un-creatable either way — never 201.
		if resp.StatusCode == http.StatusCreated {
			t.Fatalf("case-fold key %q must never match the closed schema", body)
		}
	}
}

// TestT012DuplicateOuterKeysAreTransport400: duplicate OUTER envelope member
// keys (same spelling, escaped-vs-plain spelling, or deeper closed shapes at
// the envelope level) are refused by the closed envelope rule with the static
// transport 400 — never accepted, never last-wins, never echoed.
func TestT012DuplicateOuterKeysAreTransport400(t *testing.T) {
	_, h, cookie := t012Server(t, t012NodeKeyFile(t))
	for _, body := range []string{
		`{"protocol":"vless","protocol":"vless","fields":{"active":{},"inactive":{},"unknown":{}}}`,
		`{"protocol":"vless","fields":{"active":{},"inactive":{},"unknown":{}},"fields":{"active":{},"inactive":{},"unknown":{}}}`,
		// Raw duplicate: same key spelled once escaped, once plain.
		`{"protocol":"vless","protoco\u006c":"vless","fields":{"active":{},"inactive":{},"unknown":{}}}`,
		`{"protocol":"vless","fields":{"active":{},"inactive":{},"unknown":{}},"secrets":{"uuid":{"op":"unchanged"}},"secrets":{}}`,
	} {
		resp := t012Post(t, h, cookie, []byte(body))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("duplicate outer key %q: want 400, got %d", body, resp.StatusCode)
		}
	}
}

// TestT012DuplicateInnerKeysAreTypedRefused: duplicates INSIDE the closed
// typed component shapes (bucket members, secrets update keys) belong to the
// typed category — a static 422 that never echoes the key.
func TestT012DuplicateInnerKeysAreTypedRefused(t *testing.T) {
	_, h, cookie := t012Server(t, t012NodeKeyFile(t))
	for _, body := range []string{
		`{"protocol":"vless","fields":{"active":{},"inactive":{},"unknown":{}},"secrets":{"uuid":{"op":"unchanged","op":"clear"}}}`,
	} {
		resp := t012Post(t, h, cookie, []byte(body))
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("duplicate inner key %q: want 422, got %d", body, resp.StatusCode)
		}
	}
}

// TestT012RawControlByteIsTransport400: a RAW C0 control byte inside any JSON
// string literal — label value or object key — violates RFC 8259 and is the
// transport category, like invalid UTF-8.
func TestT012RawControlByteIsTransport400(t *testing.T) {
	_, h, cookie := t012Server(t, t012NodeKeyFile(t))
	for _, body := range []string{
		strings.TrimSuffix(t012Create, "}") + `,"label":"raw	tab"}`,
		`{"protocol":"vless","lab	el":"x","fields":{"active":{},"inactive":{},"unknown":{}}}`,
	} {
		if resp := t012Post(t, h, cookie, []byte(body)); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("raw control byte body: want 400, got %d", resp.StatusCode)
		}
	}
}

func TestT012RawInvalidUTF8IsTransport400(t *testing.T) {
	_, h, cookie := t012Server(t, t012NodeKeyFile(t))
	bad := []byte(`{"protocol":"vless","fields":{"active":{"server":"a`)
	bad = append(bad, 0xff, 0xfe)
	bad = append(bad, []byte(`"},"inactive":{},"unknown":{}}`)...)
	if resp := t012Post(t, h, cookie, bad); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("raw invalid UTF-8 value: want 400, got %d", resp.StatusCode)
	}
	badKey := []byte(`{"protocol":"vless","fields":{"active":{},"inactive":{},"unknown":{}},"lab`)
	badKey = append(badKey, 0xC0, 0x80)
	badKey = append(badKey, []byte(`el":"x"}`)...)
	if resp := t012Post(t, h, cookie, badKey); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("raw invalid UTF-8 key: want 400, got %d", resp.StatusCode)
	}
	// A legal literal U+FFFD is an ordinary value (semantic domain, saved).
	ok := []byte(`{"protocol":"vless","fields":{"active":{"server":"a\uFFFDb"},"inactive":{},"unknown":{}}}`)
	if resp := t012Post(t, h, cookie, ok); resp.StatusCode != http.StatusCreated {
		t.Fatalf("legal literal U+FFFD draft: want 201, got %d", resp.StatusCode)
	}
}

func TestT012TypedLabelScalarIntegrity(t *testing.T) {
	_, h, cookie := t012Server(t, t012NodeKeyFile(t))
	accept := map[string]bool{`"\udbff\udfff"`: true, `"line\nbreak-ok"`: true, `"é"`: true}
	for _, label := range []string{
		`"\ud800"`,       // unpaired high surrogate escape — 422
		`"\udfff"`,       // unpaired surrogate escape (upper bound) — 422
		`"\udc00"`,       // lone low surrogate — 422
		`"\udbff\udfff"`, // LEGAL surrogate pair — 201
		`"line\nbreak-ok"`,
		`"\u0000"`, // NUL escape — 422 (decoded scalar-unsafe under the settled label rule)
		`"é"`,
	} {
		body := strings.TrimSuffix(t012Create, "}") + `,"label":` + label + `}`
		resp := t012Post(t, h, cookie, []byte(body))
		raw := t012Body(t, resp)
		if accept[label] {
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("legal label %s: want 201, got %d", label, resp.StatusCode)
			}
			continue
		}
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("scalar-unsafe label %q: want 422, got %d", label, resp.StatusCode)
		}
		if bytes.Contains(raw, []byte(label)) {
			t.Fatalf("422 must never echo the rejected label %q", label)
		}
	}
}

func TestT012TypedComponentRefusalsAre422(t *testing.T) {
	_, h, cookie := t012Server(t, t012NodeKeyFile(t))
	for _, body := range []string{
		`{"protocol":1,"fields":{"active":{},"inactive":{},"unknown":{}}}`,
		`{"protocol":null,"fields":{"active":{},"inactive":{},"unknown":{}}}`,
		`{"protocol":["vless"],"fields":{"active":{},"inactive":{},"unknown":{}}}`,
		`{"protocol":"vless","fields":[]}`,
		`{"protocol":"vless","fields":"x"}`,
		`{"protocol":"vless","fields":{"active":{},"inactive":{},"unknown":{},"extra":{}}}`,
		`{"protocol":"vless","fields":{"active":{},"inactive":{}}}`,
		`{"protocol":"ss","fields":{"active":{},"inactive":{},"unknown":{}}}`, // not the write enum
		// Duplicate CANONICAL bucket name — typed component refusal.
		`{"protocol":"vless","fields":{"active":{},"active":{},"inactive":{},"unknown":{}}}`,
	} {
		resp := t012Post(t, h, cookie, []byte(body))
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("typed component %q: want 422, got %d", body, resp.StatusCode)
		}
		t012Body(t, resp)
	}
}

func TestT012MalformedSyntaxAndOverLimitSize(t *testing.T) {
	_, h, cookie := t012Server(t, t012NodeKeyFile(t))
	for _, body := range []string{`{`, `{"protocol":`, `{} {}`, `[1]`, ``} {
		resp := t012Post(t, h, cookie, []byte(body))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("malformed %q: want 400, got %d", body, resp.StatusCode)
		}
	}
	// The 262144 bound is read ONCE: exactly the limit must be PROCESSED
	// (semantic content decides), limit+1 is 413 with no second read.
	pad := strings.Repeat("a", 262144-len(`{"protocol":"vless","fields":{"active":{"server":""},"inactive":{},"unknown":{}}}`))
	justRight := `{"protocol":"vless","fields":{"active":{"server":"` + pad + `"},"inactive":{},"unknown":{}}}`
	if len(justRight) != 262144 {
		t.Fatalf("padding math off: %d", len(justRight))
	}
	if resp := t012Post(t, h, cookie, []byte(justRight)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("exact-limit legal body: want 201, got %d", resp.StatusCode)
	}
	if resp := t012Post(t, h, cookie, []byte(justRight+" ")); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("limit+1: want 413, got %d", resp.StatusCode)
	}
}

// TestT012InvalidDraftSavesAndIsNeverRevalidated: semantic Invalid drafts
// SAVE with the exact stored verdict; an independent read-back proves the wire
// reported the STORED result, not a recomputed one.
func TestT012InvalidDraftSavesAndIsNeverRevalidated(t *testing.T) {
	_, h, cookie := t012Server(t, t012NodeKeyFile(t))

	// (a) unknown field + enum violation + wrong type in one draft.
	body := `{"protocol":"vless","fields":{"active":{"server":123,"unknownName":"x","serverPort":99999},"inactive":{},"unknown":{}}}`
	resp := t012Post(t, h, cookie, []byte(body))
	raw := t012Body(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("invalid draft must SAVE: want 201, got %d %s", resp.StatusCode, raw)
	}
	m := t012JSONRaw(t, raw)
	val, _ := m["validation"].(map[string]any)
	if val["state"] != "invalid-draft" {
		t.Fatalf("stored verdict must be invalid-draft: %v", val)
	}
	issues, _ := val["errors"].([]any)
	if len(issues) == 0 {
		t.Fatalf("invalid draft must carry the exact issues: %v", val)
	}
	for _, is := range issues {
		im, ok := is.(map[string]any)
		if !ok {
			t.Fatalf("issue shape must be {field,message}: %v", is)
		}
		if _, ok := im["field"].(string); !ok {
			t.Fatalf("issue.field must be a string: %v", im)
		}
		if _, ok := im["message"].(string); !ok {
			t.Fatalf("issue.message must be a string: %v", im)
		}
	}
	id, _ := m["id"].(string)
	got := t012Do(h, http.MethodGet, "/api/v1/nodes/"+id, "", nil, cookie)
	gm := t012JSON(t, got)
	if got.StatusCode != http.StatusOK || gm["revision"] != m["revision"] {
		t.Fatalf("read-back mismatch: %v vs %v", gm["revision"], m["revision"])
	}
	gval, _ := gm["validation"].(map[string]any)
	gissues, _ := gval["errors"].([]any)
	if len(gissues) != len(issues) {
		t.Fatalf("GET must expose the full historical issue set: %v vs %v", gissues, issues)
	}

	// (b) >20 unknown names: saved invalid draft (capacity applies only to the
	// canonical decoded bucket member count, never to unknown names).
	var inner []string
	for i := 0; i < 25; i++ {
		inner = append(inner, fmt.Sprintf(`"u%d":1`, i))
	}
	many := `{"protocol":"vless","fields":{"active":{},"inactive":{},"unknown":{` + strings.Join(inner, ",") + `}}}`
	if resp := t012Post(t, h, cookie, []byte(many)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("25 unknown names: want 201 saved-invalid, got %d", resp.StatusCode)
	} else {
		t012Body(t, resp)
	}

	// (c) inner duplicate keys are a SEMANTIC fact, saved — outer-only
	// duplicate scan never refuses them at transport.
	innerDup := `{"protocol":"vless","fields":{"active":{"server":"a","server":"b"},"inactive":{},"unknown":{}}}`
	if resp := t012Post(t, h, cookie, []byte(innerDup)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("inner duplicate key: want 201 (semantic, saved), got %d", resp.StatusCode)
	} else {
		t012Body(t, resp)
	}

	// (d) noncanonical inner escapes are preserved, never rejected nor
	// "cleaned": the wire captures the component bytes verbatim.
	weird := `{"protocol":"vless","fields":{"active":{"server":"a\/b\u0041\u007cd"},"inactive":{},"unknown":{}}}`
	if resp := t012Post(t, h, cookie, []byte(weird)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("noncanonical escapes: want 201 (saved as sent), got %d", resp.StatusCode)
	} else {
		t012Body(t, resp)
	}

	// (e) The verdict the wire reports IS the stored one under the composed
	// authority: a row written by a FOREIGN authority is never safe-read (and
	// therefore never re-reported) by the composition built from the compiled
	// bytes — profile drift cannot silently reinterpret stored content.
	keyPath := t012NodeKeyFile(t)
	db := t012RawStore(t)
	ss, err := store.OpenSecretStore(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	w, err := store.OpenNodeWriter(db, ss, t012ForeignAuthority(t, "hostile"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := w.CreateNodeAtomic(t012Ctx(t), store.NodeCreateInput{
		ProtocolBytes: []byte(`"vless"`),
		FieldsBytes:   []byte(`{"active":{"server":"a.example","serverPort":443},"inactive":{},"unknown":{}}`),
	})
	if err != nil {
		t.Fatalf("foreign-authority create: %v", err)
	}
	realAuth, err := store.OpenNodeAuthority(t012CompiledProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	rdr, err := store.OpenNodeReader(db, realAuth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rdr.ReadNodeSafe(t012Ctx(t), out.NodeID); !errors.Is(err, store.ErrSafeRead) {
		t.Fatalf("digest mismatch must refuse safe read, got %v", err)
	}
}
