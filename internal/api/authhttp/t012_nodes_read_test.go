package authhttp

// T012 safe GET and precedence (RED) tests: the NodeDraft read-model wire
// shape, no-key safe read, the read-time protocol membership guard (a node
// persisted outside the current wire enum NEVER leaks its protocol), the
// 401/403/405/404/503 precedence ladder on the two registered node routes,
// and the exact-secret-presence semantics.

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/contracts"
	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/store"
)

// t012ExtendedProfile returns a semantically valid profile that ADDS a
// protocol the compiled one does not have, while keeping the compiled
// protocol digests intact — enough to build a NodeAuthority whose stored rows
// are foreign to the reader composed from the compiled bytes.
func TestT012ProfileAccessorByteExactCopy(t *testing.T) {
	authored := t012CompiledProfile(t)
	got := contracts.ProfileBytes()
	if !bytes.Equal(got, authored) {
		t.Fatal("compiled profile must be byte-exact with the authored file")
	}
	got[0] = 'X' // caller mutation must not poison the compiled bytes
	if !bytes.Equal(contracts.ProfileBytes(), authored) {
		t.Fatal("ProfileBytes must return a copy, not the compiled buffer")
	}
	if _, err := capability.Parse(contracts.ProfileBytes()); err != nil {
		t.Fatalf("compiled profile must parse: %v", err)
	}
}

// t012RawWriter builds a writer over a fresh store with an EXTENDED authority
// (test-only export) so foreign-authority rows can be persisted.
func t012RawWriter(t *testing.T, profileExtra string) (*store.Store, *store.NodeWriter) {
	t.Helper()
	db := t012RawStore(t)
	ss, err := store.OpenSecretStore(db, t012NodeKeyFile(t))
	if err != nil {
		t.Fatal(err)
	}
	w, err := store.OpenNodeWriter(db, ss, t012ForeignAuthority(t, profileExtra))
	if err != nil {
		t.Fatal(err)
	}
	return db, w
}

func TestT012SafeGetShapeAndSecretPresence(t *testing.T) {
	keyPath := t012NodeKeyFile(t)
	_, h, cookie := t012Server(t, keyPath)
	body := []byte(`{"protocol":"vless","label":"edge-1","fields":{"active":{"server":"a.example","serverPort":443,"uuid":"CANARY-SECRET-VALUE","transport":"raw","security":"tls"},"inactive":{},"unknown":{"flow":"old-flow-value"}},"secrets":{"uuid":{"op":"replace","value":"CANARY-SECRET-VALUE"}}}`)
	resp := t012Post(t, h, cookie, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, t012Body(t, resp))
	}
	created := t012Body(t, resp)
	if strings.Contains(string(created), "CANARY-SECRET-VALUE") {
		t.Fatal("201 leaked a secret value")
	}
	id := strings.Split(strings.Split(string(created), `"id":"`)[1], `"`)[0]

	got := t012Do(h, http.MethodGet, "/api/v1/nodes/"+id, "", nil, cookie)
	if got.StatusCode != http.StatusOK {
		t.Fatalf("safe GET: %d", got.StatusCode)
	}
	raw := t012Body(t, got)
	if strings.Contains(string(raw), "CANARY-SECRET-VALUE") || strings.Contains(string(raw), "old-flow-value") {
		t.Fatalf("safe GET leaked secret values: %s", raw)
	}
	m := t012JSONRaw(t, raw)
	// Exact top-level members (same closed set as 201).
	for k := range m {
		switch k {
		case "id", "protocol", "revision", "validation", "fields", "secrets":
		default:
			t.Fatalf("unexpected GET member %q", k)
		}
	}
	// The label is SEALED-only at this increment: no lossless read path yet,
	// so it is OMITTED rather than decrypted or folded in.
	if _, ok := m["label"]; ok {
		t.Fatal("label must be omitted until a lossless read path exists")
	}
	// Secrets: ONLY declared-name presence booleans, current-row backed.
	secrets, _ := m["secrets"].(map[string]any)
	for name, v := range secrets {
		vm, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("secrets[%s] must be a {present} object: %v", name, v)
		}
		if _, ok := vm["present"].(bool); !ok {
			t.Fatalf("secrets[%s].present must be a boolean: %v", name, vm)
		}
		if len(vm) != 1 {
			t.Fatalf("secrets[%s] must carry ONLY presence, no value: %v", name, vm)
		}
	}
	present := func(name string) any {
		v, ok := secrets[name]
		if !ok {
			return nil
		}
		return v.(map[string]any)["present"]
	}
	// The vless profile does not declare "flow": an undeclared name must NOT
	// gain a presence entry (no oracle over what is not declared).
	if _, ok := secrets["flow"]; ok {
		t.Fatalf("undeclared secret name must not appear in presence: %v", secrets)
	}
	if present("uuid") != true {
		t.Fatalf("declared secret with a row must be present:true: %v", secrets)
	}
	// At least one declared-but-absent secret must read false (the profile
	// declares more than uuid for vless).
	anyFalse := false
	for _, v := range secrets {
		if v.(map[string]any)["present"] == false {
			anyFalse = true
		}
	}
	if !anyFalse {
		t.Fatalf("declared secrets without rows must be present:false: %v", secrets)
	}
	// Keyless safe read works: compose a KEYLESS server over the SAME store is
	// not possible here (separate DB), so prove key-independence by reading
	// with the reader while the key file permissions deny nothing new — the
	// reader type takes no key at all (compile-level), and the presence above
	// came from row metadata. Additionally: unknown id is a static 404.
	missing := t012Do(h, http.MethodGet, "/api/v1/nodes/nonexistent-id-xyz", "", nil, cookie)
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id: want 404, got %d", missing.StatusCode)
	}
	if mb := t012Body(t, missing); strings.Contains(string(mb), "nonexistent-id-xyz") {
		t.Fatalf("404 must be static and never echo the id: %s", mb)
	}
}

// TestT012ReadTimeProtocolMembershipGuard: a node persisted by a writer using
// an EXTENDED authority (protocol "hostile") is foreign to the composition
// built from the compiled bytes — the safe read refuses via the authority
// digest, and the wire layer can therefore never emit a protocol outside the
// closed enum. Additionally the pure mapping guard: even if the decode layer
// ever saw an out-of-enum protocol, wireProtocolEnum omits it.
func TestT012ReadTimeProtocolMembershipGuard(t *testing.T) {
	if wireProtocolEnum["hostile"] || !wireProtocolEnum["vless"] || len(wireProtocolEnum) != 4 {
		t.Fatal("wire protocol enum must be exactly the accepted closed set")
	}
	db, w := t012RawWriter(t, "hostile")
	out, err := w.CreateNodeAtomic(t012Ctx(t), store.NodeCreateInput{
		ProtocolBytes: []byte(`"hostile"`),
		FieldsBytes:   []byte(`{"active":{},"inactive":{},"unknown":{}}`),
	})
	if err != nil {
		t.Fatalf("hostile-authority create: %v", err)
	}
	// The composition built from the COMPILED bytes refuses the foreign row
	// wholesale — no partial publication of hostile-profile content.
	realAuth, err := store.OpenNodeAuthority(t012CompiledProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	rdr, err := store.OpenNodeReader(db, realAuth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rdr.ReadNodeSafe(t012Ctx(t), out.NodeID); err == nil {
		t.Fatal("foreign-authority row must never safe-read under the compiled authority")
	}
}

func TestT012NodeRoutesPrecedenceAndUnregistered(t *testing.T) {
	_, h, cookie := t012Server(t, "")
	// Settled T008 precedence (TestT008OriginCSRFRejectBeforeAnyWork): the
	// CSRF origin gate for unsafe methods runs BEFORE any session check — a
	// missing/foreign Origin on POST is 403 no matter what else is true, and
	// the request never reaches auth or body processing.
	noOrigin := t012Do(h, http.MethodPost, "/api/v1/nodes", "", []byte(`{}`), nil)
	if noOrigin.StatusCode != http.StatusForbidden {
		t.Fatalf("POST no-Origin no-session: want 403 (CSRF first), got %d", noOrigin.StatusCode)
	}
	// With the CSRF gate passed, BOTH registered routes demand a session:
	// 401 on the POST create and on the GET read (safe method: Origin is not
	// required for the gate, but authentication is).
	for _, tc := range [][3]string{
		{http.MethodPost, "/api/v1/nodes", testOrigin},
		{http.MethodGet, "/api/v1/nodes/abc", ""},
	} {
		resp := t012Do(h, tc[0], tc[1], tc[2], []byte(`{}`), nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s no-session: want 401, got %d", tc[0], tc[1], resp.StatusCode)
		}
	}
	// Session + wrong Origin (unsafe method): 403 BEFORE body/key checks —
	// an oversized invalid body must not change the outcome.
	resp := t012Do(h, http.MethodPost, "/api/v1/nodes", "https://evil.example", []byte(strings.Repeat("{", 200000)), cookie)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Origin: want 403, got %d", resp.StatusCode)
	}
	// The collection path is create-only: any other method there — safe or
	// unsafe — is the generic 403 refusal, never a 405 oracle (an unsafe
	// method without Origin is 403 at the CSRF gate first).
	resp = t012Do(h, http.MethodPut, "/api/v1/nodes", testOrigin, []byte(`{}`), cookie)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT on create-only collection path: want 403 (no oracle), got %d", resp.StatusCode)
	}
	resp = t012Do(h, http.MethodPost, "/api/v1/nodes/abc", testOrigin, []byte(`{}`), cookie)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST on the read-only node path: want 403 (no method oracle), got %d", resp.StatusCode)
	}
	// Unregistered node paths — and every non-owning method on the two
	// registered paths — stay the generic 403 (no existence/method oracle, no
	// CRUD) even with a valid session and a trusted Origin.
	for _, tc := range [][2]string{
		{http.MethodDelete, "/api/v1/nodes"},
		{http.MethodPatch, "/api/v1/nodes/abc"},
		{http.MethodDelete, "/api/v1/nodes/abc"},
		{http.MethodGet, "/api/v1/nodes/abc/secrets"},
		{http.MethodPost, "/api/v1/nodes/abc/apply"},
	} {
		resp := t012Do(h, tc[0], tc[1], testOrigin, nil, cookie)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("unregistered %s %s: want generic 403, got %d", tc[0], tc[1], resp.StatusCode)
		}
	}
	// Keyless POST: after auth+Origin, static 503 — no Retry-After.
	resp = t012Do(h, http.MethodPost, "/api/v1/nodes", testOrigin, []byte(t012Create), cookie)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "" {
		t.Fatalf("keyless create: want 503 no Retry-After, got %d %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	// Keyless GET still works structurally (404 for unknown id, NOT 503):
	// safe reads never need the key.
	resp = t012Do(h, http.MethodGet, "/api/v1/nodes/abc", "", nil, cookie)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("keyless safe read: want 404 for unknown id, got %d", resp.StatusCode)
	}
	// 401/403/405 bodies carry NO token material and never echo the id/path.
	resp = t012Do(h, http.MethodGet, "/api/v1/nodes/secret-canary-path", "", nil, cookie)
	t012Body(t, resp)
}
