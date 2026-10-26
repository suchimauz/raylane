package authhttp

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// This file guards the RAW-BYTES input contract (G1) and the single-value
// session-cookie contract (G2) of the management API.
//
// G1 — invalid UTF-8 is refused on the RAW body, BEFORE the JSON decoder can
// silently replace every invalid byte with U+FFFD. The accepted reference
// behaviour is auth.ValidUsername/ValidPassword over []byte: a credential
// whose raw bytes are not valid UTF-8 is not a valid credential. Waiting for
// the decoder would compare the REPLACED string, which (a) accepts
// originally-invalid input and (b) creates an alias between two different raw
// usernames. Valid multibyte credentials (2-4 byte sequences, including
// astral ones and a LITERAL U+FFFD) must keep working with exact bytes.
//
// G2 — exactly ONE raylane_session cookie value may reach lookup/revoke. A
// duplicated or ambiguous name across EVERY Cookie header (both orders,
// valid+garbage and valid+valid, one header or several, or a smuggled
// malformed-name form Go's lenient request parser silently drops) is refused
// with 401 BEFORE any lookup or revoke, while the Origin 403 stays FIRST.

// --- G1: raw invalid UTF-8 is refused before decode -----------------------

// invalidRawCredentialBytes are individually invalid in a UTF-8 stream: a
// continuation byte with no lead byte, a truncated 2-byte lead, a 3-byte lead
// with the following byte being ASCII, and an over-long NUL encoding.
var invalidRawCredentialBytes = []struct {
	name string
	raw  string
}{
	{"lone continuation ff", "\xff"},
	{"lone continuation fe", "\xfe"},
	{"lone continuation 80", "\x80"},
	{"truncated 2-byte lead c3", "adm\xc3"},
	{"3-byte lead over ASCII e2 71", "u\xe2q"},
	{"over-long NUL c0 80", "u\xc0\x80"},
}

func TestBujG1RawInvalidUTF8LoginRefusedBeforeDecode(t *testing.T) {
	// An identity whose username literally contains U+FFFD (a legal code
	// point). Under replacement-decoding a raw 0xFF byte decodes to exactly
	// this string, so the identity is the alias a decoder bug would match.
	//
	// The bodies are hand-built RAW BYTE strings: json.Marshal would itself
	// replace the invalid byte with U+FFFD while ENCODING, so the request
	// would carry a legal literal-replacement code point instead of the raw
	// bytes a client actually sends.
	srv, h := newTestServer(t, "")
	bootstrapAdmin(t, srv, "adm\xef\xbf\xbdin", "correct-password")
	for _, tc := range invalidRawCredentialBytes {
		t.Run(tc.name+"/username", func(t *testing.T) {
			body := `{"username":"adm` + tc.raw + `in","password":"correct-password"}`
			resp := do(h, http.MethodPost, "/api/v1/session", testOrigin, body, nil)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("raw invalid-UTF-8 username accepted: got %d want 401 (no decoder replacement may authenticate it)", resp.StatusCode)
			}
			if len(resp.Cookies()) != 0 {
				t.Fatalf("session cookie set for raw invalid-UTF-8 username")
			}
		})
		t.Run(tc.name+"/password", func(t *testing.T) {
			body := `{"username":"adm\xef\xbf\xbdin","password":"p` + tc.raw + `"}`
			resp := do(h, http.MethodPost, "/api/v1/session", testOrigin, body, nil)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("raw invalid-UTF-8 password accepted: got %d want 401", resp.StatusCode)
			}
			if len(resp.Cookies()) != 0 {
				t.Fatalf("session cookie set for raw invalid-UTF-8 password")
			}
		})
	}
}

func TestBujG1RawInvalidUTF8BootstrapRefusedAndNotPersisted(t *testing.T) {
	// The local bootstrap path must refuse the raw bytes before decode, so no
	// replacement identity is ever created (and the token is burned).
	for _, tc := range invalidRawCredentialBytes {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newTestServer(t, "")
			m := srv.ManagementHandler()
			tok := issueToken(t, m)
			body := `{"username":"adm` + tc.raw + `in","password":"p","token":"` + tok + `"}`
			resp := do(m, http.MethodPost, "/api/v1/bootstrap", "", body, nil)
			resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent {
				t.Fatalf("raw invalid-UTF-8 bootstrap accepted and persisted: %q", tc.name)
			}
			if hasAdminIdentity(t, srv) {
				t.Fatalf("identity persisted from raw invalid-UTF-8 bootstrap: %q", tc.name)
			}
		})
	}
}

func TestBujG1BootstrapTokenFieldRefusesRawInvalidUTF8(t *testing.T) {
	// A raw invalid byte inside the token VALUE must be refused without any
	// replacement aliasing against a token containing a literal U+FFFD (a
	// legal, though never-issued, code point in a token string).
	srv, _ := newTestServer(t, "")
	m := srv.ManagementHandler()
	tok := issueToken(t, m)
	for _, tc := range invalidRawCredentialBytes {
		body := `{"username":"adm","password":"p","token":"` + tok[:2] + tc.raw + `"}`
		resp := do(m, http.MethodPost, "/api/v1/bootstrap", "", body, nil)
		resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			t.Fatalf("raw invalid-UTF-8 token accepted: %q", tc.name)
		}
	}
	if hasAdminIdentity(t, srv) {
		t.Fatal("identity persisted from raw invalid-UTF-8 token")
	}
}

// hasAdminIdentity reports whether the store currently holds a well-formed
// admin identity, through the SAME store read path the login handler uses.
func hasAdminIdentity(t *testing.T, srv *Server) bool {
	t.Helper()
	_, err := srv.store.AdminIdentity(context.Background())
	return err == nil
}

func TestBujG1ValidMultibyteCredentialsWorkWithExactBytes(t *testing.T) {
	// Positive controls: every legal multibyte form (2/3/4-byte sequences,
	// astral pairs, and a LITERAL U+FFFD code point) must keep authenticating,
	// and must NOT authenticate a different multibyte username (no cross-alias
	// in the other direction either).
	type tc struct{ name, username, password string }
	cases := []tc{
		{"2-byte cyrillic", "оператор", "пароль-секрет"},
		{"3-byte cjk", "管理者", "合言葉123"},
		{"4-byte astral pair", "𝄞😀", "musical😀key"},
		{"literal U+FFFD", "adm\xef\xbf\xbdin", "correct-password"},
		{"latin1-range 2-byte", "caf\xc3\xa9", "pass\xc3\xa9word"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// One identity per store: a fresh server per case.
			srv, h := newTestServer(t, "")
			bootstrapAdmin(t, srv, c.username, c.password)
			resp := login(t, h, testOrigin, c.username, c.password)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("valid multibyte login rejected: got %d want 204", resp.StatusCode)
			}
			// A DIFFERENT multibyte username must not authenticate: exact
			// bytes, not a normalized form.
			other := c.username + "x"
			bad := login(t, h, testOrigin, other, c.password)
			bad.Body.Close()
			if bad.StatusCode != http.StatusUnauthorized {
				t.Fatalf("different multibyte username accepted: got %d want 401", bad.StatusCode)
			}
			// The issued session must be usable and revocable (exact bytes
			// travelled the whole path, no truncation at a code-point edge).
			cookie := loginCookie(t, resp)
			state := do(h, http.MethodGet, "/api/v1/state", "", "", func(r *http.Request) { r.AddCookie(cookie) })
			defer state.Body.Close()
			if state.StatusCode != http.StatusOK {
				t.Fatalf("state with multibyte-created session: got %d want 200", state.StatusCode)
			}
			out := do(h, http.MethodDelete, "/api/v1/session", testOrigin, "", func(r *http.Request) { r.AddCookie(cookie) })
			defer out.Body.Close()
			if out.StatusCode != http.StatusNoContent {
				t.Fatalf("logout with multibyte-created session: got %d want 204", out.StatusCode)
			}
		})
	}
}

func TestBujG1BodyLimitsUnchanged(t *testing.T) {
	// The settled body-limit contract must survive the UTF-8 gate: exactly
	// loginBodyLimit bytes is processed, one byte more is 413 — including a
	// body that is entirely multibyte (so the limit stays BYTES, not runes).
	srv, h := newTestServer(t, "")
	bootstrapAdmin(t, srv, "u", "p")
	at := strings.Repeat("é", loginBodyLimit/2) // exactly loginBodyLimit bytes
	resp := do(h, http.MethodPost, "/api/v1/session", testOrigin, at, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("exactly-limit body status = %d want 401 (processed, wrong credential)", resp.StatusCode)
	}
	tooBig := strings.Repeat("é", loginBodyLimit/2+1)
	over := do(h, http.MethodPost, "/api/v1/session", testOrigin, tooBig, nil)
	over.Body.Close()
	if over.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("limit+1 body status = %d want 413", over.StatusCode)
	}
}

// --- G2: exactly one session cookie value may reach lookup/revoke ---------

func TestBujG2DuplicateSessionCookieRefusedOnAllPaths(t *testing.T) {
	// Every duplicate/ambiguous arrangement must be a 401 on BOTH the
	// authenticated GET /state and the DELETE /session, and the ORIGINAL
	// session must still work afterwards (no revoke happened on reject).
	srv, h := newTestServer(t, "")
	bootstrapAdmin(t, srv, "operator", "synthetic-password")
	resp := login(t, h, testOrigin, "operator", "synthetic-password")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	resp.Body.Close()
	cookie := loginCookie(t, resp)
	value := cookie.Value

	// A second session is used as the "valid second value" case.
	resp2 := login(t, h, testOrigin, "operator", "synthetic-password")
	resp2.Body.Close()
	second := loginCookie(t, resp2)

	name := sessionCookieName
	arrangements := []struct {
		name    string
		cookies []string // each element is one full Cookie header value
	}{
		{"same header valid+garbage", []string{name + "=" + value + "; " + name + "=garbage"}},
		{"same header garbage+valid", []string{name + "=garbage; " + name + "=" + value}},
		{"same header valid+valid", []string{name + "=" + value + "; " + name + "=" + second.Value}},
		{"two headers valid+garbage", []string{name + "=" + value, name + "=garbage"}},
		{"two headers garbage+valid", []string{name + "=garbage", name + "=" + value}},
		{"two headers valid+valid", []string{name + "=" + value, name + "=" + second.Value}},
		{"malformed name with space", []string{name + "=" + value + "; " + name + " =evil"}},
		{"bare name no value", []string{name + "=" + value + "; " + name}},
		{"header only duplicate", []string{name + "=only1", name + "=only2"}},
	}
	for _, a := range arrangements {
		t.Run(a.name, func(t *testing.T) {
			for _, m := range []struct {
				method, target string
				want           int
			}{
				{http.MethodGet, "/api/v1/state", http.StatusUnauthorized},
				{http.MethodDelete, "/api/v1/session", http.StatusUnauthorized},
			} {
				req := do(h, m.method, m.target, testOrigin, "", func(r *http.Request) {
					for _, c := range a.cookies {
						r.Header.Add("Cookie", c)
					}
				})
				req.Body.Close()
				if req.StatusCode != m.want {
					t.Fatalf("%s %s with duplicated cookie = %d want %d (must be refused BEFORE lookup/revoke)",
						m.method, m.target, req.StatusCode, m.want)
				}
			}
			// The ORIGINAL single-cookie session must still authenticate: the
			// reject path never revoked it.
			after := do(h, http.MethodGet, "/api/v1/state", "", "", func(r *http.Request) { r.AddCookie(cookie) })
			defer after.Body.Close()
			if after.StatusCode != http.StatusOK {
				t.Fatalf("original session revoked by a duplicated-cookie reject: %d", after.StatusCode)
			}
		})
	}
}

func TestBujG2SingleCookieStillWorks(t *testing.T) {
	// Positive control: one unambiguous cookie value authenticates GET /state
	// and a single DELETE /session revokes exactly that session.
	srv, h := newTestServer(t, "")
	bootstrapAdmin(t, srv, "operator", "synthetic-password")
	resp := login(t, h, testOrigin, "operator", "synthetic-password")
	resp.Body.Close()
	cookie := loginCookie(t, resp)
	state := do(h, http.MethodGet, "/api/v1/state", "", "", func(r *http.Request) { r.AddCookie(cookie) })
	state.Body.Close()
	if state.StatusCode != http.StatusOK {
		t.Fatalf("single cookie GET /state = %d want 200", state.StatusCode)
	}
	// An unrelated other cookie in the SAME header must not disturb it.
	state2 := do(h, http.MethodGet, "/api/v1/state", "", "", func(r *http.Request) {
		r.Header.Add("Cookie", "theme=dark; "+cookie.Name+"="+cookie.Value+"; lang=ru")
	})
	state2.Body.Close()
	if state2.StatusCode != http.StatusOK {
		t.Fatalf("single session cookie among neighbours = %d want 200", state2.StatusCode)
	}
	out := do(h, http.MethodDelete, "/api/v1/session", testOrigin, "", func(r *http.Request) { r.AddCookie(cookie) })
	out.Body.Close()
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("single cookie DELETE /session = %d want 204", out.StatusCode)
	}
	again := do(h, http.MethodGet, "/api/v1/state", "", "", func(r *http.Request) { r.AddCookie(cookie) })
	again.Body.Close()
	if again.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked session still authenticates: %d want 401", again.StatusCode)
	}
}

func TestBujG2OriginForbiddenStaysBeforeCookieRules(t *testing.T) {
	// A bad Origin on an unsafe method is rejected with 403 BEFORE any cookie
	// examination, even when the cookie jar is duplicated.
	srv, h := newTestServer(t, "")
	bootstrapAdmin(t, srv, "operator", "synthetic-password")
	resp := login(t, h, testOrigin, "operator", "synthetic-password")
	resp.Body.Close()
	cookie := loginCookie(t, resp)
	dup := do(h, http.MethodDelete, "/api/v1/session", "https://foreign.example", "", func(r *http.Request) {
		r.Header.Add("Cookie", cookie.Name+"="+cookie.Value)
		r.Header.Add("Cookie", cookie.Name+"=garbage")
	})
	dup.Body.Close()
	if dup.StatusCode != http.StatusForbidden {
		t.Fatalf("duplicate cookie with foreign Origin = %d want 403 (Origin check first)", dup.StatusCode)
	}
}
