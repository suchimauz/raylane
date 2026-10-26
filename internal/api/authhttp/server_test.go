package authhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suchimauz/raylane/internal/api/auth"
	"github.com/suchimauz/raylane/internal/store"
)

// newTestServer opens a REAL store in t.TempDir and returns a Server plus the
// LAN handler. Every test below drives the real handlers over httptest with
// real store transactions — no source-text assertions.
func newTestServer(t *testing.T, origin string) (*Server, http.Handler) {
	t.Helper()
	if origin == "" {
		origin = "https://manage.test"
	}
	cfg := Config{
		ManagementListen: "127.0.0.1:0",
		TrustedOrigin:    origin,
		TLSCertPath:      "unused",
		TLSKeyPath:       "unused",
		DBPath:           filepath.Join(t.TempDir(), "state.db"),
		UnixSocketDir:    t.TempDir(),
	}
	db, err := store.Open(context.Background(), cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	srv, err := NewServer(cfg, db)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, srv.Handler()
}

// bootstrapAdmin drives the SAME store path the HTTP bootstrap handler uses.
func bootstrapAdmin(t *testing.T, srv *Server, username, password string) {
	t.Helper()
	if err := auth.CreateIdentity(context.Background(), srv.store, []byte(username), []byte(password)); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
}

func do(h http.Handler, method, target, origin, body string, extra func(*http.Request)) *http.Response {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	req.RemoteAddr = "192.0.2.7:1234"
	if extra != nil {
		extra(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func login(t *testing.T, h http.Handler, origin, username, password string) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	return do(h, http.MethodPost, "/api/v1/session", origin, string(body), nil)
}

func loginCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatalf("no session cookie in response (status %d)", resp.StatusCode)
	return nil
}

func TestT008LoginCookieExactSettledAttributes(t *testing.T) {
	srv, h := newTestServer(t, "")
	bootstrapAdmin(t, srv, "admin", "correct horse battery staple")
	resp := login(t, h, "https://manage.test", "admin", "correct horse battery staple")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("login status = %d, want 204", resp.StatusCode)
	}
	c := loginCookie(t, resp)
	if !c.Secure || !c.HttpOnly {
		t.Fatalf("cookie Secure/HttpOnly = %v/%v, want true/true", c.Secure, c.HttpOnly)
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie SameSite = %v, want Strict", c.SameSite)
	}
	if c.Domain != "" {
		t.Fatalf("cookie Domain = %q, want host-only (empty)", c.Domain)
	}
	if c.Path != "/api/v1" {
		t.Fatalf("cookie Path = %q, want /api/v1", c.Path)
	}
	// Statefulness through the REAL handler: cookie -> 200, none -> 401.
	if code := do(h, http.MethodGet, "/api/v1/state", "", "", func(r *http.Request) { r.AddCookie(c) }).StatusCode; code != http.StatusOK {
		t.Fatalf("GET /state with session = %d, want 200", code)
	}
	if code := do(h, http.MethodGet, "/api/v1/state", "", "", nil).StatusCode; code != http.StatusUnauthorized {
		t.Fatalf("GET /state without session = %d, want 401", code)
	}
}

// TestT008LoginFailureIsGenericNoOracle: a wrong password, a wrong username
// and the no-admin-yet state all produce the IDENTICAL public outcome; only
// the per-request requestId differs (required by the contract).
func TestT008LoginFailureIsGenericNoOracle(t *testing.T) {
	srv, h := newTestServer(t, "")
	before := problemOf(t, login(t, h, "https://manage.test", "whoever", "whatever"))
	bootstrapAdmin(t, srv, "admin", "correct horse battery staple")
	wrongPass := problemOf(t, login(t, h, "https://manage.test", "admin", "wrong password here"))
	wrongUser := problemOf(t, login(t, h, "https://manage.test", "no-such-user", "correct horse battery staple"))
	for _, p := range []problem{before, wrongPass, wrongUser} {
		if p.RequestID == "" {
			t.Fatal("problem body must carry a non-empty requestId")
		}
	}
	if p1, p2 := before.RequestID, wrongPass.RequestID; p1 == p2 || p2 == wrongUser.RequestID {
		t.Fatal("requestId must be fresh per request")
	}
	if before.Code != wrongPass.Code || before.Code != wrongUser.Code {
		t.Fatalf("codes differ: %q / %q / %q — existence oracle", before.Code, wrongPass.Code, wrongUser.Code)
	}
	if before.Message != wrongPass.Message || before.Message != wrongUser.Message {
		t.Fatal("messages differ across failure categories — oracle")
	}
}

// TestT008OriginCSRFRejectBeforeAnyWork: missing, null, foreign or merely
// SIMILAR origin is a 403 forbidden with the generic body, before any session
// or credential processing; the received origin is never echoed.
func TestT008OriginCSRFRejectBeforeAnyWork(t *testing.T) {
	srv, h := newTestServer(t, "https://manage.test")
	bootstrapAdmin(t, srv, "admin", "correct horse battery staple")
	cases := map[string]string{
		"missing":      "",
		"null":         "null",
		"foreign":      "https://evil.test",
		"similar":      "https://manage.test.evil.test",
		"wrong-scheme": "http://manage.test",
	}
	body := `{"username":"admin","password":"correct horse battery staple"}`
	for name, origin := range cases {
		resp := do(h, http.MethodPost, "/api/v1/session", origin, body, nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: status = %d, want 403", name, resp.StatusCode)
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		var p problem
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("%s: body %q: %v", name, raw, err)
		}
		if p.Code != codeForbidden || p.Message != msgForbidden {
			t.Fatalf("%s: problem = %+v, want generic forbidden", name, p)
		}
		if strings.Contains(string(raw), "evil") || strings.Contains(string(raw), "manage") {
			t.Fatalf("%s: body echoes the origin: %s", name, raw)
		}
	}
}

// TestT008LANHandlerNeverRoutesBootstrap: the bootstrap routes are physically
// ABSENT from the LAN handler; a LAN POST to them is the same generic 403 as
// any other unknown path (indistinguishable, no existence oracle — the
// settled V4 contract makes LAN bootstrap/unknown protected paths a 403, not
// a 404).
func TestT008LANHandlerNeverRoutesBootstrap(t *testing.T) {
	_, h := newTestServer(t, "")
	unknown := do(h, http.MethodPost, "/api/v1/bootstrap", "https://manage.test", `{}`, nil)
	bogus := do(h, http.MethodPost, "/api/v1/no-such-route", "https://manage.test", `{}`, nil)
	if unknown.StatusCode != http.StatusForbidden || bogus.StatusCode != http.StatusForbidden {
		t.Fatalf("LAN bootstrap=%d bogus=%d, want 403/403", unknown.StatusCode, bogus.StatusCode)
	}
	// Identical public shape: only requestId differs.
	pi, pj := readProblem(t, unknown), readProblem(t, bogus)
	if pi.Code != pj.Code || pi.Message != pj.Message {
		t.Fatalf("bootstrap 403 differs from generic 403: %+v vs %+v", pi, pj)
	}
	// Same over the real HTTPS listener, with a spoofed Origin header set to
	// the trusted value: locality is decided by WHICH listener answers.
	ts := httptest.NewTLSServer(h)
	defer ts.Close()
	client := ts.Client()
	post, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/bootstrap", strings.NewReader(`{"token":"x","username":"a","password":"bb"}`))
	if err != nil {
		t.Fatal(err)
	}
	post.Header.Set("Origin", "https://manage.test")
	resp, err := client.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("TLS /bootstrap = %d, want 403 (route absent on LAN)", resp.StatusCode)
	}
}

func TestT008RequestIdentity(t *testing.T) {
	_, h := newTestServer(t, "")
	cases := []struct {
		name   string
		sent   string
		wantEq bool
	}{
		{"absent", "", false},
		{"conforming", "corr-42_A.b:c", true},
		{"oversized", strings.Repeat("a", 129), false},
		{"bad-pattern", "id with spaces", false},
	}
	for _, tc := range cases {
		resp := do(h, http.MethodGet, "/api/v1/state", "", "", func(r *http.Request) {
			if tc.sent != "" {
				r.Header.Set("X-Request-Id", tc.sent)
			}
		})
		got := resp.Header.Get("X-Request-Id")
		if got == "" || len(got) > maxRequestIDLen || validRequestID(got) == "" {
			t.Fatalf("%s: response X-Request-Id %q is not conforming", tc.name, got)
		}
		if tc.wantEq && got != tc.sent {
			t.Fatalf("%s: X-Request-Id = %q, want echo of %q", tc.name, got, tc.sent)
		}
		if !tc.wantEq && tc.sent != "" && got == tc.sent {
			t.Fatalf("%s: non-conforming id %q echoed unchanged", tc.name, tc.sent)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("%s: Cache-Control = %q, want no-store", tc.name, cc)
		}
		if resp.Header.Get("Pragma") != "no-cache" {
			t.Fatalf("%s: Pragma no-cache missing", tc.name)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: nosniff missing", tc.name)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			p := readProblem(t, resp)
			if p.RequestID != got {
				t.Fatalf("%s: body requestId %q != header %q", tc.name, p.RequestID, got)
			}
		}
	}
	// CRLF in a client id must NEVER reach the response (header-injection
	// surface): httptest refuses to write a corrupted header, so assert via
	// the recorder that the emitted value is always conforming.
	resp := do(h, http.MethodGet, "/api/v1/state", "", "", func(r *http.Request) {
		r.Header["X-Request-Id"] = []string{"a\r\nSet-Cookie: evil=1"}
	})
	if v := resp.Header.Get("X-Request-Id"); validRequestID(v) == "" {
		t.Fatalf("CRLF-bearing id leaked: %q", v)
	}
	ids := map[string]bool{}
	for i := 0; i < 50; i++ {
		id := do(h, http.MethodGet, "/api/v1/state", "", "", nil).Header.Get("X-Request-Id")
		if ids[id] {
			t.Fatalf("requestId %q repeated", id)
		}
		ids[id] = true
	}
}

// TestT008LogoutExpiresCookieWithSameAttributes: empty value, Max-Age=0 and
// the SAME Path/Secure/HttpOnly/SameSite as it was set with.
func TestT008LogoutExpiresCookieWithSameAttributes(t *testing.T) {
	srv, h := newTestServer(t, "")
	bootstrapAdmin(t, srv, "admin", "correct horse battery staple")
	c := loginCookie(t, login(t, h, "https://manage.test", "admin", "correct horse battery staple"))
	resp := do(h, http.MethodDelete, "/api/v1/session", "https://manage.test", "", func(r *http.Request) { r.AddCookie(c) })
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", resp.StatusCode)
	}
	cs := resp.Cookies()
	var found http.Cookie
	for i := range cs {
		if cs[i].Name == sessionCookieName {
			found = *cs[i]
		}
	}
	if found.Name == "" {
		t.Fatal("logout must re-send the cookie to expire it")
	}
	// The WIRE form must carry Max-Age=0 (delete). Go's cookie PARSER maps the
	// "Max-Age=0" attribute to the internal delete marker MaxAge=-1, so the
	// parsed value is negative; assert the raw header says Max-Age=0 and the
	// parsed marker is the delete form (MaxAge<0), never a positive lifetime.
	if found.Value != "" || !strings.Contains(resp.Header.Get("Set-Cookie"), "Max-Age=0") || found.MaxAge > 0 {
		t.Fatalf("expiry cookie = %q Max-Age %d, header %q, want empty/Max-Age=0/delete", found.Value, found.MaxAge, resp.Header.Get("Set-Cookie"))
	}
	if found.Path != c.Path || found.Secure != c.Secure || found.HttpOnly != c.HttpOnly || found.SameSite != c.SameSite {
		t.Fatalf("expiry attributes %v differ from session attributes %v", found, *c)
	}
	if code := do(h, http.MethodGet, "/api/v1/state", "", "", func(r *http.Request) { r.AddCookie(c) }).StatusCode; code != http.StatusUnauthorized {
		t.Fatalf("state after logout = %d, want 401", code)
	}
}

// TestT008SessionIdleExpiryUsesServerClock drives the server clock field: one
// tick before the idle boundary the session is alive, at the boundary dead.
func TestT008SessionIdleExpiryUsesServerClock(t *testing.T) {
	srv, h := newTestServer(t, "")
	bootstrapAdmin(t, srv, "admin", "correct horse battery staple")
	now := time.Unix(1700000000, 0)
	srv.now = func() time.Time { return now }
	c := loginCookie(t, login(t, h, "https://manage.test", "admin", "correct horse battery staple"))
	state := func() int {
		return do(h, http.MethodGet, "/api/v1/state", "", "", func(r *http.Request) { r.AddCookie(c) }).StatusCode
	}
	now = now.Add(sessionIdleSeconds*time.Second - time.Millisecond)
	if state() != http.StatusOK {
		t.Fatal("session expired before the idle boundary")
	}
	now = now.Add(time.Millisecond)
	if state() != http.StatusUnauthorized {
		t.Fatal("session survived past the idle boundary")
	}
}

// TestT008LimiterBoundaryAndRetryAfter: burst 5, then 429 with integer
// Retry-After; a different peer is unaffected; the body limit boundary is
// exact.
func TestT008LimiterBoundaryAndRetryAfter(t *testing.T) {
	srv, h := newTestServer(t, "")
	bootstrapAdmin(t, srv, "admin", "correct horse battery staple")
	attempt := func(body, peer string) *http.Response {
		return do(h, http.MethodPost, "/api/v1/session", "https://manage.test", body, func(r *http.Request) {
			r.RemoteAddr = peer
		})
	}
	for i := 0; i < limitBurst; i++ {
		if c := attempt(`{"username":"u","password":"p"}`, "198.51.100.4:5").StatusCode; c != http.StatusUnauthorized {
			t.Fatalf("attempt %d inside burst: status = %d, want 401", i+1, c)
		}
	}
	resp := attempt(`{"username":"u","password":"p"}`, "198.51.100.4:5")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("attempt %d: status = %d, want 429", limitBurst+1, resp.StatusCode)
	}
	ra := resp.Header.Get("Retry-After")
	if ra == "" {
		t.Fatal("429 must carry Retry-After")
	}
	for _, b := range ra {
		if b < '0' || b > '9' {
			t.Fatalf("Retry-After %q is not integer seconds", ra)
		}
	}
	if c := attempt(`{"username":"u","password":"p"}`, "198.51.100.5:5").StatusCode; c != http.StatusUnauthorized {
		t.Fatalf("different peer status = %d, want 401 (per-peer bucket)", c)
	}
	// Refill by ONE token through the server clock: exactly 60 s later the
	// peer gets one attempt back.
	now := srv.now()
	srv.now = func() time.Time { return now }
	srv.limiter.now = srv.now
	if c := attempt(`{"username":"u","password":"p"}`, "198.51.100.4:5").StatusCode; c != http.StatusTooManyRequests {
		t.Fatalf("still inside 60s window: status = %d, want 429", c)
	}
	now = now.Add(limitRefillSeconds * time.Second)
	if c := attempt(`{"username":"u","password":"p"}`, "198.51.100.4:5").StatusCode; c != http.StatusUnauthorized {
		t.Fatalf("after refill: status = %d, want 401 (one token back)", c)
	}
	// Body-size boundary: exactly the limit is processed; limit+1 is 413.
	pad := strings.Repeat("a", loginBodyLimit-len(`{"username":"","password":"x"}`))
	justRight := `{"username":"` + pad + `","password":"x"}`
	if len(justRight) != loginBodyLimit {
		t.Fatalf("padding math off: %d", len(justRight))
	}
	if c := attempt(justRight, "198.51.100.6:5").StatusCode; c != http.StatusUnauthorized {
		t.Fatalf("exact-limit body status = %d, want it processed (401 bad creds)", c)
	}
	tooBig := attempt(justRight+"x", "198.51.100.7:5")
	if tooBig.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("limit+1 body status = %d, want 413", tooBig.StatusCode)
	}
}

// TestT008GlobalArgon2CeilingSpansAllKDFPaths: the global max-2 ceiling is
// held on EVERY path that spends KDF cost — no-admin (dummy burn), wrong
// username (dummy burn) and wrong password (real verify) — so a burst cannot
// pile up KDF work through ANY of them. Two in-flight hold the ceiling; a
// third concurrent attempt on a DIFFERENT path fails fast (429, no queue).
func TestT008GlobalArgon2CeilingSpansAllKDFPaths(t *testing.T) {
	srv, h := newTestServer(t, "")
	bootstrapAdmin(t, srv, "admin", "correct horse battery staple")

	// Occupy both global Argon2 slots directly (a held slot models an in-flight
	// KDF on any path), then prove a third concurrent attempt is refused fast.
	srv.limiter.argon2 <- struct{}{}
	srv.limiter.argon2 <- struct{}{}
	resp := do(h, http.MethodPost, "/api/v1/session", "https://manage.test", `{"username":"admin","password":"x"}`, func(r *http.Request) {
		r.RemoteAddr = "198.51.100.11:1" // fresh peer, bucket has tokens
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third concurrent KDF attempt status = %d, want 429 (global ceiling)", resp.StatusCode)
	}
	if v := resp.Header.Get("Retry-After"); v != "" {
		t.Fatalf("global-ceiling attempt fabricated Retry-After %q (not computable)", v)
	}
	// Drain and the next attempt is admitted again.
	<-srv.limiter.argon2
	<-srv.limiter.argon2
	resp2 := do(h, http.MethodPost, "/api/v1/session", "https://manage.test", `{"username":"nope","password":"x"}`, func(r *http.Request) {
		r.RemoteAddr = "198.51.100.12:1"
	})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-drain attempt status = %d, want 401 (ceiling released)", resp2.StatusCode)
	}
}

// TestT008StateTruthfulBody: the body conforms to RuntimeState (no extra
// fields) and the readiness posture is truthful.
func TestT008StateTruthfulBody(t *testing.T) {
	srv, h := newTestServer(t, "")
	bootstrapAdmin(t, srv, "admin", "correct horse battery staple")
	c := loginCookie(t, login(t, h, "https://manage.test", "admin", "correct horse battery staple"))
	resp := do(h, http.MethodGet, "/api/v1/state", "", "", func(r *http.Request) { r.AddCookie(c) })
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(mustRead(t, resp), &raw); err != nil {
		t.Fatalf("state body: %v", err)
	}
	for k := range raw {
		switch k {
		case "phase", "draftRevisionId", "activeRevisionId", "activeGeneration", "readiness", "lastErrorCode", "lastErrorMessage":
		default:
			t.Fatalf("state body carries %q outside RuntimeState", k)
		}
	}
	var readiness map[string]bool
	if err := json.Unmarshal(raw["readiness"], &readiness); err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if len(readiness) != 4 || !readiness["management"] || readiness["dns"] || readiness["engine"] || readiness["classification"] {
		t.Fatalf("readiness = %v, want management-only true", readiness)
	}
	if string(raw["phase"]) != `"not-running"` {
		t.Fatalf("phase = %s, want not-running while no engine/apply exists (no dataplane guard is engaged, so stopped-guarded would be false)", raw["phase"])
	}
}

// TestT008LocalBootstrapHandlerOrdering: wrong method 405; consuming the
// live token is the FIRST gate — a shape-rejected credential after the token
// was burned is the SAME generic 403 (no per-field oracle), the burned token
// cannot be replayed, and a fresh issuance + correct submit wins.
func TestT008LocalBootstrapHandlerOrdering(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := srv.ManagementHandler()
	if c := do(m, http.MethodGet, "/bootstrap-token", "", "", nil).StatusCode; c != http.StatusMethodNotAllowed {
		t.Fatalf("GET /bootstrap-token = %d, want 405", c)
	}
	if c := do(m, http.MethodGet, "/api/v1/bootstrap", "", "", nil).StatusCode; c != http.StatusMethodNotAllowed {
		t.Fatalf("GET /bootstrap = %d, want 405", c)
	}
	raw := issueToken(t, m)
	bad := `{"token":"` + raw + `","username":"","password":"x"}`
	badResp := do(m, http.MethodPost, "/api/v1/bootstrap", "", bad, nil)
	if badResp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad-shape after token burn = %d, want 403 generic", badResp.StatusCode)
	}
	if p := readProblem(t, badResp); p.Code != codeForbidden || p.Message != msgForbidden {
		t.Fatalf("bad-shape problem = %+v, want generic forbidden (no field oracle)", p)
	}
	if srv.issuer.HasLive() {
		t.Fatal("token survived a consumed redemption")
	}
	// Replaying the burned token: identical generic 403.
	replay := do(m, http.MethodPost, "/api/v1/bootstrap", "", bad, nil)
	if replay.StatusCode != http.StatusForbidden {
		t.Fatalf("replayed token = %d, want 403", replay.StatusCode)
	}
	// Fresh issuance + correct submit succeeds.
	raw2 := issueToken(t, m)
	good := `{"token":"` + raw2 + `","username":"admin","password":"valid bootstrap password"}`
	if c := do(m, http.MethodPost, "/api/v1/bootstrap", "", good, nil).StatusCode; c != http.StatusNoContent {
		t.Fatalf("bootstrap with fresh token = %d, want 204", c)
	}
}

// TestT008LocalBootstrapConcurrencyOneWinner drives real goroutines at the
// real handler boundary with one issued token: exactly one 204.
func TestT008LocalBootstrapConcurrencyOneWinner(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := srv.ManagementHandler()
	raw := issueToken(t, m)
	const racers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make([]int, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := `{"token":"` + raw + `","username":"admin","password":"valid bootstrap password"}`
			rec := httptest.NewRecorder()
			<-start
			m.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap", strings.NewReader(body)))
			codes[i] = rec.Code
		}(i)
	}
	close(start)
	wg.Wait()
	wins := 0
	for _, c := range codes {
		switch c {
		case http.StatusNoContent:
			wins++
		case http.StatusForbidden, http.StatusConflict:
			// consumed-token 403 / store-closure 409 — both generic losers
		default:
			t.Fatalf("unexpected racer status %d", c)
		}
	}
	if wins != 1 {
		t.Fatalf("winners = %d, want exactly 1 (codes %v)", wins, codes)
	}
	if c := login(t, srv.Handler(), "https://manage.test", "admin", "valid bootstrap password").StatusCode; c != http.StatusNoContent {
		t.Fatalf("post-bootstrap LAN login = %d, want 204", c)
	}
}

// TestT008ServeLocalUnixSocket drives the REAL socket: dir 0700, socket 0600,
// end-to-end bootstrap over the socket, socket removed on shutdown.
func TestT008ServeLocalUnixSocket(t *testing.T) {
	srv, _ := newTestServer(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	died := make(chan error, 1)
	go func() { died <- srv.ServeLocal(ctx) }()
	sockPath := srv.cfg.UnixSocketPath()
	waitSocket(t, sockPath, died)
	if st, err := os.Stat(srv.cfg.UnixSocketDir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("socket dir mode = %v (%v), want 700", st.Mode(), err)
	}
	client := unixClient(sockPath)
	resp, err := client.Post("http://unix/bootstrap-token", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("issue over socket: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("issue = %d, want 200", resp.StatusCode)
	}
	var tok struct{ Token string }
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	body, _ := json.Marshal(map[string]string{"token": tok.Token, "username": "admin", "password": "valid bootstrap password"})
	resp, err = client.Post("http://unix/api/v1/bootstrap", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("bootstrap over socket = %d, want 204", resp.StatusCode)
	}
	cancel()
	if err := <-died; err != nil {
		t.Fatalf("ServeLocal returned %v after cancel, want nil", err)
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatal("socket file must be removed on shutdown")
	}
}

// TestT008ServeLocalRefusesLiveSocketAndForeignFile: a socket a live listener
// owns is refused; a non-socket file at the path is a hard error and is never
// unlinked; a stale socket is replaced.
func TestT008ServeLocalRefusesLiveSocketAndForeignFile(t *testing.T) {
	srv, _ := newTestServer(t, "")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	srv.cfg.UnixSocketDir = dir
	if err := os.WriteFile(srv.cfg.UnixSocketPath(), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := srv.ServeLocal(context.Background()); err == nil {
		t.Fatal("ServeLocal accepted a non-socket file at the socket path")
	}
	if _, err := os.Stat(srv.cfg.UnixSocketPath()); err != nil {
		t.Fatal("ServeLocal removed a foreign file it does not own")
	}
	if err := os.Remove(srv.cfg.UnixSocketPath()); err != nil {
		t.Fatal(err)
	}
	other, err := net.Listen("unix", srv.cfg.UnixSocketPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ServeLocal(context.Background()); err == nil {
		other.Close()
		t.Fatal("ServeLocal displaced a live socket")
	}
	other.Close()
	ctx, cancel := context.WithCancel(context.Background())
	died := make(chan error, 1)
	go func() { died <- srv.ServeLocal(ctx) }()
	waitSocket(t, srv.cfg.UnixSocketPath(), died)
	cancel()
	<-died
}

// --- helpers ---

func issueToken(t *testing.T, m http.Handler) string {
	t.Helper()
	resp := do(m, http.MethodPost, "/bootstrap-token", "", `{}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("issue token = %d, want 200", resp.StatusCode)
	}
	var tok struct{ Token string }
	if err := json.Unmarshal(mustRead(t, resp), &tok); err != nil {
		t.Fatal(err)
	}
	if tok.Token == "" {
		t.Fatal("empty issued token")
	}
	return tok.Token
}

func readProblem(t *testing.T, resp *http.Response) problem {
	t.Helper()
	var p problem
	if err := json.Unmarshal(mustRead(t, resp), &p); err != nil {
		t.Fatalf("problem body: %v", err)
	}
	return p
}

func problemOf(t *testing.T, resp *http.Response) problem {
	t.Helper()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	p := readProblem(t, resp)
	if p.Code != codeInvalidCredentials || p.Message != msgInvalidCredentials {
		t.Fatalf("problem = %+v, want generic invalid_credentials", p)
	}
	return p
}

func mustRead(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func waitSocket(t *testing.T, path string, died chan error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if st, err := os.Stat(path); err == nil && st.Mode()&os.ModeSocket != 0 {
			if st.Mode().Perm() != 0o600 {
				t.Fatalf("socket mode = %o, want 600", st.Mode().Perm())
			}
			return
		}
		select {
		case err := <-died:
			t.Fatalf("ServeLocal died: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never appeared")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func unixClient(sockPath string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}
}
