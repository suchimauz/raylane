package authhttp

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Early contract probes exist ONLY in bui's frozen WIP snapshot. They deliberately
// assert the already assigned product contract, not the author's current assertions.
func TestBuiCurrentContractOriginMultiplicity(t *testing.T) {
	_, h := newTestServer(t, testOrigin)
	resp := do(h, http.MethodPost, "/api/v1/session", testOrigin, `{"username":"u","password":"p"}`, func(r *http.Request) { r.Header.Add("Origin", "https://foreign.test") })
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("two Origin fields trusted+foreign accepted through CSRF: got %d want 403", resp.StatusCode)
	}
}
func TestBuiCurrentContractBootstrapTTLEquality(t *testing.T) {
	now := time.Unix(1000, 0)
	issuer := newBootstrapIssuerAt(func() time.Time { return now })
	raw, _, err := issuer.Issue()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(300 * time.Second)
	if issuer.Redeem(raw) {
		t.Fatal("token accepted at exact TTL300 expiry boundary")
	}
}
func TestBuiCurrentContractMappedPeer(t *testing.T) {
	a, b := peerIP("127.0.0.1:12"), peerIP("[::ffff:127.0.0.1]:12")
	if a != b {
		t.Fatalf("equivalent IPv4/mappedIPv6 peers split limiter buckets: %q vs %q", a, b)
	}
}
func TestBuiCurrentContractConfigurationRejectsUnsafe(t *testing.T) {
	for _, tc := range []struct{ name, listen, origin string }{
		{"wildcard", "0.0.0.0:9443", "https://127.0.0.1:9443"},
		{"public", "8.8.8.8:9443", "https://8.8.8.8:9443"},
		{"httpOrigin", "127.0.0.1:9443", "http://127.0.0.1:9443"},
		{"inconsistentPort", "127.0.0.1:9443", "https://127.0.0.1:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{ManagementListen: tc.listen, TrustedOrigin: tc.origin, TLSCertPath: "x", TLSKeyPath: "x", DBPath: "x", UnixSocketDir: "x"}
			if err := c.Validate(); err == nil {
				t.Fatal("unsafe configuration accepted by Validate; no listener was opened by this probe")
			}
		})
	}
}
func TestBuiCurrentContractRetryAfterOnlyComputable(t *testing.T) {
	_, h := newTestServer(t, testOrigin)
	// The global semaphore is occupied while this peer's bucket is fresh.
	s, h := newTestServer(t, testOrigin)
	s.limiter.argon2 <- struct{}{}
	s.limiter.argon2 <- struct{}{}
	resp := do(h, http.MethodPost, "/api/v1/session", testOrigin, `{"username":"u","password":"p"}`, nil)
	defer resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("want429 got%d", resp.StatusCode)
	}
	if v := resp.Header.Get("Retry-After"); v != "" {
		t.Fatalf("noncomputable global capacity hint was fabricated: Retry-After=%q", v)
	}
}
func TestBuiCurrentContractLANBootstrapGeneric(t *testing.T) {
	_, h := newTestServer(t, testOrigin)
	resp := do(h, http.MethodPost, "/bootstrap-token", testOrigin, `{}`, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("LAN bootstrap/unknown protected refusal=%d wantgeneric403", resp.StatusCode)
	}
}
func TestBuiCurrentContractFreshStateAndCookie(t *testing.T) {
	s, h := newTestServer(t, testOrigin)
	bootstrapAdmin(t, s, "operator", "synthetic-password")
	resp := do(h, http.MethodPost, "/api/v1/session", testOrigin, `{"username":"operator","password":"synthetic-password"}`, nil)
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("login=%d", resp.StatusCode)
	}
	c := resp.Cookies()[0]
	if strings.Contains(resp.Header.Get("Set-Cookie"), "Max-Age=0") {
		t.Error("successful login expires its own cookie with Max-Age=0")
	}
	state := do(h, http.MethodGet, "/api/v1/state", "", "", func(r *http.Request) { r.AddCookie(c) })
	defer state.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	n, _ := state.Body.Read(buf)
	b.Write(buf[:n])
	if !strings.Contains(b.String(), `"phase":"not-running"`) {
		t.Errorf("fresh state misclaims guarded dataplane: %s", b.String())
	}
	logout := do(h, http.MethodDelete, "/api/v1/session", testOrigin, "", func(r *http.Request) { r.AddCookie(c) })
	defer logout.Body.Close()
	if !strings.Contains(logout.Header.Get("Set-Cookie"), "Max-Age=0") {
		t.Errorf("logout fails to delete cookie: %q", logout.Header.Get("Set-Cookie"))
	}
}
