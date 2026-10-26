package authhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/store"
)

// unixHandlerClient serves h on a fresh owner-temp Unix socket and returns an
// HTTP client talking to it over that socket. This is the REAL wire path for
// the local management handler — the settled contract is decided by WHICH
// listener answers, and a socket connection carries NO Origin header, so this
// exercises that decision honestly (an httptest.NewRequest would fake
// RemoteAddr="@" and skip the real transport).
func unixHandlerClient(t *testing.T, h http.Handler) *http.Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "control.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		srv.Close()
		<-done
	})
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Dial: func(_, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
	}
}

// TestT008SettledLocalIssuerPathIsUnversioned asserts the settled local
// issuer route: POST /bootstrap-token over the real owner socket answers 200
// with the one-time token and no-store, while every versioned spelling is the
// generic refusal. The CLI and all clients must speak this exact path.
func TestT008SettledLocalIssuerPathIsUnversioned(t *testing.T) {
	srv, _ := newTestServer(t, "")
	client := unixHandlerClient(t, srv.ManagementHandler())
	resp, err := client.Post("http://unix/bootstrap-token", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("settled local POST /bootstrap-token = %d, want 200", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("issued token response Cache-Control = %q, want no-store", cc)
	}
	var tok struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expiresIn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if tok.Token == "" || tok.ExpiresIn != int(bootstrapTokenTTL/time.Second) {
		t.Fatalf("token response = %+v, want a token + expiresIn=%d", tok, int(bootstrapTokenTTL/time.Second))
	}
	// Redemption stays versioned at /api/v1/bootstrap and wins over the LAN
	// 403 isolation: here, over the local socket, the SAME settled pair works
	// end to end.
	body, _ := json.Marshal(map[string]string{"token": tok.Token, "username": "admin", "password": "settled bootstrap password"})
	resp, err = client.Post("http://unix/api/v1/bootstrap", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("settled redemption = %d, want 204", resp.StatusCode)
	}
	// Versioned issuance must NOT be a second route: it is the generic local
	// refusal (never a 200, no discovery oracle between paths is NOT claimed
	// — the settled path is the only one that issues).
	resp, err = client.Post("http://unix/api/v1/bootstrap-token", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		t.Fatal("/api/v1/bootstrap-token must not issue on the settled server")
	}
	resp.Body.Close()
}

// TestT008BootstrapSharesGlobalKDFGate proves the expensive bootstrap KDF work
// shares the SAME global max-2 admission as login: with both global slots
// held, a VALID bootstrap is refused BEFORE any KDF/DB commit (no identity is
// created, the token's fate is an explicit single-winner policy), no
// Retry-After is fabricated, and after freeing the gate a FRESH issuance
// bootstraps normally.
func TestT008BootstrapSharesGlobalKDFGate(t *testing.T) {
	srv, _ := newTestServer(t, "")
	// Occupy BOTH global KDF slots on the SAME runtime.
	for i := 0; i < cap(srv.limiter.argon2); i++ {
		srv.limiter.argon2 <- struct{}{}
	}
	releaseAll := func() {
		for len(srv.limiter.argon2) > 0 {
			<-srv.limiter.argon2
		}
	}
	token, _, err := srv.issuer.Issue()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"token": token, "username": "gate-admin", "password": "gate password long"})
	resp1 := do(srv.ManagementHandler(), http.MethodPost, "/api/v1/bootstrap", "", string(raw), nil)
	if resp1.StatusCode != http.StatusTooManyRequests {
		releaseAll()
		t.Fatalf("saturated global KDF gate: bootstrap = %d, want 429 before any KDF/DB work", resp1.StatusCode)
	}
	if ra := resp1.Header.Get("Retry-After"); ra != "" {
		releaseAll()
		t.Fatalf("global saturation must not fabricate Retry-After, got %q", ra)
	}
	// No identity was created (no DB commit happened).
	if ok, err := identityExists(srv.store); err != nil || ok {
		releaseAll()
		t.Fatalf("identity after refused bootstrap: ok=%v err=%v, want none", ok, err)
	}
	// The refusal consumed the single-use token (explicit single-winner
	// policy: a 429 must not leave a reusable credential behind).
	if srv.issuer.HasLive() {
		releaseAll()
		t.Fatal("capacity refusal must consume the one-time token (no double-authorization path)")
	}
	releaseAll()
	// Free gate: a FRESH issuance bootstraps normally.
	token2, _, err := srv.issuer.Issue()
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := json.Marshal(map[string]string{"token": token2, "username": "gate-admin", "password": "gate password long"})
	resp2 := do(srv.ManagementHandler(), http.MethodPost, "/api/v1/bootstrap", "", string(raw2), nil)
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("free-gate bootstrap = %d, want 204", resp2.StatusCode)
	}
	if ok, err := identityExists(srv.store); err != nil || !ok {
		t.Fatalf("free-gate bootstrap must commit identity: ok=%v err=%v", ok, err)
	}
}

// identityExists reports whether an admin identity row is present, via the
// store's own validated read (AdminIdentity) — no KDF, no raw SQL here.
func identityExists(st *store.Store) (bool, error) {
	_, err := st.AdminIdentity(context.Background())
	if errors.Is(err, domain.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// TestT008SocketDirSymlinkComponentRefusedWithoutTouchingTarget mirrors the
// CLI-level symlink guard at the authhttp ServeLocal boundary.
func TestT008SocketDirSymlinkComponentRefusedWithoutTouchingTarget(t *testing.T) {
	srv, _ := newTestServer(t, "")
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil { //nolint:gosec // owner-test fixture dir, deliberately wide to prove it is NOT touched
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	srv.cfg.UnixSocketDir = link
	// Use a cancellable context and assert the refusal, so this test can never
	// hang even if the guard ever regressed to accepting the alias.
	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ServeLocal(ctx) }()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ServeLocal accepted a symlinked socket dir")
		}
	case <-time.After(2 * time.Second):
		cancel()
		<-errCh
		t.Fatal("ServeLocal accepted a symlinked socket dir (never refused)")
	}
	cancel()
	st, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("symlinked target mode was modified to %o — must stay 755", st.Mode().Perm())
	}
}
