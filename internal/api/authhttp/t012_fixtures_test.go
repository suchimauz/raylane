package authhttp

// Shared T012 test fixtures: LAN server composition with a real session
// cookie, trusted-key files, and the compiled/extended profile helpers used
// by the wire, read and composition test files.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/suchimauz/raylane/internal/store"
)

// t012FixtureBase creates the private, project-owned fixture root under the
// repository's ignored .hyper/tmp area. The production "/"-anchored key trust
// chain rejects anything hanging off the 1777 system temp (t.TempDir() with
// unset TMPDIR), so trusted fixtures live here: every ancestor is a real,
// non-group/world-writable, euid-owned directory. Never HOME, never /tmp.
func t012FixtureBase(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", ".hyper", "tmp", "authhttp-fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		t.Fatal(err)
	}
	return abs
}

// t012TrustedDir returns a fresh 0700 fixture directory in the trusted chain.
func t012TrustedDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp(t012FixtureBase(t), "d")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func t012Ctx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}

func t012RawStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t012TrustedDir(t), "raw.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// t012Do issues one management-surface request against the LAN handler with a
// spoofed foreign peer address (never 127.0.0.1, which is LOCAL-only).
func t012Do(h http.Handler, method, target, origin string, body []byte, cookie *http.Cookie) *http.Response {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	req.RemoteAddr = "192.0.2.7:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

// t012Server composes a LAN Server + handler over a fresh store with the real
// bootstrap + login flow (a genuine session cookie, no injected presence).
func t012Server(t *testing.T, keyPath string) (*Server, http.Handler, *http.Cookie) {
	t.Helper()
	cfg := Config{
		ManagementListen: testListen,
		TrustedOrigin:    testOrigin,
		TLSCertPath:      "unused",
		TLSKeyPath:       "unused",
		DBPath:           filepath.Join(t012TrustedDir(t), "state.db"),
		UnixSocketDir:    t012TrustedDir(t),
		NodeKeyPath:      keyPath,
	}
	db, err := store.Open(context.Background(), cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	srv, err := NewServer(cfg, db)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	h := srv.Handler()
	bootstrapAdmin(t, srv, "admin-t012", "Passw0rd-t012-x!")
	resp := t012Do(h, http.MethodPost, "/api/v1/session", testOrigin,
		[]byte(`{"username":"admin-t012","password":"Passw0rd-t012-x!"}`), nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	return srv, h, loginCookie(t, resp)
}

func t012JSONRaw(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("body not JSON: %s", raw)
	}
	return m
}

func t012JSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	return t012JSONRaw(t, mustRead(t, resp))
}

// t012CompiledProfile loads the authored repository profile bytes. The test
// deliberately reads the FILE, never contracts.ProfileBytes, so the compiled
// embed can be byte-compared against the authored source.
func t012CompiledProfile(t *testing.T) []byte {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "contracts", "capability-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// t012ExtendedProfile clones the authored profile and ADDS the given protocol
// id (a clone of the first protocol's shape) — enough to build an authority
// whose stored rows are foreign to the compiled-bytes composition.
func t012ExtendedProfile(t *testing.T, extraID string) []byte {
	t.Helper()
	var prof map[string]any
	if err := json.Unmarshal(t012CompiledProfile(t), &prof); err != nil {
		t.Fatal(err)
	}
	protocols, _ := prof["protocols"].(map[string]any)
	var first map[string]any
	for _, v := range protocols {
		if m, ok := v.(map[string]any); ok {
			first = m
			break
		}
	}
	if first == nil {
		t.Fatal("authored profile has no protocol objects")
	}
	clone := map[string]any{}
	for k, v := range first {
		clone[k] = v
	}
	protocols[extraID] = clone
	out, err := json.Marshal(prof)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// t012ForeignAuthority composes an authority from EXTRA profile bytes. The
// store package's test-only helpers are not importable across packages, so the
// fixture builds the authority the same way NewServer does — from bytes.
func t012ForeignAuthority(t *testing.T, extraID string) *store.NodeAuthority {
	t.Helper()
	a, err := store.OpenNodeAuthority(t012ExtendedProfile(t, extraID))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
