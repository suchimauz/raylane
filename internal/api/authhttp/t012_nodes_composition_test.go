package authhttp

// T012 create/read composition-boundary tests: the optional trusted node key
// (Config.NodeKeyPath) and the keyed/keyless composition inside NewServer.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/store"
)

func t012NodeKeyFile(t *testing.T) string {
	t.Helper()
	dir := t012TrustedDir(t)
	path := filepath.Join(dir, "master.key")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func t012Config(keyPath string) Config {
	return Config{
		ManagementListen: testListen,
		TrustedOrigin:    testOrigin,
		TLSCertPath:      "unused",
		TLSKeyPath:       "unused",
		DBPath:           "/shape-only/state.db",
		UnixSocketDir:    "/shape-only",
		NodeKeyPath:      keyPath,
	}
}

func TestT012ConfigNodeKeyPathShape(t *testing.T) {
	for _, p := range []string{"/x/master.key", "/var/lib/raylane/master.key"} {
		if err := t012Config(p).Validate(); err != nil {
			t.Fatalf("valid shape %q refused: %v", p, err)
		}
	}
	for _, p := range []string{"relative/master.key", "/", "//x/master.key", "/x//master.key",
		"/x/./master.key", "/x/../master.key", "/x/", "/x/master.key/"} {
		if err := t012Config(p).Validate(); err == nil {
			t.Fatalf("invalid path shape %q accepted", p)
		}
	}
	// Omitted/empty stays keyless: the six-field config keeps validating.
	if err := t012Config("").Validate(); err != nil {
		t.Fatalf("empty nodeKeyPath must stay keyless-valid: %v", err)
	}
	// PURE shape: a well-shaped path to a MISSING file validates (no IO).
	if err := t012Config("/definitely/not/here/master.key").Validate(); err != nil {
		t.Fatalf("path-shape validation must not touch the filesystem: %v", err)
	}
}

func TestT012ConfigStringRedactsNodeKey(t *testing.T) {
	s := t012Config("/var/lib/raylane/master.key").String()
	if strings.Contains(s, "master.key") || strings.Contains(s, "/var/lib") {
		t.Fatalf("Config.String leaks the node key path: %s", s)
	}
}

func TestT012NewServerTrustFailureNoDowngrade(t *testing.T) {
	dir := t012TrustedDir(t)
	badKey := filepath.Join(dir, "master.key")
	if err := os.WriteFile(badKey, []byte("too-short-for-aes"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ManagementListen: testListen,
		TrustedOrigin:    testOrigin,
		TLSCertPath:      "unused",
		TLSKeyPath:       "unused",
		DBPath:           filepath.Join(t012TrustedDir(t), "state.db"),
		UnixSocketDir:    t012TrustedDir(t),
		NodeKeyPath:      badKey,
	}
	db, err := store.Open(context.Background(), cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv, err := NewServer(cfg, db)
	if err == nil {
		t.Fatal("unusable node key must be a HARD failure, never a keyless downgrade")
	}
	if srv != nil {
		t.Fatal("no partial server on key failure")
	}
	if !errors.Is(err, store.ErrKeyUnavailable) {
		t.Fatalf("key failure must surface ErrKeyUnavailable category, got %v", err)
	}
}

// TestT012KeylessServerStillSafeReads pins the keyless split: authenticated
// create is a static 503 while the safe reader stays composed (unknown id is
// 404, not 503), and the unauthenticated ladder is unchanged.
func TestT012KeylessServerStillSafeReads(t *testing.T) {
	_, h, cookie := t012Server(t, "")
	resp := t012Do(h, http.MethodPost, "/api/v1/nodes", testOrigin, []byte(t012Create), cookie)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("keyless create: want 503, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") != "" {
		t.Fatal("503 must not carry Retry-After")
	}
	m := t012JSON(t, resp)
	if m["code"] != "service_unavailable" {
		t.Fatalf("503 code: %v", m)
	}
	if rid := resp.Header.Get("X-Request-Id"); rid == "" || rid != m["requestId"] {
		t.Fatal("503 body requestId must equal the header")
	}
	if resp := t012Do(h, http.MethodGet, "/api/v1/nodes/abc", "", nil, cookie); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("keyless safe read: want 404 for unknown id, got %d", resp.StatusCode)
	}
}
