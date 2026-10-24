package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/suchimauz/raylane/internal/store"
)

// All fixtures here are synthetic test data under ordinary user permissions
// inside t.TempDir(): no /etc or service paths, no privilege, no real
// credentials. The bytes below are a throwaway test key, never a secret of
// any system.

func writeKeyFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	// Copy the bytes: a fixture must never share a backing array with a
	// later mutation (an in-place tweak of a copied slice corrupted every
	// subsequent fixture that reused the same slice).
	buf := append([]byte(nil), data...)
	if err := os.WriteFile(p, buf, mode); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("chmod fixture: %v", err)
	}
	return p
}

func validTestKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestKeyStoreAcceptsSafeKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { // trusted key directory
		t.Fatalf("chmod: %v", err)
	}
	p := writeKeyFile(t, dir, "master.key", validTestKey(), 0o600)
	ks, err := store.NewKeyStore(p)
	if err != nil {
		t.Fatalf("NewKeyStore(safe): %v", err)
	}
	if ks.Version() != store.KeyVersion {
		t.Fatalf("Version() = %d, want %d", ks.Version(), store.KeyVersion)
	}
}

func TestKeyStoreFailsClosedOnUnsafeOrMissingKeys(t *testing.T) {
	dir := t.TempDir()
	sub, err := os.MkdirTemp("", "raylane-keygroup")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sub) })
	if err := os.Chmod(sub, 0o755); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}

	symlinkDir := t.TempDir()
	if err := os.Chmod(symlinkDir, 0o700); err != nil { // trusted, for the positive-target fixture
		t.Fatalf("chmod symlinkdir: %v", err)
	}

	cases := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{"missing", func(t *testing.T) string { return filepath.Join(dir, "absent.key") }},
		{"group-readable-0640", func(t *testing.T) string {
			return writeKeyFile(t, sub, "g.key", validTestKey(), 0o640)
		}},
		{"world-readable-0604", func(t *testing.T) string {
			return writeKeyFile(t, sub, "w.key", validTestKey(), 0o604)
		}},
		{"world-writable-0602", func(t *testing.T) string {
			return writeKeyFile(t, sub, "ww.key", validTestKey(), 0o602)
		}},
		{"no-owner-read-0000", func(t *testing.T) string {
			return writeKeyFile(t, sub, "z.key", validTestKey(), 0o000)
		}},
		{"too-short", func(t *testing.T) string {
			return writeKeyFile(t, sub, "short.key", validTestKey()[:16], 0o600)
		}},
		{"too-long-33", func(t *testing.T) string {
			long := make([]byte, 33)
			copy(long, validTestKey())
			long[32] = 9
			return writeKeyFile(t, sub, "long.key", long, 0o600)
		}},
		{"empty", func(t *testing.T) string { return writeKeyFile(t, sub, "empty.key", nil, 0o600) }},
		{"directory-not-regular", func(t *testing.T) string {
			d := filepath.Join(sub, "keydir")
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			return d
		}},
		{"symlink-substitution", func(t *testing.T) string {
			real := writeKeyFile(t, symlinkDir, "real.key", validTestKey(), 0o600)
			link := filepath.Join(symlinkDir, "link.key")
			if err := os.Symlink(real, link); err != nil {
				t.Fatalf("symlink: %v", err)
			}
			return link
		}},
		{"parent-dir-world-writable", func(t *testing.T) string {
			// A 0777 directory that the service user owns: any other local
			// user could swap the key file — unsafe parent must fail closed.
			loose := filepath.Join(sub, "loose")
			if err := os.Mkdir(loose, 0o777); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.Chmod(loose, 0o777); err != nil {
				t.Fatalf("chmod loose: %v", err)
			}
			return writeKeyFile(t, loose, "k.key", validTestKey(), 0o600)
		}},
		{"parent-dir-group-writable", func(t *testing.T) string {
			loose := filepath.Join(sub, "loose2")
			if err := os.Mkdir(loose, 0o770); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.Chmod(loose, 0o770); err != nil {
				t.Fatalf("chmod loose2: %v", err)
			}
			return writeKeyFile(t, loose, "k.key", validTestKey(), 0o600)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.setup(t)
			ks, err := store.NewKeyStore(p)
			if err == nil {
				t.Fatalf("NewKeyStore(%s) accepted unsafe key material", tc.name)
			}
			if ks != nil {
				t.Fatalf("NewKeyStore(%s) returned non-nil keystore with error", tc.name)
			}
			if !errors.Is(err, store.ErrKeyUnavailable) {
				t.Fatalf("NewKeyStore(%s) error = %v, want ErrKeyUnavailable", tc.name, err)
			}
			// Fail closed: no key file may be silently created or repaired.
			if _, statErr := os.Lstat(p); tc.name == "missing" && statErr == nil {
				t.Fatalf("missing key case created the file")
			}
		})
	}
}

func TestKeyStoreErrorIsSecretFree(t *testing.T) {
	// The fail-closed error must be the generic typed condition only: never
	// key bytes, never file contents, never an input echo.
	dir := t.TempDir()
	canary := append(validTestKey(), []byte("KEYCANARY")...)
	p := writeKeyFile(t, dir, "c.key", canary, 0o602) // unsafe perms AND oversized
	_, err := store.NewKeyStore(p)
	if err == nil {
		t.Fatal("expected unsafe oversized key to be refused")
	}
	if !errors.Is(err, store.ErrKeyUnavailable) {
		t.Fatalf("err = %v, want ErrKeyUnavailable", err)
	}
	if err.Error() != store.ErrKeyUnavailable.Error() {
		t.Fatalf("error text escaped the generic condition: %q", err.Error())
	}
}

func TestKeyStoreRoundtripUsesOpenedObject(t *testing.T) {
	// Positive path of the key boundary: a safe 32-byte key file opens and
	// reports the fixed key version. (Deep seal/open roundtrips live in
	// secrets_test.go.)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	p := writeKeyFile(t, dir, "rt.key", validTestKey(), 0o600)
	ks, err := store.NewKeyStore(p)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	if ks.Version() != store.KeyVersion {
		t.Fatalf("Version() = %d, want fixed %d", ks.Version(), store.KeyVersion)
	}
}
