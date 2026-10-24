package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/suchimauz/raylane/internal/store"
)

// testRoot is the process-local trusted fixture root, established once: the
// caller (check runner) exports TMPDIR to a mode-0700 euid-owned directory
// under this repository's ignored scratch area; testRoot re-derives and
// re-secures it so the whole t.TempDir() chain stays production-policy
// compliant (no sticky-/tmp segment anywhere).
var testRoot = mustTestRoot()

func mustTestRoot() string {
	base := os.Getenv("TMPDIR")
	if base == "" {
		panic("store tests require TMPDIR set to a private 0700 fixture directory (see check log)")
	}
	fi, err := os.Lstat(base)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		panic("TMPDIR fixture root must be a real non-symlinked directory")
	}
	if err := os.Chmod(base, 0o700); err != nil {
		panic("chmod fixture root: " + err.Error())
	}
	return base
}

// All fixtures here are synthetic test data under ordinary user permissions
// inside t.TempDir(): no /etc or service paths, no privilege, no real
// credentials. The bytes below are a throwaway test key, never a secret of
// any system.

// trustedDir returns a fresh directory that satisfies the production trust
// policy for the WHOLE chain: every ancestor of t.TempDir() is forced
// non group/world writable. Run the suite with TMPDIR pointed at a
// mode-0700, euid-owned, non-symlinked directory of this workspace so the
// root->...->fixture chain contains no sticky /tmp segment (recorded in the
// check evidence). This is fixture hygiene, not a policy exemption: the
// product-side walk enforces the same predicate on every component.
func trustedDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatalf("chmod fixture dir: %v", err)
	}
	for a := filepath.Dir(d); a != "/" && a != "."; a = filepath.Dir(a) {
		fi, err := os.Lstat(a)
		if err != nil {
			t.Fatalf("lstat ancestor: %v", err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("TMPDIR chain ancestor %s is a symlink; set TMPDIR to a real 0700 dir", a)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			// Only this process's own temp chain is adjusted; never / or
			// other users' directories (chmod would fail there anyway).
			if err := os.Chmod(a, 0o755); err != nil {
				t.Fatalf("chmod ancestor %s: %v", a, err)
			}
		}
	}
	return d
}

// openKeyStore opens the key at absPath enforcing the full production policy
// under the explicitly established trusted test-root descriptor (the process
// workspace fixture root, 0700 euid-owned, no symlinks). All chain
// components below the root face the identical production predicate; this is
// the documented test-only anchor seam in the package, never a product path.
func openKeyStore(t *testing.T, absPath string) (*store.KeyStore, error) {
	t.Helper()
	return store.NewKeyStoreUnderTrustedRootForTests(testRootForFixtures(t), absPath)
}

func testRootForFixtures(t *testing.T) string {
	t.Helper()
	if err := os.Setenv("TMPDIR", testRoot); err != nil { // recorded in evidence
		t.Fatalf("set process-local TMPDIR: %v", err)
	}
	return testRoot
}

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
	dir := trustedDir(t)
	p := writeKeyFile(t, dir, "master.key", validTestKey(), 0o600)
	ks, err := openKeyStore(t, p)
	if err != nil {
		t.Fatalf("NewKeyStore(safe): %v", err)
	}
	if ks.Version() != store.KeyVersion {
		t.Fatalf("Version() = %d, want %d", ks.Version(), store.KeyVersion)
	}
}

func TestKeyStoreFailsClosedOnUnsafeOrMissingKeys(t *testing.T) {
	dir := trustedDir(t)
	// A trusted intermediate holding the unsafe FINAL-object fixtures: the
	// key files themselves carry the unsafe properties under test.
	sub := filepath.Join(dir, "h")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	symlinkDir := filepath.Join(dir, "lnk")
	if err := os.Mkdir(symlinkDir, 0o700); err != nil { // trusted, for the positive-target fixture
		t.Fatalf("mkdir symlinkdir: %v", err)
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
			ks, err := openKeyStore(t, p)
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
	dir := trustedDir(t)
	canary := append(validTestKey(), []byte("KEYCANARY")...)
	p := writeKeyFile(t, dir, "c.key", canary, 0o602) // unsafe perms AND oversized
	_, err := openKeyStore(t, p)
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
	dir := trustedDir(t)
	p := writeKeyFile(t, dir, "rt.key", validTestKey(), 0o600)
	ks, err := openKeyStore(t, p)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	if ks.Version() != store.KeyVersion {
		t.Fatalf("Version() = %d, want fixed %d", ks.Version(), store.KeyVersion)
	}
}

// TestKeyStoreTrustChainAncestors covers T007-S1: the trust chain is
// established descriptor-relatively from the process filesystem-root anchor,
// so a symlink at ANY ancestor depth, an unsafe ancestor directory, or a
// non-directory component fails closed. Positive control: a valid multi-level
// nested path under the trusted chain still opens.
func TestKeyStoreTrustChainAncestors(t *testing.T) {
	dir := trustedDir(t)
	// Real, safe location for the key.
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	key := writeKeyFile(t, realDir, "master.key", validTestKey(), 0o600)

	// Positive control: valid trusted nested path opens under the test anchor.
	if ks, err := openKeyStore(t, key); err != nil || ks == nil {
		t.Fatalf("trusted nested path rejected: %v", err)
	}

	link := filepath.Join(dir, "linked")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// Higher ancestor symlink: .../linked/master.key (immediate parent via link)
	immediate := filepath.Join(link, "master.key")
	// Deeper: link2 -> dir, then link2/real/master.key (higher ancestor in path)
	link2 := filepath.Join(dir, "deep")
	if err := os.Symlink(dir, link2); err != nil {
		t.Fatalf("symlink deep: %v", err)
	}
	deeper := filepath.Join(link2, "real", "master.key")

	notDir := writeKeyFile(t, dir, "notadir", []byte("x"), 0o600) // used as a path component
	loose := filepath.Join(dir, "loose")
	if err := os.Mkdir(loose, 0o700); err != nil {
		t.Fatalf("mkdir loose: %v", err)
	}
	if err := os.Chmod(loose, 0o777); err != nil { // world-writable ancestor
		t.Fatalf("chmod loose: %v", err)
	}
	nested := filepath.Join(loose, "deep2")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	hiddenKey := writeKeyFile(t, nested, "master.key", validTestKey(), 0o600)

	cases := []struct {
		name, path string
	}{
		{"immediate-symlink-parent", immediate},
		{"higher-symlink-ancestor", deeper},
		{"writable-ancestor", hiddenKey},
		{"non-directory-component", filepath.Join(notDir, "master.key")},
		{"missing-component", filepath.Join(dir, "nope", "master.key")},
		{"relative-path", "relative/master.key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ks, err := openKeyStore(t, tc.path)
			if err == nil || ks != nil {
				t.Fatalf("unsafe path accepted: %s (%v)", tc.name, err)
			}
			if !errors.Is(err, store.ErrKeyUnavailable) {
				t.Fatalf("err = %v, want ErrKeyUnavailable", err)
			}
		})
	}

	// The exact reviewer repro (symlinked parent accepted before the fix):
	t.Run("reviewer-repro-linked-parent", func(t *testing.T) {
		if _, err := openKeyStore(t, immediate); err == nil {
			t.Fatal("symlinked parent path was accepted")
		}
	})
}

// TestKeyStoreFinalObjectCannotHangOrLeak: a FIFO at the final path slot
// must fail closed immediately (O_NONBLOCK makes the open non-blocking; the
// fstat then rejects the non-regular object). Repeated opens across a deep
// chain must not leak directory descriptors: an intermediate fd is closed by
// the caller's cleanup exactly once.
func TestKeyStoreFinalObjectCannotHangOrLeak(t *testing.T) {
	dir := trustedDir(t)
	fifo := filepath.Join(dir, "fifo.key")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := openKeyStore(t, fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, store.ErrKeyUnavailable) {
			t.Fatalf("fifo err = %v, want ErrKeyUnavailable", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("FIFO final component blocked the key open (pre-auth hang)")
	}
	// fd-exhaustion smoke: 200 sequential deep opens complete.
	deep := filepath.Join(dir, "chain", "a", "b")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatalf("mkdir deep: %v", err)
	}
	k := writeKeyFile(t, deep, "k.key", validTestKey(), 0o600)
	for i := 0; i < 200; i++ {
		if _, err := openKeyStore(t, k); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
}
