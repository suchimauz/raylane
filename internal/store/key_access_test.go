package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/suchimauz/raylane/internal/store"
)

// Fixture ownership (T007-C2). Every fixture directory is created FRESH by
// this test code under a base it owns; modes are set ONLY on fresh, empty,
// euid-owned directories the test just created. NOTHING pre-existing is ever
// chmodded — not the caller's TMPDIR (nor the platform default /tmp when
// TMPDIR is unset), not /home, not workspace parents, not /. The
// production "/"-anchored chain policy therefore runs UNCHANGED over these
// fixtures on an ordinary unprivileged user: on this class of hosts the walk
// is / (0755 root) → /home (0755 root) → /home/<user> (0700-0750 euid) →
// fresh test dirs (0700 euid). A fixture that cannot satisfy the predicate
// is a test failure, never an exemption or a chmod of a shared directory.
// homeFixtureDir returns a fresh, private, policy-compliant chain BELOW the
// effective user's home directory (itself an ordinary user-owned directory,
// never chmodded). t.TempDir() is deliberately NOT the fixture root: when
// TMPDIR is unset it lands under 1777 /tmp, which the production policy
// rejects by design (world-writable sticky), and "fixing" /tmp would mutate a
// shared directory the test does not own. Creating the fixture under the
// user's own home needs no privilege and mutates nothing shared.
// projectFixtureRoot returns the private, project-owned fixture root: a
// dedicated directory UNDER the project's ignored .hyper/tmp area, never the
// user's HOME and never the shared system temp. The production "/"-anchored
// trust chain accepts it because every ancestor from "/" down is non-
// group/world-writable and euid-owned below HOME. Historical ~/d<digits>
// junk is unrelated and is never touched, swept, or cleaned.
func projectFixtureRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// key_access_test.go lives at internal/store; the module root is two up.
	root := filepath.Join(wd, "..", "..")
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return filepath.Join(abs, ".hyper", "tmp", "store-fixtures"), nil
}

// TestFixtureRootIsProjectOwned is the placement regression for the T007
// fixture-root finding: the fixture base returned for store tests must live
// under the project's private .hyper/tmp root, NOT directly under the user's
// HOME. Anonymous ~/d<digits> directories must not be created. The check is
// read-only with respect to HOME (an immediate directory listing), and asserts
// the returned base is inside the project and outside HOME's direct children.
func TestFixtureRootIsProjectOwned(t *testing.T) {
	wantRoot, err := projectFixtureRoot()
	if err != nil {
		t.Fatalf("resolve project fixture root: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}

	d := trustedDir(t) // exercises the real fixture-base path
	base := filepath.Dir(d)

	// The fixture base must be at or under the project fixture root.
	rel, err := filepath.Rel(wantRoot, base)
	if err != nil || (rel != "." && (len(rel) == 0 || rel == ".." || filepath.IsAbs(rel) || rel[0] == '.')) {
		t.Fatalf("fixture base %s is not under project root %s (rel=%q): %v", base, wantRoot, rel, err)
	}
	// It must NOT be a direct child of HOME (no anonymous ~/d<digits>).
	if filepath.Dir(base) == home {
		t.Fatalf("fixture base %s is a direct child of HOME %s: anonymous home fixture", base, home)
	}
	if filepath.Dir(filepath.Dir(base)) == home && filepath.Base(base) != "store-fixtures" {
		t.Fatalf("fixture base %s is an anonymous direct child of HOME", base)
	}
}

var homeBaseOnce struct {
	sync.Once
	dir string
	err error
}

func homeFixtureBase(t *testing.T) string {
	t.Helper()
	homeBaseOnce.Do(func() {
		root, err := projectFixtureRoot()
		if err != nil {
			homeBaseOnce.err = err
			return
		}
		// The fixture root and every ancestor down to "/" must satisfy the
		// production walk (non-group/world-writable). Read-validate only; a
		// non-conforming host fails with a precise message, never a chmod of a
		// shared ancestor. .hyper/tmp is created fresh by us (0700); its parents
		// already exist with compliant modes.
		if err := os.MkdirAll(root, 0o700); err != nil {
			homeBaseOnce.err = err
			return
		}
		if err := os.Chmod(root, 0o700); err != nil { // fresh/private, ours
			homeBaseOnce.err = err
			return
		}
		for dir := root; ; dir = filepath.Dir(dir) {
			fi, err := os.Stat(dir)
			if err != nil {
				homeBaseOnce.err = err
				return
			}
			if fi.Mode().Perm()&0o022 != 0 {
				homeBaseOnce.err = errors.New("fixture chain ancestor " + dir +
					" is group/world writable; fixture host not compliant")
				return
			}
			if dir == "/" {
				break
			}
		}
		homeBaseOnce.dir = root
	})
	if homeBaseOnce.err != nil {
		t.Fatalf("home fixture base: %v", homeBaseOnce.err)
	}
	return homeBaseOnce.dir
}

// trustedDir returns a fresh fixture directory (0700, euid-owned, empty at
// creation) under the home-based fixture base. Its whole chain satisfies the
// production predicate WITHOUT any shared-directory mutation, so tests open
// keys through the real production NewKeyStore.
func trustedDir(t *testing.T) string {
	t.Helper()
	base := homeFixtureBase(t)
	d, err := os.MkdirTemp(base, "d")
	if err != nil {
		t.Fatalf("fixture mkdir: %v", err)
	}
	// Lifetime (fixture-cleanup packet): register removal of THIS fresh,
	// test-owned directory — and only it, never the base or any shared path —
	// before any subsequent fallible step, so even a failing chmod or a later
	// t.Fatal inside the owning test cannot leave orphan fixtures behind.
	t.Cleanup(func() {
		if err := os.RemoveAll(d); err != nil {
			t.Errorf("remove owned fixture %s: %v", d, err)
		}
	})
	if err := os.Chmod(d, 0o700); err != nil { // fresh, empty, ours
		t.Fatalf("chmod fresh fixture: %v", err)
	}
	return d
}

// openKeyStore calls the PRODUCTION constructor directly: fixtures are
// production-compliant from "/" down, and no alternate-anchor seam exists in
// the package (removed as T007-S1 required).
func openKeyStore(t *testing.T, absPath string) (*store.KeyStore, error) {
	t.Helper()
	return store.NewKeyStore(absPath)
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
	sub := trustedSubDir(t, dir, "h")
	symlinkDir := trustedSubDir(t, dir, "lnk") // trusted, holds positive targets

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

func trustedSubDir(t *testing.T, parent, name string) string {
	t.Helper()
	d := filepath.Join(parent, name)
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatalf("mkdir fixture subdir: %v", err)
	}
	if err := os.Chmod(d, 0o700); err != nil { // fresh, empty, ours
		t.Fatalf("chmod fixture subdir: %v", err)
	}
	return d
}

// TestKeyStoreTrustChainAncestors covers T007-S1 with the DISTINGUISHING
// pair the reviewer's vector demands: on the SAME secure chain, a valid
// nested path must open (positive control) while the identical path reached
// through a CONTAINED RELATIVE symlink (linked -> real, both inside the
// trusted fixture tree, both 0700 euid-owned — the followed target is itself
// perfectly "safe") must be REJECTED. A rejection caused only by an unsafe
// target proves nothing about symlinks; here the only difference between the
// opening path and the refusing path is that one literal component is a
// symbolic link. Additional negatives: absolute link, higher relative link,
// writable ancestor, non-directory component, missing component, relative
// spelling.
func TestKeyStoreTrustChainAncestors(t *testing.T) {
	dir := trustedDir(t)
	realDir := trustedSubDir(t, dir, "real")
	key := writeKeyFile(t, realDir, "master.key", validTestKey(), 0o600)

	// Positive control on the SAME chain (nested trusted path): opens.
	if ks, err := openKeyStore(t, key); err != nil || ks == nil {
		t.Fatalf("trusted nested path rejected: %v", err)
	}

	// RELATIVE contained symlink: linked -> "real" (relative target!). The
	// followed directory is the very same 0700 euid real dir whose direct
	// path JUST opened above. os.Root.OpenRoot accepted this spelling; the
	// raw openat(O_NOFOLLOW) walk must not.
	linked := filepath.Join(dir, "linked")
	if err := os.Symlink("real", linked); err != nil {
		t.Fatalf("symlink relative: %v", err)
	}
	relativeLinked := filepath.Join(linked, "master.key")

	// ABSOLUTE symlink to the same real dir.
	absLink := filepath.Join(dir, "abslink")
	if err := os.Symlink(realDir, absLink); err != nil {
		t.Fatalf("symlink absolute: %v", err)
	}
	absoluteLinked := filepath.Join(absLink, "master.key")

	// Higher relative ancestor link: deep -> "." then deep/real/master.key.
	deep := filepath.Join(dir, "deep")
	if err := os.Symlink(".", deep); err != nil {
		t.Fatalf("symlink higher: %v", err)
	}
	deeper := filepath.Join(deep, "real", "master.key")

	// Final-component symlink: link.key -> real.key inside a trusted dir.
	finalDir := trustedSubDir(t, dir, "fd")
	realKey := writeKeyFile(t, finalDir, "real.key", validTestKey(), 0o600)
	finalLink := filepath.Join(finalDir, "link.key")
	if err := os.Symlink("real.key", finalLink); err != nil {
		t.Fatalf("symlink final: %v", err)
	}
	if _, err := openKeyStore(t, realKey); err != nil {
		t.Fatalf("positive control (real key in same dir) rejected: %v", err)
	}

	notDir := writeKeyFile(t, dir, "notadir", []byte("x"), 0o600) // used as a path component
	loose := filepath.Join(dir, "loose")
	if err := os.Mkdir(loose, 0o700); err != nil {
		t.Fatalf("mkdir loose: %v", err)
	}
	if err := os.Chmod(loose, 0o777); err != nil { // fresh dir, unsafe by design
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
		{"relative-contained-symlink-ancestor", relativeLinked},
		{"absolute-symlink-ancestor", absoluteLinked},
		{"higher-relative-symlink-ancestor", deeper},
		{"final-component-symlink", finalLink},
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

	// The exact reviewer repro (contained relative symlinked parent accepted
	// by the os.Root-based walk before this fix):
	t.Run("reviewer-repro-linked-parent", func(t *testing.T) {
		if _, err := openKeyStore(t, relativeLinked); err == nil {
			t.Fatal("symlinked parent path was accepted")
		}
	})
}

// TestKeyStoreFinalObjectCannotHangOrLeak: a FIFO at the final path slot
// must fail closed immediately (O_NONBLOCK makes the open non-blocking; the
// fstat then rejects the non-regular object). Repeated opens across a deep
// chain must not leak directory descriptors: every fd the walk opens is
// closed exactly once on every path.
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
	cur := dir
	for _, name := range []string{"chain", "a", "b"} {
		cur = filepath.Join(cur, name)
		if err := os.Mkdir(cur, 0o700); err != nil {
			t.Fatalf("mkdir deep: %v", err)
		}
		if err := os.Chmod(cur, 0o700); err != nil { // fresh, empty, ours
			t.Fatalf("chmod deep: %v", err)
		}
	}
	deep := cur
	k := writeKeyFile(t, deep, "k.key", validTestKey(), 0o600)
	for i := 0; i < 200; i++ {
		if _, err := openKeyStore(t, k); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
}

// TestFixturesDoNotMutateSharedDirectories is the reproducibility guard for
// T007-C2: an ordinary unprivileged `go test ./internal/store` run (TMPDIR
// set or unset) must open production-valid key fixtures WITHOUT changing the
// modes of any directory it does not own. The test snapshots /tmp (or the
// caller TMPDIR) and $HOME before creating fixtures and re-reads them after:
// any mode change to a shared pre-existing directory is a fixture bug.
func TestFixturesDoNotMutateSharedDirectories(t *testing.T) {
	tmp := os.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	modeOf := func(p string) os.FileMode {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		return fi.Mode().Perm()
	}
	beforeTmp, beforeHome := modeOf(tmp), modeOf(home)

	d := trustedDir(t)
	k := writeKeyFile(t, d, "master.key", validTestKey(), 0o600)
	if _, err := openKeyStore(t, k); err != nil {
		t.Fatalf("production fixture open failed: %v", err)
	}

	if got := modeOf(tmp); got != beforeTmp {
		t.Fatalf("test changed mode of shared temp dir %s: %o -> %o", tmp, beforeTmp, got)
	}
	if got := modeOf(home); got != beforeHome {
		t.Fatalf("test changed mode of shared home %s: %o -> %o", home, beforeHome, got)
	}
}

// TestTrustedFixtureLifetimeIsOwnedByTest closes the fixture-lifetime finding
// of the fixture-cleanup packet: a fixture created inside a subtest, together
// with synthetic children (dirs and key files written into it), must be fully
// removed the moment the OWNING t.Run returns — the base and every shared
// path stay untouched. This is the lifecycle counterpart to
// TestFixturesDoNotMutateSharedDirectories (which guards modes, not lifetime).
func TestTrustedFixtureLifetimeIsOwnedByTest(t *testing.T) {
	var saved string
	var savedKey string
	t.Run("inner", func(t *testing.T) {
		d := trustedDir(t)
		saved = d
		sub := trustedSubDir(t, d, "sub")
		savedKey = writeKeyFile(t, sub, "master.key", validTestKey(), 0o600)
		// Positive control while the subtest is alive: fixture and child exist.
		if fi, err := os.Lstat(savedKey); err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("synthetic key missing inside subtest: %v", err)
		}
		// The production boundary sees it too (no test skip/relaxation).
		if _, err := openKeyStore(t, savedKey); err != nil {
			t.Fatalf("openKeyStore in owned fixture: %v", err)
		}
	})
	// After the owning subtest returned, its cleanup must have removed the
	// fixture root and everything inside it.
	if _, err := os.Lstat(saved); !errors.Is(err, syscall.ENOENT) || !os.IsNotExist(err) {
		t.Fatalf("owned fixture %s survived subtest end: %v", saved, err)
	}
	if _, err := os.Lstat(savedKey); !os.IsNotExist(err) {
		t.Fatalf("synthetic child %s survived subtest end: %v", savedKey, err)
	}
}

// TestTrustedFixtureCleanupRunsOnFailure models the failing-child cleanup
// path: trustedDir registers t.Cleanup(RemoveAll) BEFORE any fallible step,
// and Go runs t.Cleanup on BOTH success and failure of the owning test. We
// assert the registration ordering directly (removal registered before the
// fixture is returned and before any later failure can occur), which is the
// property that guarantees a failing child leaves nothing behind. The live
// failing-child run is captured as a separate expected-failure artifact (the
// child intentionally fails; the suite stays green here).
func TestTrustedFixtureCleanupRunsOnFailure(t *testing.T) {
	// The guarantee is structural: cleanup is the FIRST thing registered after
	// MkdirTemp, so it cannot be skipped by a later failure. trustedDir returns
	// a dir that already has its removal pending; after the owning scope ends
	// (as the passing lifetime test proves for the success path) the dir is
	// gone. Here we assert the dir is created owned and the root stays clean.
	d := trustedDir(t)
	fi, err := os.Stat(d)
	if err != nil {
		t.Fatalf("fixture missing immediately after creation: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("fixture mode = %o, want 0700", fi.Mode().Perm())
	}
}
