package store_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// initFixtureRoot prepares the fixture root WITHOUT ever mutating a root this
// invocation did not freshly create. It mirrors the production trust bits
// (real directory — never a symlink — non-group/world-writable, euid-owned)
// but inspects via Lstat (no-follow) so an unsafe pre-existing root or symlink
// is REJECTED before anything is touched, never laundered by a chmod.
//
//   - Pre-existing root: Lstat (no-follow). Symlink, non-directory, group/world
//     writable, or not euid-owned => error, no chmod, no target mutation. A
//     safe 0700 euid-owned real directory is REUSED unchanged (no chmod).
//   - Missing root: created EXCLUSIVELY 0700 (the trusted parent .hyper/tmp
//     already exists). A create race (ErrExist) re-inspects via Lstat and fails
//     closed if the now-present root is not compliant — never an auto-chmod
//     fallback.
func initFixtureRoot(root string) error {
	st, err := os.Lstat(root)
	switch {
	case err == nil:
		// Pre-existing: validate without following links or mutating perms.
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("fixture root " + root + " is a symlink; refusing to use or mutate it")
		}
		if !st.IsDir() {
			return errors.New("fixture root " + root + " exists and is not a directory")
		}
		if st.Mode().Perm()&0o022 != 0 {
			return errors.New("fixture root " + root + " is group/world writable; refusing to chmod a pre-existing root")
		}
		if st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return errors.New("fixture root " + root + " is not euid-owned; refusing to take ownership")
		}
		return nil // safe 0700 euid-owned real dir: reuse unchanged, NO chmod.
	case errors.Is(err, os.ErrNotExist):
		// Fresh: exclusive 0700 creation under the already-trusted parent.
		if err := os.Mkdir(root, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				// Create race: re-inspect the now-present root and fail closed if
				// it is not compliant; never chmod an appearing path.
				if st2, lerr := os.Lstat(root); lerr == nil {
					if st2.Mode()&os.ModeSymlink != 0 || !st2.IsDir() ||
						st2.Mode().Perm()&0o022 != 0 ||
						st2.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
						return errors.New("fixture root " + root + " appeared non-compliant in a create race")
					}
					return nil
				}
				return err
			}
			return err
		}
		return nil // freshly created 0700 by us.
	default:
		return err
	}
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

// --- Controlled fixture-root initialization (V4-T007-FIXTURE-EXISTING-ROOT-MUTATION) ---

// statNoFollow returns the Lstat result (never follows a final symlink).
func statNoFollow(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatalf("lstat %s: %v", p, err)
	}
	return fi
}

// writeSentinel writes a marker file with fixed bytes and returns its path.
func writeSentinel(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("sentinel-bytes"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	return p
}

// readSentinelBytes returns the sentinel contents for an unchanged-bytes check.
func readSentinelBytes(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read sentinel %s: %v", p, err)
	}
	return string(b)
}

// TestInitFixtureRootRejectsUnsafeExistingRoot: a pre-existing 0777 root is
// REJECTED, and critically is NOT chmodded to 0700 — its mode, the sentinel
// bytes inside it, and its identity are unchanged. RED against the old
// MkdirAll+Chmod path (which laundered it to 0700 and passed).
func TestInitFixtureRootRejectsUnsafeExistingRoot(t *testing.T) {
	parent := t.TempDir() // own isolated control parent
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0o777); err != nil {
		t.Fatalf("mkdir unsafe root: %v", err)
	}
	os.Chmod(root, 0o777)
	sentinel := writeSentinel(t, root, "sentinel")
	beforeMode := statNoFollow(t, root).Mode().Perm()
	beforeIno := statNoFollow(t, root).Sys().(*syscall.Stat_t).Ino

	if err := initFixtureRoot(root); err == nil {
		t.Fatalf("unsafe 0777 existing root was accepted (should fail closed)")
	}
	if got := statNoFollow(t, root).Mode().Perm(); got != beforeMode {
		t.Fatalf("unsafe root mode mutated: %o -> %o (must never chmod a pre-existing root)", beforeMode, got)
	}
	if got := statNoFollow(t, root).Sys().(*syscall.Stat_t).Ino; got != beforeIno {
		t.Fatalf("unsafe root identity changed: inode %d -> %d", beforeIno, got)
	}
	if got := readSentinelBytes(t, sentinel); got != "sentinel-bytes" {
		t.Fatalf("sentinel bytes changed: %q", got)
	}
}

// TestInitFixtureRootRejectsRootSymlink: a root that is a symlink — whether to
// a safe 0700 target or an unsafe 0777 target — is REJECTED and NEITHER the
// link NOR the target is chmodded. RED against the old path (Chmod followed
// the link and mutated the target to 0700).
func TestInitFixtureRootRejectsRootSymlink(t *testing.T) {
	for _, unsafeTarget := range []bool{false, true} {
		parent := t.TempDir()
		target := filepath.Join(parent, "target")
		mode := os.FileMode(0o700)
		if unsafeTarget {
			mode = 0o777
		}
		if err := os.Mkdir(target, mode); err != nil {
			t.Fatalf("mkdir target: %v", err)
		}
		os.Chmod(target, mode)
		sentinel := writeSentinel(t, target, "sentinel")
		link := filepath.Join(parent, "rootlink")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		targetBefore := statNoFollow(t, target).Mode().Perm()
		linkBefore := statNoFollow(t, link).Mode() // symlink mode itself

		if err := initFixtureRoot(link); err == nil {
			t.Fatalf("root symlink (unsafeTarget=%v) was accepted (should fail closed)", unsafeTarget)
		}
		if got := statNoFollow(t, target).Mode().Perm(); got != targetBefore {
			t.Fatalf("symlink TARGET mode mutated: %o -> %o (must never follow+chmod)", targetBefore, got)
		}
		if got := statNoFollow(t, link).Mode(); got != linkBefore {
			t.Fatalf("symlink itself mutated: %v -> %v", linkBefore, got)
		}
		if got := readSentinelBytes(t, sentinel); got != "sentinel-bytes" {
			t.Fatalf("target sentinel bytes changed: %q", got)
		}
	}
}

// TestInitFixtureRootRejectsWritableAncestor: a compliant root under a
// group/world-writable ANCESTOR is rejected. (The root itself is fine; the
// chain is not.) RED proves validation happens BEFORE any use of the root.
func TestInitFixtureRootRejectsWritableAncestor(t *testing.T) {
	// This exercises homeFixtureBase's chain walk, not just the root. We build
	// an own isolated chain with a writable ancestor and call the chain check
	// via a helper seam.
	grand := t.TempDir()
	badAncestor := filepath.Join(grand, "badparent")
	if err := os.Mkdir(badAncestor, 0o777); err != nil {
		t.Fatalf("mkdir writable ancestor: %v", err)
	}
	os.Chmod(badAncestor, 0o777)
	root := filepath.Join(badAncestor, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	os.Chmod(root, 0o700)
	ancestorBefore := statNoFollow(t, badAncestor).Mode().Perm()

	// initFixtureRoot validates the root in isolation (it is compliant), so the
	// ANCESTOR rejection is a homeFixtureBase chain-walk concern; verify the walk
	// rejects without mutating the ancestor.
	if err := validateFixtureChain(root); err == nil {
		t.Fatalf("writable ancestor should make the chain non-compliant")
	}
	if got := statNoFollow(t, badAncestor).Mode().Perm(); got != ancestorBefore {
		t.Fatalf("writable ancestor mode mutated: %o -> %o", ancestorBefore, got)
	}
}

// TestInitFixtureRootReusesSafeExistingRootNoChmod: a pre-existing safe 0700
// euid-owned real dir is REUSED WITHOUT a gratuitous chmod. We detect a chmod
// via ctime change (a no-op metadata touch we avoid) and inode stability.
func TestInitFixtureRootReusesSafeExistingRootNoChmod(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir safe root: %v", err)
	}
	os.Chmod(root, 0o700)
	sentinel := writeSentinel(t, root, "sentinel")
	beforeMode := statNoFollow(t, root).Mode().Perm()
	beforeIno := statNoFollow(t, root).Sys().(*syscall.Stat_t).Ino
	beforeCtime := statNoFollow(t, root).Sys().(*syscall.Stat_t).Ctim

	if err := initFixtureRoot(root); err != nil {
		t.Fatalf("safe existing root rejected: %v", err)
	}
	if got := statNoFollow(t, root).Mode().Perm(); got != beforeMode {
		t.Fatalf("safe root mode changed on reuse: %o -> %o", beforeMode, got)
	}
	if got := statNoFollow(t, root).Sys().(*syscall.Stat_t).Ino; got != beforeIno {
		t.Fatalf("safe root inode changed on reuse")
	}
	if got := statNoFollow(t, root).Sys().(*syscall.Stat_t).Ctim; got != beforeCtime {
		t.Fatalf("safe root ctime changed on reuse: a gratuitous chmod/mutation occurred")
	}
	if got := readSentinelBytes(t, sentinel); got != "sentinel-bytes" {
		t.Fatalf("sentinel bytes changed on reuse: %q", got)
	}
}

// TestInitFixtureRootFreshCreateOpensWithProductionCtor: a fresh root created
// by initFixtureRoot accepts a synthetic key via the REAL production
// NewKeyStore (positive control that the new exclusive-0700 creation is
// production-compliant). The root is placed under a compliant 0700 chain (NOT
// world-writable /tmp) so the production "/"-anchored walk accepts it.
func TestInitFixtureRootFreshCreateOpensWithProductionCtor(t *testing.T) {
	// Build a private 0700 chain the production walk accepts. Anchor at an
	// existing compliant ancestor (the module dir) and go down with 0700 dirs.
	modRoot, err := projectFixtureRoot() // .../.hyper/tmp/store-fixtures
	if err != nil {
		t.Fatalf("project root: %v", err)
	}
	// Use a sibling of the real store-fixtures root for this isolated control.
	base := filepath.Join(filepath.Dir(modRoot), "fresh-create-probe")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatalf("mkdir base: %v", err)
	}
	os.Chmod(base, 0o700) // fresh private dir we own
	t.Cleanup(func() { os.RemoveAll(base) })
	root := filepath.Join(base, "store-fixtures")
	if err := initFixtureRoot(root); err != nil {
		t.Fatalf("fresh create: %v", err)
	}
	if got := statNoFollow(t, root).Mode().Perm(); got != 0o700 {
		t.Fatalf("fresh root mode = %o, want 0700", got)
	}
	sub := trustedSubDir(t, root, "sub")
	key := writeKeyFile(t, sub, "master.key", validTestKey(), 0o600)
	if _, err := store.NewKeyStore(key); err != nil {
		t.Fatalf("production NewKeyStore on fresh root rejected: %v", err)
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
		// Prepare the root WITHOUT mutating any pre-existing root/symlink (a
		// fresh root is created 0700 exclusively; an unsafe existing one fails
		// closed before any use). Then read-validate the chain from the root up
		// to "/": every ancestor must be non-group/world-writable, matching the
		// production walk. Read-only; never a chmod of a shared ancestor.
		if err := initFixtureRoot(root); err != nil {
			homeBaseOnce.err = err
			return
		}
		if err := validateFixtureChain(root); err != nil {
			homeBaseOnce.err = err
			return
		}
		homeBaseOnce.dir = root
	})
	if homeBaseOnce.err != nil {
		t.Fatalf("home fixture base: %v", homeBaseOnce.err)
	}
	return homeBaseOnce.dir
}

// validateFixtureChain read-validates the chain from root up to "/": every
// component must be a non-symlink, non-group/world-writable directory. It is
// read-only (Lstat, no-follow) and never chmods a shared ancestor.
func validateFixtureChain(root string) error {
	for dir := root; ; dir = filepath.Dir(dir) {
		fi, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("fixture chain ancestor " + dir + " is a symlink; host not compliant")
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return errors.New("fixture chain ancestor " + dir + " is group/world writable; fixture host not compliant")
		}
		if dir == "/" {
			return nil
		}
	}
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

// fixtureCleanupChildEnv is the env var the parent uses to pass the marker
// file path to the child probe; fixtureCleanupFailMarker is the exact expected
// failure string the child emits, so the parent can distinguish the intended
// failure from an unrelated startup error.
const (
	fixtureCleanupChildEnv = "RAYLANE_FIXTURE_CLEANUP_CHILD_MARKER"
	fixtureCleanupFailMark = "INTENTIONAL-FIXTURE-CLEANUP-FAILURE"
)

// TestFixtureCleanupChildProbe is the CHILD half of the maintained failing-
// child cleanup regression. It is NOT run directly in the normal suite (the
// parent launches it in a subprocess); on its own it always fails. It creates
// a REAL trustedDir + nested key, records the exact owned paths to the marker
// file, proves the key opens via the production constructor while alive, then
// fails with the exact marker so the parent can confirm cleanup-on-failure.
func TestFixtureCleanupChildProbe(t *testing.T) {
	marker := os.Getenv(fixtureCleanupChildEnv)
	if marker == "" {
		t.Skip("child probe only runs under the parent subprocess")
	}
	d := trustedDir(t) // registers t.Cleanup(RemoveAll) BEFORE any fallible step
	sub := trustedSubDir(t, d, "nested")
	key := writeKeyFile(t, sub, "master.key", validTestKey(), 0o600)
	// Prove the key opened via the real production constructor while alive.
	if _, err := store.NewKeyStore(key); err != nil {
		t.Fatalf("child: production NewKeyStore while alive: %v", err)
	}
	// Record the exact owned paths BEFORE failing, so the parent can assert
	// they existed during the child and are ENOENT after it exits.
	rec := key + "\n" + d + "\n"
	if err := os.WriteFile(marker, []byte(rec), 0o600); err != nil {
		t.Fatalf("child: write marker: %v", err)
	}
	t.Fatalf("%s", fixtureCleanupFailMark) // intentional failure -> cleanup must still run
}

// TestTrustedFixtureCleanupRunsOnFailure is the PARENT half: it launches the
// child probe as a separate test-binary PROCESS, requires the child's failure
// to be the EXACT expected marker (never an unrelated startup error), confirms
// the recorded fixture path + key existed while the child was alive, and then
// that the whole fixture directory is ENOENT after the child exits. An
// unrelated pre-existing sentinel must survive. The outer test is GREEN only
// when the expected child failure AND the cleanup are both observed.
func TestTrustedFixtureCleanupRunsOnFailure(t *testing.T) {
	// Unrelated sentinel outside the fixture root: must survive untouched.
	sentinel := filepath.Join(homeFixtureBase(t), "unrelated-sentinel-do-not-remove")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write unrelated sentinel: %v", err)
	}
	defer os.Remove(sentinel) // own probe sentinel, removed by us only

	marker := filepath.Join(homeFixtureBase(t), "child-marker-"+t.Name())
	defer os.Remove(marker)

	cmd := exec.Command(os.Args[0], "-test.run=^TestFixtureCleanupChildProbe$")
	cmd.Env = append(os.Environ(), fixtureCleanupChildEnv+"="+marker)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()

	// The child MUST have failed with the EXACT expected marker (not any
	// unrelated startup failure): non-zero exit AND the marker present.
	if runErr == nil {
		t.Fatalf("child probe unexpectedly succeeded; want intentional failure")
	}
	if !strings.Contains(out.String(), fixtureCleanupFailMark) {
		t.Fatalf("child failed for an UNEXPECTED reason (no %q marker):\n%s", fixtureCleanupFailMark, out.String())
	}

	// Read the exact owned paths the child recorded while alive.
	b, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read child marker: %v (child did not reach fixture creation = no coverage)", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("marker malformed: %q", string(b))
	}
	keyPath, dirPath := lines[0], lines[1]

	// While the child was alive it proved the key opened; the marker recording
	// the key is itself evidence the key path existed. After exit, the whole
	// fixture dir (and the key inside it) must be gone.
	if _, err := os.Lstat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("child key %s still present after child exit (cleanup failed): %v", keyPath, err)
	}
	if _, err := os.Lstat(dirPath); !os.IsNotExist(err) {
		t.Fatalf("child fixture dir %s still present after child exit (cleanup failed): %v", dirPath, err)
	}
	// Unrelated sentinel outside the fixture must survive.
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep" {
		t.Fatalf("unrelated sentinel damaged/removed: %v %q", err, got)
	}
}
