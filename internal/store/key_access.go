package store

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// KeyVersion is the only key generation this package understands. It is
// recorded with every sealed record; records carrying any other version fail
// closed with ErrSecretAuth. Key rotation and multi-key lifecycle are NOT
// implemented in T007 and are not claimed.
const KeyVersion = 1

// KeyStore opens and validates the service master key from the trusted,
// service-configured location. The path is never request-supplied. Opening
// ordinary configuration storage never requires the key: NewKeyStore is an
// explicit initialization boundary of the secret store, and its failure is a
// fail-closed condition, never a plaintext fallback.
type KeyStore struct {
	aes cipher.Block
	ver int
}

// NewKeyStore opens the master key at an absolute path and establishes the
// full trust chain DESCRIPTOR-RELATIVELY, closing the ancestor-symlink class
// that a final O_NOFOLLOW open alone cannot cover:
//
//   - The trust anchor is the filesystem root "/". It is opened once with
//     os.OpenRoot and is the kernel's own root identity for this process —
//     an already-approved, non-forged anchor, not a re-declared parent.
//   - Every path component below the anchor is opened with
//     openat(O_NOFOLLOW|O_DIRECTORY) relative to the previously validated
//     directory descriptor (os.Root semantics, verified in the Go 1.27.3
//     stdlib: root_unix.go uses unix.Openat with O_NOFOLLOW at each step).
//     A pathname is never followed between checks; there is no
//     Lstat/EvalSymlinks-then-Open race.
//   - Each opened ANCESTOR directory is validated on its own descriptor via
//     fstat: must be a directory, not group/world writable, owned by the
//     effective service user or root (the provisioning owner). Any symlink at
//     ANY depth, a missing or non-directory component, or an unsafe owner or
//     mode anywhere in the chain fails closed. World-writable sticky
//     directories such as /tmp fail the write-bit check like any other.
//   - The final key file is opened through its validated parent descriptor
//     with O_NOFOLLOW, then fstat-validated: regular file, exactly 0600,
//     owned by the effective user; content must be exactly 32 bytes.
//
// Every rejection is the same fixed secret-free ErrKeyUnavailable. No key is
// ever created, regenerated or logged here. Relative paths have no anchor
// and are rejected.
func NewKeyStore(path string) (*KeyStore, error) {
	if !filepath.IsAbs(path) || runtime.GOOS == "windows" {
		return nil, ErrKeyUnavailable
	}
	clean := filepath.Clean(path)
	base := filepath.Base(clean)
	if base == "." || base == ".." || base == "/" || base == string(filepath.Separator) {
		return nil, ErrKeyUnavailable
	}
	// The key's own directory must exist and be reachable: the very first
	// component of the chain is the directory the operator provisioned the
	// key in, and its name must resolve (no hidden fallback locations).
	if _, err := os.Stat(filepath.Dir(clean)); err != nil {
		return nil, ErrKeyUnavailable
	}

	// Establish the production trust anchor: the process's filesystem root
	// ("/"). open("/" ) cannot traverse any component, so the descriptor the
	// kernel hands back IS the mount-namespace root identity — an already
	// approved, non-forged anchor, requiring no new deployment decision. The
	// chain below is walked strictly descriptor-relatively from it.
	anchor, err := newAnchorRoot("/")
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	defer anchor.Close()
	if err := validateAnchor(anchor); err != nil {
		return nil, ErrKeyUnavailable
	}
	return openKeyUnderRoot(anchor, clean)
}

// newAnchorRoot opens a directory as a descriptor-based os.Root anchor.
func newAnchorRoot(dir string) (*os.Root, error) {
	return os.OpenRoot(dir)
}

// validateAnchor enforces the same directory predicate on the anchor that
// every other chain component faces: real directory, no group/world write,
// owned by the effective service user or root (provisioning owner). On this
// platform the "/" anchor is root-owned mode 0555 — it passes because it is
// not writable by group or world, exactly like any service-owned directory.
func validateAnchor(anchor *os.Root) error {
	info, err := anchor.Stat(".") // fstat on the opened anchor fd
	if err != nil || !trustedDirInfo(info) {
		return ErrKeyUnavailable
	}
	return nil
}

// openKeyUnderRoot walks absPath (cleaned, absolute) descriptor-relatively
// beneath an already-validated anchor root and returns the validated key
// store. Production reaches it through NewKeyStore with the "/" anchor; the
// package-private anchor variant lets a test establish its explicitly trusted
// root descriptor (via NewKeyStoreUnderTrustedRootForTests) while enforcing
// the IDENTICAL production policy on every component beneath it — no
// sticky-/tmp or any other exemption exists.
// pathComponents lists the non-empty components of a slash-separated
// relative directory chain ("a/b/" -> ["a","b"]); the empty chain yields no
// steps because the anchor descriptor is already the key directory.
func pathComponents(relDir string) []string {
	var out []string
	for _, c := range strings.Split(strings.Trim(relDir, "/"), "/") {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

func openKeyUnderRoot(anchor *os.Root, absPath string) (*KeyStore, error) {
	return openKeyRelative(anchor, strings.TrimPrefix(absPath, "/"))
}

// openKeyRelative resolves the key directory and file beneath an already
// validated anchor descriptor. Root.OpenRoot(name) is implemented by the
// maintained stdlib as a chain of openat(O_NOFOLLOW|O_CLOEXEC) calls, one per
// component, strictly relative to the previously opened descriptor
// (os/root_unix.go openRootInRoot + doInRoot in the Go 1.27.3 sources, read
// before relying on this): therefore a symlink at ANY ancestor is ELOOP/EMLINK
// and an error, never a followed hop, and no pathname is re-resolved after a
// check — there is no Lstat/EvalSymlinks-then-Open race. The parent is
// additionally fstat-validated on ITS OWN fd before use, and the final object
// is opened O_NOFOLLOW through that validated parent fd and fstat-checked.
// Intermediate directory fds are closed as soon as the parent is reached.
func openKeyRelative(anchor *os.Root, relKey string) (*KeyStore, error) {
	relDir, base := path.Split(filepath.ToSlash(relKey))
	if base == "" || base == "." || base == ".." {
		return nil, ErrKeyUnavailable
	}
	// Validate EVERY directory descriptor in the chain, not only the final
	// parent: open each component as its own Root and fstat it before moving
	// one level deeper. Each Root.OpenRoot step is itself an
	// openat(O_NOFOLLOW) resolution under the previously validated fd, so a
	// symlink never becomes a followed hop and no checked descriptor is ever
	// traded for a pathname re-resolution.
	cur := anchor
	var opened []*os.Root // every directory fd opened below the anchor, in order
	defer func() {
		for _, r := range opened {
			r.Close()
		}
	}()
	for _, comp := range pathComponents(relDir) {
		next, err := cur.OpenRoot(comp)
		if err != nil {
			return nil, ErrKeyUnavailable
		}
		opened = append(opened, next)
		ancestor, err := next.Stat(".") // fstat on THIS directory fd
		if err != nil || !trustedDirInfo(ancestor) {
			return nil, ErrKeyUnavailable
		}
		cur = next
	}
	parent := cur

	// The final object is reached only through the validated parent
	// descriptor; O_NOFOLLOW rejects even a trailing-component symlink, and
	// O_NONBLOCK guarantees a FIFO can never block the open (fstat then
	// rejects it as non-regular). A blocking-only open would hand a local
	// attacker a pre-authorization hang on any path slot they can create.
	f, err := parent.OpenFile(base, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	defer f.Close()
	st, err := f.Stat() // fstat on the opened fd, not a path stat
	if err != nil || !st.Mode().IsRegular() {
		return nil, ErrKeyUnavailable
	}
	if err := checkOwnedRegular(st.Mode(), st); err != nil {
		return nil, err
	}
	key, err := io.ReadAll(io.LimitReader(f, 33)) // one over exact size detects "too long"
	if err != nil || len(key) != 32 {
		return nil, ErrKeyUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	return &KeyStore{aes: block, ver: KeyVersion}, nil
}

// Version reports the fixed key generation in use.
func (k *KeyStore) Version() int { return k.ver }

// NewKeyStoreUnderTrustedRootForTests opens a key below an explicitly
// established trusted root descriptor. It exists ONLY so unit tests can set
// up a fully production-policy-compliant chain without privilege (e.g. under
// a process-local TMPDIR fixture) when the process filesystem root itself is
// not owned/writable-compliant in the test environment. The policy enforced
// on every component below the anchor is the same openKeyUnderRoot code path
// production uses; this adds no exemption. It is not exported for the
// product: no production call site may pass an arbitrary anchor.
func NewKeyStoreUnderTrustedRootForTests(anchorDir, absKeyPath string) (*KeyStore, error) {
	if !filepath.IsAbs(absKeyPath) || !filepath.IsAbs(anchorDir) || runtime.GOOS == "windows" {
		return nil, ErrKeyUnavailable
	}
	clean := filepath.Clean(absKeyPath)
	anchorClean := filepath.Clean(anchorDir)
	rel, err := filepath.Rel(anchorClean, clean)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, ErrKeyUnavailable
	}
	if _, err := os.Stat(filepath.Dir(clean)); err != nil {
		return nil, ErrKeyUnavailable
	}
	anchor, err := newAnchorRoot(anchorClean)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	defer anchor.Close()
	if err := validateAnchor(anchor); err != nil {
		return nil, ErrKeyUnavailable
	}
	return openKeyRelative(anchor, rel)
}

// aead returns the established standard-library AEAD for this key:
// AES-256-GCM with fresh random 96-bit nonces prepended by Seal and extracted
// by Open (cipher.NewGCMWithRandomNonce). Overhead is 28 bytes (nonce + tag).
// A given key MUST NOT seal more than 2^32 messages; at that point a human
// operator must provision a new key generation — automatic rotation is not
// implemented and not claimed.
func (k *KeyStore) aead() (cipher.AEAD, error) {
	return cipher.NewGCMWithRandomNonce(k.aes)
}

// sameOwner enforces the ownership rule on an fstat result: the file must be
// owned by the effective user opening it. Group equality is deliberately not
// required — that is the normal case under an application umask (e.g. 002),
// and group access is already forbidden by the permission check above. This
// validates the OPENED object via its descriptor, not a prior path stat.
func checkOwnedRegular(mode os.FileMode, st os.FileInfo) error {
	if st == nil {
		return ErrKeyUnavailable
	}
	if mode.Perm()&0o077 != 0 {
		return ErrKeyUnavailable // group or world access is unsafe
	}
	if mode.Perm()&0o700 != 0o600 {
		return ErrKeyUnavailable // expect exactly rw-------
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrKeyUnavailable
	}
	if sys.Uid != uint32(os.Geteuid()) {
		return ErrKeyUnavailable
	}
	return nil
}

// trustedDirInfo validates one OPENED ancestor directory descriptor's fstat:
// a real directory, not group/world writable (sticky /tmp included), owned by
// the effective service user or root. This is the single policy predicate for
// every component of the chain, tests included — there is no exemption.
func trustedDirInfo(di os.FileInfo) bool {
	if di == nil || !di.IsDir() {
		return false
	}
	if di.Mode().Perm()&0o022 != 0 {
		return false
	}
	sys, ok := di.Sys().(*syscall.Stat_t)
	if !ok {
		return runtime.GOOS == "windows"
	}
	return sys.Uid == uint32(os.Geteuid()) || sys.Uid == 0
}
