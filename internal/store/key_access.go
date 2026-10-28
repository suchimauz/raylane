package store

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"os"
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

// NewKeyStore opens the master key at an absolute, cleaned path and
// establishes the full trust chain strictly descriptor-relatively (see
// openTrustedKeyChain). The PATH SHAPE rules live in exactly ONE place —
// ValidateKeyPathShape, which NewKeyStore calls first — so any operator-facing
// preflight can validate the identical shape with zero filesystem IO. After
// Clean never dereferences symlinks, requiring the already-cleaned canonical
// spelling rejects ".", "..", "//" and trailing-slash trickery before any
// syscall; every remaining literal component is then opened no-follow
// regardless of what it points at.
func NewKeyStore(keyPath string) (*KeyStore, error) {
	rel, err := ValidateKeyPathShape(keyPath)
	if err != nil {
		return nil, err
	}
	return openTrustedKeyChain(rel)
}

// ValidateKeyPathShape applies the EXACT pure path-shape rules NewKeyStore
// applies before its first syscall: linux-only, absolute, already-cleaned
// (canonical spelling), not root, and no empty/"."/".." component. It opens
// NOTHING and states nothing about existence, ownership or mode — those remain
// the trust-chain checks of openTrustedKeyChain. The returned rel is the
// slash-escaped root-relative path used by the chain walker. The error is the
// same fixed secret-free ErrKeyUnavailable as every other key rejection.
func ValidateKeyPathShape(keyPath string) (rel string, err error) {
	if !filepath.IsAbs(keyPath) || runtime.GOOS != "linux" {
		return "", ErrKeyUnavailable
	}
	clean := filepath.Clean(keyPath)
	if clean != keyPath || clean == "/" {
		return "", ErrKeyUnavailable
	}
	rel = strings.TrimPrefix(clean, "/")
	for _, c := range strings.Split(rel, "/") {
		if c == "" || c == "." || c == ".." {
			return "", ErrKeyUnavailable
		}
	}
	return rel, nil
}

// openTrustedKeyChain resolves a CLEANED, escape-free, slash-separated
// RELATIVE key path anchored at the process filesystem root, entirely
// descriptor-relatively. The invariant, primitive by primitive:
//
//   - Anchor: syscall.Open(AT_FDCWD, "/", O_RDONLY|O_DIRECTORY|O_CLOEXEC).
//     Opening "/" traverses no component, so the fd IS the kernel's root
//     identity for this mount namespace — the existing production trust
//     anchor, not a re-declared parent, no forged ancestors, and no invented
//     home-prefix or /tmp exception.
//   - Every subsequent step is the raw Linux openat(2) via
//     syscall.Openat(parentFd, ONE literal component,
//     O_RDONLY|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC, 0). On a symlink the kernel
//     returns ELOOP and that error is RETURNED — never caught and turned into
//     a link-following resolver. os.Root.OpenRoot is deliberately NOT used:
//     Go 1.27.3 os/root_unix.go openRootInRoot catches this same ELOOP via
//     isNoFollowErr→checkSymlink→readlinkat and CONTINUES resolution on the
//     contained target (its docs state contained symlinks "should be
//     followed"), which silently reopens the ancestor-symlink class this
//     function exists to close. syscall.Openat itself wraps nothing: the
//     stdlib syscall_linux.go shows the exported func calls the //sys
//     openat directly, only OR-ing in O_LARGEFILE.
//   - Every opened directory fd is validated by fstat ON ITS OWN DESCRIPTOR
//     (fstatDirInfo) before descending — a real directory, not group/world
//     writable (sticky world-writable /tmp fails like any other), owned by
//     the effective service user or root. No pathname is re-resolved after a
//     check: there is no Lstat/EvalSymlinks-then-Open race, no TOCTOU window.
//   - The final object is opened through its fully validated parent fd with
//     syscall.Openat(parentFd, base, O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,
//     0) — no-follow even for the last component, non-blocking so a FIFO can
//     never hang the open before fstat — then fstat: regular file, exactly
//     0600, owned by the effective user, content exactly 32 bytes.
//
// Every rejection is the same fixed secret-free ErrKeyUnavailable. All
// descriptors opened here are closed on every success and error path.
func openTrustedKeyChain(rel string) (*KeyStore, error) {
	rootFd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	fds := []int{rootFd} // every fd this function opens; all closed at return
	defer func() {
		for _, fd := range fds {
			syscall.Close(fd)
		}
	}()
	if err := checkTrustedDirFd(rootFd); err != nil { // same predicate as any component
		return nil, err
	}
	return openTrustedKeyFromValidatedAnchor(rootFd, rel)
}

// openTrustedKeyFromValidatedAnchor is the single chain body: every
// component open, fstat and the final no-follow open below an already
// validated anchor descriptor. Its only production caller is
// openTrustedKeyChain, which passes the "/" anchor fd it opened and
// validated itself — production has NO anchor-parameterized entry point of
// any kind, exported or unexported. (If a future test ever needs a fixture
// anchor, the bridge must be a _test.go file wrapping this body, per the
// T007 correction-2 packet; no such seam exists in this build.)
func openTrustedKeyFromValidatedAnchor(anchorFd int, rel string) (*KeyStore, error) {
	parts := strings.Split(rel, "/")
	parent := anchorFd
	var opened []int // fds this call opened; the anchor fd is NOT ours to close
	defer func() {
		for _, fd := range opened {
			syscall.Close(fd)
		}
	}()
	for _, comp := range parts[:len(parts)-1] {
		fd, err := syscall.Openat(parent, comp,
			syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, ErrKeyUnavailable // incl. ELOOP on any symlink ancestor
		}
		opened = append(opened, fd)
		if err := checkTrustedDirFd(fd); err != nil {
			return nil, err
		}
		parent = fd
	}
	keyFd, err := syscall.Openat(parent, parts[len(parts)-1],
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrKeyUnavailable // no-follow + nonblock: link or FIFO fails here
	}
	st, err := fstatStat(keyFd)
	if err != nil || !statIsRegular(st) {
		syscall.Close(keyFd)
		return nil, ErrKeyUnavailable
	}
	if err := checkOwnedRegular(st); err != nil {
		syscall.Close(keyFd)
		return nil, err
	}
	// os.NewFile hands keyFd to an *os.File for the read. poll.FD.Close
	// closes the descriptor exactly once (fd_mutex increfAndClose; verified
	// in internal/poll/fd_{unix,mutex}.go before relying on it), so keyFd is
	// intentionally NOT appended to opened and f.Close is its single owner.
	f := os.NewFile(uintptr(keyFd), "key")
	defer f.Close()
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

// checkTrustedDirFd fstats one OPENED directory descriptor and enforces the
// single chain predicate: real directory, not group/world writable, owned by
// the effective service user or root (the provisioning owner). Tests face the
// identical predicate — there is no /tmp or any other exemption. The check
// happens on the descriptor the walk actually continues from, never on a
// re-resolved pathname.
func checkTrustedDirFd(fd int) error {
	st, err := fstatStat(fd)
	if err != nil || !statIsDir(st) {
		return ErrKeyUnavailable
	}
	if st.Mode&0o022 != 0 {
		return ErrKeyUnavailable // group/world writable, sticky /tmp included
	}
	if st.Uid != uint32(os.Geteuid()) && st.Uid != 0 {
		return ErrKeyUnavailable // neither the service user nor provisioning root
	}
	return nil
}

// fstatStat performs a pure fstat(2) on an open descriptor. It cannot
// involve pathname resolution or symlink inspection: the result describes
// exactly the object the fd refers to. It deliberately does NOT wrap the fd
// in os.NewFile — a poll-managed File whose finalizer runs would close a
// descriptor this function does not own, corrupting unrelated later opens
// (observed as EBADF on a subsequent openat). The descriptor is never
// closed here; ownership stays with the caller's sweep.
func fstatStat(fd int) (*syscall.Stat_t, error) {
	var st syscall.Stat_t
	for {
		err := syscall.Fstat(fd, &st)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		return &st, nil
	}
}

// statIsDir reports whether an fstat result describes a real directory.
func statIsDir(st *syscall.Stat_t) bool {
	return st.Mode&syscall.S_IFMT == syscall.S_IFDIR
}

// statIsRegular reports whether an fstat result describes a regular file.
func statIsRegular(st *syscall.Stat_t) bool {
	return st.Mode&syscall.S_IFMT == syscall.S_IFREG
}

// checkOwnedRegular enforces the ownership rule on an fstat result: the file
// must be owned by the effective user opening it. Group equality is
// deliberately not required — that is the normal case under an application
// umask (e.g. 002), and group access is already forbidden by the permission
// check above. This validates the OPENED object via its descriptor, not a
// prior path stat.
func checkOwnedRegular(st *syscall.Stat_t) error {
	if st == nil {
		return ErrKeyUnavailable
	}
	if st.Mode&0o077 != 0 {
		return ErrKeyUnavailable // group or world access is unsafe
	}
	if st.Mode&0o700 != 0o600 {
		return ErrKeyUnavailable // expect exactly rw-------
	}
	if st.Uid != uint32(os.Geteuid()) {
		return ErrKeyUnavailable
	}
	return nil
}

// Version reports the fixed key generation in use.
func (k *KeyStore) Version() int { return k.ver }

// aead returns the established standard-library AEAD for this key:
// AES-256-GCM with fresh random 96-bit nonces prepended by Seal and extracted
// by Open (cipher.NewGCMWithRandomNonce). Overhead is 28 bytes (nonce + tag).
// A given key MUST NOT seal more than 2^32 messages; at that point a human
// operator must provision a new key generation — automatic rotation is not
// implemented and not claimed.
func (k *KeyStore) aead() (cipher.AEAD, error) {
	return cipher.NewGCMWithRandomNonce(k.aes)
}
