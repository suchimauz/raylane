package store

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"
)

// KeyVersion is the only key generation this package understands. It is
// recorded with every sealed record; records carrying any other version fail
// closed with ErrSecretAuth. Key rotation and multi-key lifecycle are NOT
// implemented in T007 and are not claimed.
const KeyVersion = 1

// keyFileMode is the exact expected length of the master key file: one 256-bit
// AES key, nothing else. There is no header, no padding and no KDF.
const keyFileMode = os.FileMode(0600)

// KeyStore opens and validates the service master key from the trusted,
// service-configured location. The path is never request-supplied. Opening
// ordinary configuration storage never requires the key: NewKeyStore is an
// explicit initialization boundary of the secret store, and its failure is a
// fail-closed condition, never a plaintext fallback.
type KeyStore struct {
	aes cipher.Block
	ver int
}

// NewKeyStore opens the master key at path and validates the OPENED OBJECT,
// not a prior path stat. It fails closed with ErrKeyUnavailable for:
// missing/unreadable file, wrong length (not exactly 32 bytes), non-regular
// file, a symlink at the final path component (O_NOFOLLOW rejects opening it
// at all), group/world-readable permissions, or an owner other than the
// effective service user. The parent directory must also be trusted: owned by
// the same effective user and not group/world writable, so an untrusted
// process cannot swap the key out from under the service. No key is ever
// created, regenerated or logged here.
func NewKeyStore(path string) (*KeyStore, error) {
	// Reject a symlink at the final component before opening, then validate
	// the object actually reached through the opened descriptor below.
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, ErrKeyUnavailable
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	defer f.Close()

	// Validate the opened descriptor itself (fstat): regular file, exact
	// owner, no group/world access bits. A stat-then-open race cannot make us
	// trust a different object, because these facts are about the fd we read.
	st, err := f.Stat()
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	if !st.Mode().IsRegular() {
		return nil, ErrKeyUnavailable
	}
	if err := checkOwnedRegular(st.Mode(), st); err != nil {
		return nil, err
	}
	// The trusted parent directory boundary: not group/world writable, and
	// owned by the effective service user or root (the provisioning owner).
	// A world-writable sticky directory such as the system /tmp fails the
	// write-bit check even though root owns it, because any local process
	// could swap the key file there.
	di, err := os.Stat(parentDir(path))
	if err != nil || !di.IsDir() {
		return nil, ErrKeyUnavailable
	}
	if di.Mode().Perm()&0o022 != 0 {
		return nil, ErrKeyUnavailable
	}
	if !trustedOwner(di) {
		return nil, ErrKeyUnavailable
	}

	key, err := io.ReadAll(io.LimitReader(f, 33)) // one byte over the exact size suffices to detect "too long"
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

// trustedOwner accepts a directory owned by the effective service user or by
// root (the provisioning owner of a service key location). Group/world write
// is rejected separately by the caller's permission check.
func trustedOwner(di os.FileInfo) bool {
	sys, ok := di.Sys().(*syscall.Stat_t)
	if !ok {
		return runtime.GOOS == "windows"
	}
	return sys.Uid == uint32(os.Geteuid()) || sys.Uid == 0
}

func parentDir(path string) string {
	for i := len(path); i > 0; i-- {
		if path[i-1] == '/' {
			if i == 1 {
				return "/"
			}
			return path[:i-1]
		}
	}
	return "."
}

var _ = fmt.Sprintf
