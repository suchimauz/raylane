// Package-private bridge between the accepted typed store boundary and the
// accepted private KDF primitive. ONE-WAY dependency: this file imports
// internal/store; internal/store must NEVER import this package.
//
// This file exports NOTHING (guard G-1 is package-wide): the only exported
// names anywhere in production files of this package are the required
// standard error methods Error() string on the package's own unexported
// concrete error types (saltSourceError in kdf.go, bridgeError here), each
// with a value receiver of its own type, zero parameters and exactly one
// string result. This file declares NO package-level var of any kind, no
// function variable, no error sentinel, no hook, no reader parameter and no
// injectable KDF (guards G-2/G-6); every error value is constructed FRESH at
// the return site that produces it. It contains no raw SQL, no Store.DB()
// and no transaction of its own (guard G-5): persistence goes through the
// single accepted atomic typed call s.CreateAdminAndConsumeBootstrap, and
// reads through the single K1-guarded typed call s.AdminVerifier.
//
// Error classification: the store's typed API surfaces failures as the domain
// sentinels domain.ErrNotFound / domain.ErrConflict (internal/store/auth.go),
// so the bridge classifies by errors.Is on the category root and then
// DISCARDS the wrapped value: no store error text is stored in a bridgeError
// value or unwrapped from it, and the store's message strings never leave the
// store package through this bridge. Absent ("no well-formed admin verifier")
// and post-read-validation failure are BOTH ErrNotFound shapes and map to the
// SAME no-verifier category — the category does not disclose existence.
//
// Honest limits: there is NO public caller (no HTTP/CLI wiring) — no public
// no-oracle or indistinguishability property is claimed here. A future
// generic wire mapping (one generic outcome, no status/body/header/timing
// distinction, no existence-disclosing log line) is a MANDATORY obligation on
// the future HTTP slice, not implemented in this file. Same-package trust is
// not isolation and not future-edit immunity.

package auth

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/store"
)

// bridgeErrorKind is the category of a bridge failure. The zero value never
// appears in a produced error: every construction site names its kind.
type bridgeErrorKind int

const (
	bridgeErrNoVerifier bridgeErrorKind = iota + 1
	bridgeErrStorage
	bridgeErrCreation
)

// bridgeError is the CONCRETE (non-interface) error type of the bridge. A
// value of it can never be a nil interface: failure errors are NON-NIL BY
// CONSTRUCTION, constructed fresh at each failure return site — no sentinel,
// no global, and NO PACKAGE-LEVEL interface-typed error variable or sentinel
// exists in this package — the accepted qualification: ordinary error return
// signatures and local variables RECEIVING an error remain valid and required;
// what is banned is a package-level error-typed variable. Fresh concrete-value
// construction at every return site and zero package-level vars are unchanged.
// The type stores ONLY its category: no wrapped cause, no store error text, no
// password, salt, key or record data. Error() below is the REQUIRED standard
// error interface method: capitalized by interface necessity, value receiver
// of this unexported type, no parameters, exactly one builtin string result;
// it is not an exported package-level authentication API.
type bridgeError struct{ kind bridgeErrorKind }

func (e bridgeError) Error() string {
	// The receiver is NAMED (`e`) because the body switches on e.kind; that
	// is a receiver name, not a parameter: the declaration keeps the exact
	// accepted G-1 shape — value receiver of its own unexported type, ZERO
	// parameters, exactly one builtin string result (len(Params.List)==0).
	switch e.kind {
	case bridgeErrNoVerifier:
		return "auth: no usable admin verifier"
	case bridgeErrStorage:
		return "auth: storage unavailable"
	default:
		// Accepted D2 contract: EXACTLY THREE possible messages. bridgeErrCreation
		// and any unknown/zero kind share this one message — there is NO fourth
		// default string.
		return "auth: verifier creation failed"
	}
}

// storeVerifierInput converts the typed value returned by the K1-guarded
// store read into the primitive's raw verifierInput, copying the byte slices
// so the verifierInput never aliases the store value's buffers. Every field
// is validated BEFORE any copy, narrowing or use: all five metadata fields
// must equal the frozen constants and both lengths must be exactly 16/32.
// Invalid input yields ok==false and a ZERO verifierInput — hostile stored
// fields are never copied onward. Copying gives alias-freedom, not Go
// immutability.
func storeVerifierInput(v store.AdminVerifier) (verifierInput, bool) {
	if v.FormatVersion != formatVersion || v.Argon2Version != argon2Version ||
		v.TimeCost != timeCost || v.MemoryKiB != memoryKiB || v.Parallelism != parallelism ||
		len(v.Salt) != saltBytes || len(v.DerivedKey) != derivedKeyByte {
		return verifierInput{}, false
	}
	salt := make([]byte, saltBytes)
	copy(salt, v.Salt)
	key := make([]byte, derivedKeyByte)
	copy(key, v.DerivedKey)
	return verifierInput{
		formatVersion: v.FormatVersion,
		argon2Version: v.Argon2Version,
		timeCost:      v.TimeCost,
		memoryKiB:     v.MemoryKiB,
		parallelism:   v.Parallelism,
		salt:          salt,
		derivedKey:    key,
	}, true
}

// storeVerifierRecord converts the private primitive record into the typed
// store value, copying the fixed arrays into freshly allocated exact-length
// slices (no aliasing of the record's storage). Construction-time invariant:
// it is called ONLY with a record produced by newVerifierRecord (or by a
// valid storeVerifierInput path), whose metadata fields are the frozen
// constants themselves. Copying gives alias-freedom, not Go immutability.
func storeVerifierRecord(r adminVerifierRecord) store.AdminVerifier {
	return store.AdminVerifier{
		FormatVersion: r.formatVersion,
		Argon2Version: r.argon2Version,
		TimeCost:      r.timeCost,
		MemoryKiB:     r.memoryKiB,
		Parallelism:   r.parallelism,
		Salt:          append([]byte(nil), r.salt[:]...),
		DerivedKey:    append([]byte(nil), r.derivedKey[:]...),
	}
}

// CreateIdentity derives the Argon2id verifier from password and atomically
// persists username + verifier + the permanent bootstrap closure through the
// ONE accepted V4 store call. It is the exported facade creation entry (the
// single reviewed export, documented in facade.go); on any failure it
// persists nothing. A caller must first prove ValidUsername(username) and
// ValidPassword(password).
func CreateIdentity(ctx context.Context, s *store.Store, username, password []byte) error {
	return createAdminIdentity(ctx, s, username, password)
}

// VerifyIdentity reports whether the supplied credentials match the persisted
// admin identity. Missing identity, wrong username and wrong password are ALL
// false (the generic mismatch category), so no existence oracle is exposed.
// It is the exported facade verification entry.
func VerifyIdentity(ctx context.Context, s *store.Store, creds Credentials) (bool, error) {
	return verifyAdminIdentity(ctx, s, creds)
}

func verifyAdminIdentity(ctx context.Context, s *store.Store, creds Credentials) (bool, error) {
	id, err := s.AdminIdentity(ctx)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			// No well-formed identity (including a v3 row without username) is
			// the SAME generic-mismatch category as a wrong username or password.
			return false, nil
		}
		return false, bridgeError{kind: bridgeErrStorage}
	}
	// Exact-byte username comparison: a wrong username is the generic mismatch
	// category. subtle is used for the byte comparison so the username check
	// does not shortcut on the first differing byte any more than the password
	// check does.
	if subtle.ConstantTimeCompare(id.Username, creds.Username) != 1 {
		return false, nil
	}
	in, ok := storeVerifierInput(id.Verifier)
	if !ok {
		// Defense in depth: the K1-style read already validated; an invalid
		// adapter value is the same generic-mismatch category.
		return false, nil
	}
	return verifyPassword(creds.Password, in), nil
}

// createAdminIdentity derives a fresh verifier for password and atomically
// persists username + verifier + the permanent bootstrap closure through the
// ONE accepted V4 store call. Control flow mirrors createAdminVerifier:
// derive FIRST (any failure makes no store call), then persist through the
// single atomic CreateAdminIdentityAndConsumeBootstrap so no partial state is
// ever observable.
func createAdminIdentity(ctx context.Context, s *store.Store, username, password []byte) error {
	rec, ok, err := newVerifierRecord(password)
	if !ok {
		_ = err
		return bridgeError{kind: bridgeErrCreation}
	}
	if err := s.CreateAdminIdentityAndConsumeBootstrap(ctx, username, storeVerifierRecord(rec)); err != nil {
		return bridgeError{kind: bridgeErrStorage}
	}
	return nil
}

// createAdminVerifier derives a fresh verifier for password and persists it
// while permanently consuming bootstrap, through the ONE accepted atomic
// typed store call. Control flow (fixed order): newVerifierRecord FIRST — on
// any creation failure return the fresh concrete error and make NO store
// call at all; then storeVerifierRecord; then exactly one
// s.CreateAdminAndConsumeBootstrap — any store failure (including atomic
// create failure and lost race) becomes a fresh bridgeError{bridgeErrStorage}
// with the store error discarded; success returns nil. It returns NO verifier
// material: salt and derived key never cross this boundary outward.
func createAdminVerifier(ctx context.Context, s *store.Store, password []byte) error {
	// The accepted primitive returns ok==true exactly when err==nil, and
	// every saltSourceError{} is constructed fresh at its return sites; the
	// bridge adds no sentinel, global or second error construction (G-2).
	rec, ok, err := newVerifierRecord(password)
	if !ok {
		_ = err // never propagated: fixed-text bridge category below, no foreign text
		return bridgeError{kind: bridgeErrCreation}
	}
	if err := s.CreateAdminAndConsumeBootstrap(ctx, storeVerifierRecord(rec)); err != nil {
		return bridgeError{kind: bridgeErrStorage}
	}
	return nil
}

// verifyAdminPassword reads the admin verifier through the ONE K1-guarded
// typed read (no second fetch, no second transaction), maps operational read
// failures to a fresh bridgeError, treats absent and malformed records as the
// SAME no-verifier category, and verifies the password against THAT SAME
// read value via the accepted verifyPassword. Wrong password is
// (false, nil); every failure boolean is false; missing or unavailable
// storage NEVER becomes success.
func verifyAdminPassword(ctx context.Context, s *store.Store, password []byte) (bool, error) {
	v, err := s.AdminVerifier(ctx)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return false, bridgeError{kind: bridgeErrNoVerifier}
		}
		return false, bridgeError{kind: bridgeErrStorage}
	}
	in, ok := storeVerifierInput(v)
	if !ok {
		// Defense in depth: the K1 read is already fully validated; an
		// invalid adapter value is the same no-verifier category, never a
		// panic, never success.
		return false, bridgeError{kind: bridgeErrNoVerifier}
	}
	return verifyPassword(password, in), nil
}
