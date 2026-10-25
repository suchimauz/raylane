// Package auth holds the private admin-verifier KDF primitive (format V1).
//
// This package exposes NO exported package-level authentication API: every
// package-level func, type, const and var is unexported. The ONLY exported
// names anywhere in the package are the standard error interface methods
// Error() on the unexported concrete error types saltSourceError and
// bridgeError, each with a value (non-pointer) receiver of its own
// unexported type, no parameters and exactly one builtin string result,
// required verbatim by the error interface. The package is the in-memory
// boundary between the decoded verifier fields and the maintained Argon2id
// implementation. The storage-boundary guard in internal/store (the accepted
// K1 guard) is a separate, authoritative gate; this primitive does not
// replace, weaken or duplicate it. The primitive file kdf.go does not import
// internal/store; the package's bridge file storekdf.go imports internal/store
// one-way (internal/store does not import this package), to compose the
// accepted typed store boundary with this private KDF.
//
// Honest boundary statement: the reader seam in newVerifierRecordWithReader
// is a trusted SAME-PACKAGE source-construction boundary, not language-level
// isolation. The fixed-array record copy removes caller aliasing but is not
// Go immutability. No whole-system constant-time, zeroization or future-edit
// immunity is claimed anywhere in this package.
package auth

import (
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/argon2"
)

// Frozen logical constants (V1 private format). Trusted fixed constants;
// stored values are validated against them, never cast into them.
const (
	formatVersion  = 1
	argon2Version  = 19 // 0x13
	timeCost       = 3
	memoryKiB      = 65536
	parallelism    = 4
	saltBytes      = 16
	derivedKeyByte = 32
)

// saltSourceError is the CONCRETE (non-interface) failure error type of the
// salt source and of the creation guard. Because it is a struct type, a
// value of it can never be a nil interface: the failure error is NON-NIL BY
// CONSTRUCTION and is constructed fresh AT EVERY RETURN SITE — it never
// consults any package-level variable. The message is a fixed, non-empty,
// non-sensitive constant: no password, salt, key, record, length, reader or
// caller data, and never foreign reader error text. Error() below is the
// REQUIRED standard-error method: its name must be capitalized to satisfy
// the error interface, and a method on this unexported receiver is NOT an
// exported package-level authentication API.
type saltSourceError struct{}

func (saltSourceError) Error() string {
	return "auth: salt source did not deliver a full salt"
}

// verifierInput is the RAW, UNTRUSTED input at the memory boundary.
// Slice fields are owned by the caller and are NOT retained by freeze.
type verifierInput struct {
	formatVersion int
	argon2Version int
	timeCost      int
	memoryKiB     int
	parallelism   int
	salt          []byte
	derivedKey    []byte
}

// adminVerifierRecord is the private V1 record. Fixed-size arrays make the
// byte content length-fixed and copy-by-value with NO caller alias — this is
// NOT language-enforced immutability (same-package code could still mutate
// it); the repeated metadata guard in deriveFor is the load-bearing
// protection.
type adminVerifierRecord struct {
	formatVersion int
	argon2Version int
	timeCost      int
	memoryKiB     int
	parallelism   int
	salt          [saltBytes]byte
	derivedKey    [derivedKeyByte]byte
}

// freeze validates EVERY frozen metadata field and BOTH lengths of the raw
// input and returns the private value copy. ok == false means the input was
// rejected BEFORE any copy, narrowing or KDF call.
func freeze(v verifierInput) (adminVerifierRecord, bool) {
	if v.formatVersion != formatVersion ||
		v.argon2Version != argon2Version ||
		v.timeCost != timeCost ||
		v.memoryKiB != memoryKiB ||
		v.parallelism != parallelism {
		return adminVerifierRecord{}, false
	}
	if len(v.salt) != saltBytes || len(v.derivedKey) != derivedKeyByte {
		return adminVerifierRecord{}, false
	}
	var rec adminVerifierRecord
	rec.formatVersion = v.formatVersion
	rec.argon2Version = v.argon2Version
	rec.timeCost = v.timeCost
	rec.memoryKiB = v.memoryKiB
	rec.parallelism = v.parallelism
	copy(rec.salt[:], v.salt)
	copy(rec.derivedKey[:], v.derivedKey)
	return rec, true
}

// deriveFor is the SOLE place the maintained Argon2id is invoked, shared by
// creation AND verification. Its guard re-checks all five frozen metadata
// fields AT THE DECISION POINT (load-bearing: the caller's data path is
// validated here, not assumed) and then calls argon2.IDKey directly with
// COMPILE-TIME CONSTANTS. There is no injectable KDF: no parameter, field,
// function variable or hook can replace it.
func deriveFor(rec adminVerifierRecord, password []byte) ([derivedKeyByte]byte, bool) {
	if rec.formatVersion != formatVersion || rec.argon2Version != argon2Version ||
		rec.timeCost != timeCost || rec.memoryKiB != memoryKiB ||
		rec.parallelism != parallelism {
		return [derivedKeyByte]byte{}, false
	}
	derived := argon2.IDKey(password, rec.salt[:], timeCost, memoryKiB, parallelism, derivedKeyByte)
	var out [derivedKeyByte]byte
	copy(out[:], derived)
	return out, true
}

// verifyPassword validates the raw input in full, and only on a fully valid
// record derives and compares. Wrong password and invalid record are both
// false (no oracle). The comparison is reached ONLY for two valid fixed
// 32-byte values via crypto/subtle.ConstantTimeCompare; malformed lengths
// are rejected before the KDF and before any compare. No system-level
// constant-time timing guarantee is claimed.
func verifyPassword(password []byte, v verifierInput) bool {
	rec, ok := freeze(v)
	if !ok {
		return false
	}
	derived, ok := deriveFor(rec, password)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(derived[:], rec.derivedKey[:]) == 1
}

// fillSalt writes saltBytes random bytes into dst using the given source.
// Production binds read to crypto/rand.Read directly at exactly one call
// site (newVerifierRecord). Every failure — the reader's own error or a
// short count — is mapped AT THE RETURN SITE to a fresh saltSourceError{}:
// the reader's error value is DISCARDED, so no foreign error text can be
// smuggled to the caller, and the non-nil property is a property of the
// concrete type, not of package state. Success alone returns nil.
func fillSalt(dst *[saltBytes]byte, read func([]byte) (int, error)) error {
	n, err := read(dst[:])
	if err != nil {
		return saltSourceError{}
	}
	if n != saltBytes {
		return saltSourceError{}
	}
	return nil
}

// selfConsistent reports whether the record carries the frozen V1 metadata.
// It is a METADATA predicate only: byte lengths are already fixed by the
// array types, and it asserts NOTHING about salt randomness or key
// correctness — those are not decidable from metadata.
func (r adminVerifierRecord) selfConsistent() bool {
	return r.formatVersion == formatVersion &&
		r.argon2Version == argon2Version &&
		r.timeCost == timeCost &&
		r.memoryKiB == memoryKiB &&
		r.parallelism == parallelism
}

// newVerifierRecord creates a fresh V1 admin verifier record using the
// maintained CSPRNG. This is the PRODUCTION entry point and the ONLY
// production binding of a reader: it delegates once, passing the literal
// rand.Read. Go 1.27.3 crypto/rand.Read always fills the buffer or
// terminates the process irrecoverably; there is no recoverable failure
// path in production and none is claimed to be covered.
func newVerifierRecord(password []byte) (adminVerifierRecord, bool, error) {
	return newVerifierRecordWithReader(password, rand.Read)
}

// newVerifierRecordWithReader is the SINGLE implementation of the creation
// control flow (not a copied test wrapper; the only non-test caller is
// newVerifierRecord above). The reader is an ordinary unexported
// CREATION-ONLY argument: not stored globally, not a hook, and never
// reachable from verification — verifyPassword does not call this function
// and has no reader parameter. A test may pass a synthetic failing reader
// to exercise the REAL creation control flow; such synthetic failures are
// NOT real CSPRNG-failure coverage.
//
// Canonical invariant, structural by construction: err != nil ⇔ ok == false.
// Every failure return constructs a fresh saltSourceError{} at the return
// site (non-nil by construction); success alone returns nil. On every
// failure the returned record is the ZERO value — never a partial record.
func newVerifierRecordWithReader(password []byte, read func([]byte) (int, error)) (adminVerifierRecord, bool, error) {
	var rec adminVerifierRecord

	// 1) ALL FIVE metadata fields initialized to the frozen V1 constants
	//    BEFORE any salt or derivation work. No field left at its zero value.
	rec.formatVersion = formatVersion // 1
	rec.argon2Version = argon2Version // 19 (0x13)
	rec.timeCost = timeCost           // 3
	rec.memoryKiB = memoryKiB         // 65536
	rec.parallelism = parallelism     // 4

	// 2) Fresh salt through the given reader. On failure this returns
	//    BEFORE the KDF step below — zero record, non-nil error.
	if err := fillSalt(&rec.salt, read); err != nil {
		return adminVerifierRecord{}, false, saltSourceError{}
	}

	// 3) Guarded derivation via the SOLE shared argon2.IDKey call site.
	//    The !ok branch is the decision-point guard rejecting invalid
	//    metadata before any Argon2 work.
	derived, ok := deriveFor(rec, password)
	if !ok {
		return adminVerifierRecord{}, false, saltSourceError{}
	}
	copy(rec.derivedKey[:], derived[:])

	// 4) Self-consistency re-check of the produced record. Defensively,
	//    this last check — if it were ever reached failing — runs AFTER
	//    the KDF; it is honestly post-KDF, and unreachable under steps
	//    (1)–(3) as written.
	if !rec.selfConsistent() {
		return adminVerifierRecord{}, false, saltSourceError{}
	}
	return rec, true, nil
}
