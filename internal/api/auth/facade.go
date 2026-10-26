// Package auth KDF/store primitives are deliberately unexported (guard G-1).
// facade.go is the SINGLE, deliberately-reviewed exported surface that the V4
// runtime composition boundary uses — the one intentional amendment to the
// zero-export rule, per the V4 wire decision (DECISION.md §7/§3). It exposes
// ONLY a narrow create/verify over the persisted admin identity; it adds NO
// hook, NO injectable KDF, NO reader parameter and NO package-level state.
// This file does NOT import internal/store (the bridge storekdf.go owns that
// one-way dependency); the façade composes the accepted primitives.
//
// The exported API is a FACADE over the accepted private implementation, not
// a parallel path: CreateIdentity and VerifyIdentity delegate to the same
// newVerifierRecord / verifyPassword / store bridge the primitives already
// prove. Username and password are handled as exact decoded bytes; length is
// counted in Unicode code points after valid-UTF-8 validation (the settled
// contract), never trimmed or normalized.
package auth

import (
	"unicode/utf8"
)

// store is NOT imported here: the exported CreateIdentity/VerifyIdentity
// functions that need *store.Store live in storekdf.go (the one file allowed
// to import internal/store, guard G-3), so this façade file adds no second
// store import. This file carries only the credential type and the pure
// length/well-formedness validation.

// Username bounds counted in Unicode code points (the settled contract), and
// the password bound likewise. These describe the public wire/CLI shape; the
// store independently re-proves them at the SQL boundary.
const (
	// MinUsernameRunes / MaxUsernameRunes bound the username code points.
	MinUsernameRunes = 1
	MaxUsernameRunes = 256
	// MinPasswordRunes / MaxPasswordRunes bound the password code points.
	MinPasswordRunes = 1
	MaxPasswordRunes = 1024
)

// Credentials is the exact decoded credential material supplied at bootstrap
// or login. Username and Password are the exact bytes supplied (valid UTF-8,
// length counted in code points); nothing is trimmed or normalized. The
// slices are owned by the caller; the façade copies what it persists.
type Credentials struct {
	Username []byte
	Password []byte
}

// ValidUsername reports whether bs is valid UTF-8 of 1..256 code points.
func ValidUsername(bs []byte) bool {
	return validRuneCount(bs, MinUsernameRunes, MaxUsernameRunes)
}

// ValidPassword reports whether bs is valid UTF-8 of 1..1024 code points.
func ValidPassword(bs []byte) bool {
	return validRuneCount(bs, MinPasswordRunes, MaxPasswordRunes)
}

func validRuneCount(bs []byte, min, max int) bool {
	if len(bs) == 0 || !utf8.Valid(bs) {
		return false
	}
	n := utf8.RuneCount(bs)
	return n >= min && n <= max
}

// CreateIdentity and VerifyIdentity are defined in storekdf.go (the single
// file permitted to import internal/store, guard G-3); they are documented at
// the top of this file as the exported facade over the accepted primitives.
