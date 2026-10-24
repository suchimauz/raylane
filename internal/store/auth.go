package store

// T008 storage-only auth primitives: the single admin KDF verifier record and
// the permanent bootstrap-consumed closure, on the private Store.db typed
// boundary. This file deliberately contains NO password handling, NO Argon2
// call, NO token/issuer/session concept and NO public interception API — it is
// a persistence primitive only (see the assignment and
// docs/engineering/T008-kdf-record-decision.md).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/suchimauz/raylane/internal/domain"
)

// Frozen logical record constants (T008 KDF record decision, scoped-frozen).
// They are trusted fixed constants; stored values are never cast into them.
const (
	authFormatVersion  = 1
	authArgon2Version  = 19 // 0x13
	authTimeCost       = 3
	authMemoryKiB      = 65536
	authParallelism    = 4
	authSaltBytes      = 16
	authDerivedKeyByte = 32
)

// AdminVerifier is the immutable validated record returned by the typed read.
// Byte slices are fixed-length copies of the validated row; the value (not a
// shared buffer) is what callers pass on.
type AdminVerifier struct {
	FormatVersion int
	Argon2Version int
	TimeCost      int
	MemoryKiB     int
	Parallelism   int
	Salt          []byte // exactly 16 bytes
	DerivedKey    []byte // exactly 32 bytes
}

// k1GuardedSelect is the K1 read boundary: the WHERE clause enforces storage
// class (typeof), the exact signed-integer values and the exact BLOB byte
// lengths INSIDE SQLite, so a wrong-class, wrong-value, NULL or oversized row
// yields no rows at all — its BLOB bytes are never projected, and therefore
// never materialized, in Go. Scan-then-len and LIMIT alone are not proof;
// this guard runs on every production typed read regardless of table CHECKs.
const k1GuardedSelect = `SELECT format_version, argon2_version, time_cost, memory_kib, parallelism, salt, derived_key
	FROM admin_verifier
	WHERE id = 1
	  AND typeof(format_version) = 'integer' AND format_version = 1
	  AND typeof(argon2_version) = 'integer' AND argon2_version = 19
	  AND typeof(time_cost) = 'integer' AND time_cost = 3
	  AND typeof(memory_kib) = 'integer' AND memory_kib = 65536
	  AND typeof(parallelism) = 'integer' AND parallelism = 4
	  AND typeof(salt) = 'blob' AND length(salt) = 16
	  AND typeof(derived_key) = 'blob' AND length(derived_key) = 32`

// AdminVerifier returns the single validated admin record, or
// domain.ErrNotFound when no well-formed record exists.
//
// K1 (source guarantee): the statement executed here is k1GuardedSelect — its
// WHERE clause evaluates storage class (typeof), exact signed-integer values
// and exact BLOB byte lengths inside SQLite, so a wrong-class, wrong-value,
// NULL or oversized row yields NO ROW and its BLOB bytes are never projected
// by that statement. Scan-then-len, LIMIT alone or table CHECKs are not the
// guard; this predicate runs on every production typed read.
//
// K2 (source guarantee): the guarded statement runs as ONE query inside ONE
// read-only transaction (BeginTx TxOptions{ReadOnly:true}, default
// isolation — NOT ReadUncommitted), on the single connection that transaction
// is pinned to. The bytes Scan returns are exactly the bytes the guard
// evaluated in that same snapshot — one statement, no second fetch, no
// check/fetch refetch window inside this call.
//
// The defensive exact-constant re-check below copies from the already
// validated record; corrupt or hostile stored data fails closed as
// ErrNotFound with no repair and no fallback.
func (s *Store) AdminVerifier(ctx context.Context) (AdminVerifier, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AdminVerifier{}, err
	}
	defer tx.Rollback()
	var v AdminVerifier
	err = tx.QueryRowContext(ctx, k1GuardedSelect).Scan(
		&v.FormatVersion, &v.Argon2Version, &v.TimeCost, &v.MemoryKiB,
		&v.Parallelism, &v.Salt, &v.DerivedKey)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminVerifier{}, fmt.Errorf("%w: no well-formed admin verifier", domain.ErrNotFound)
	}
	if err != nil {
		return AdminVerifier{}, err
	}
	// Post-read exact-constant re-check of the validated copy: never a
	// narrowing of unvalidated values, only a final defense-in-depth gate.
	if v.FormatVersion != authFormatVersion || v.Argon2Version != authArgon2Version ||
		v.TimeCost != authTimeCost || v.MemoryKiB != authMemoryKiB || v.Parallelism != authParallelism ||
		len(v.Salt) != authSaltBytes || len(v.DerivedKey) != authDerivedKeyByte {
		return AdminVerifier{}, fmt.Errorf("%w: admin verifier failed post-read validation", domain.ErrNotFound)
	}
	return v, nil
}

// CreateAdminAndConsumeBootstrap atomically inserts the first admin verifier
// and permanently closes bootstrap: exactly one winner under concurrency,
// losers receive domain.ErrConflict and persist nothing. The closure and the
// verifier live in ONE transaction; rollback/cancellation leaves neither.
// The closure, once committed, is permanent: no production operation in this
// file set resets it or overwrites the admin.
//
// This is a persistence primitive, NOT token authorization: possessing a
// verifier record proves nothing about any token and must never be wired as a
// usable bootstrap service.
func (s *Store) CreateAdminAndConsumeBootstrap(ctx context.Context, v AdminVerifier) error {
	if v.FormatVersion != authFormatVersion || v.Argon2Version != authArgon2Version ||
		v.TimeCost != authTimeCost || v.MemoryKiB != authMemoryKiB || v.Parallelism != authParallelism {
		return fmt.Errorf("%w: verifier metadata outside frozen set", domain.ErrConflict)
	}
	if len(v.Salt) != authSaltBytes || len(v.DerivedKey) != authDerivedKeyByte {
		return fmt.Errorf("%w: verifier material outside frozen lengths", domain.ErrConflict)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	// The closure row carries the consumed=1 invariant itself; INSERT (never
	// UPDATE/OR-REPLACE) makes a committed closure permanent and race-safe.
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO bootstrap_state (id, consumed) VALUES (1, 1)`); err != nil {
		if isUniqueViolation(err) { // helper from secrets.go: same private store
			return fmt.Errorf("%w: bootstrap already consumed", domain.ErrConflict)
		}
		return err
	}
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO admin_verifier (id, format_version, argon2_version, time_cost, memory_kib, parallelism, salt, derived_key)
		 VALUES (1, ?, ?, ?, ?, ?, ?, ?)`,
		authFormatVersion, authArgon2Version, authTimeCost, authMemoryKiB, authParallelism, v.Salt, v.DerivedKey); err != nil {
		if isUniqueViolation(err) { // helper from secrets.go: same private store
			return fmt.Errorf("%w: admin already exists", domain.ErrConflict)
		}
		return err
	}
	if err = tx.Commit(); err != nil {
		// The closure INSERT above pre-checks the common race, but two
		// contenders may both pass it and collide on the admin PRIMARY KEY
		// at COMMIT; classify that as the typed conflict losers must see.
		if isUniqueViolation(err) { // helper from secrets.go: same private store
			return fmt.Errorf("%w: bootstrap already consumed", domain.ErrConflict)
		}
		return err
	}
	return nil
}

// BootstrapConsumed reports the durable permanent closure. Missing row means
// bootstrap is still open; any read error is surfaced, never silently treated
// as closed or open-success.
func (s *Store) BootstrapConsumed(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bootstrap_state WHERE id = 1 AND consumed = 1`).Scan(&n)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}
