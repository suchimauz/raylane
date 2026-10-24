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

// k1MetadataSelect is the same guard WITHOUT the BLOB columns. It exists only
// for tests that must positively prove the guard rejected a hostile row whose
// BLOB bytes were never projected (byte-insensitive observation of the same
// SQL predicate). Production typed reads use k1GuardedSelect; this constant
// is unexported and referenced only from the two internal test files.
var _ = k1MetadataSelect // referenced exclusively by TestT008* guards below
const k1MetadataSelect = `SELECT format_version, argon2_version, time_cost, memory_kib, parallelism
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
// domain.ErrNotFound when no well-formed record exists. K2: the guard and the
// full projection run on ONE connection pinned to ONE read snapshot (deferred
// ReadUncommitted tx), so the bytes returned are exactly the bytes the guard
// validated — no second fetch, no check/fetch race. The result is rejected
// unless it matches the fixed parameter set; corrupt/hostile stored rows fail
// closed as ErrNotFound without any repair or fallback.
func (s *Store) AdminVerifier(ctx context.Context) (AdminVerifier, error) {
	return s.adminVerifierFrom(ctx, s.db, k1GuardedSelect, true)
}

func (s *Store) adminVerifierFrom(ctx context.Context, q *sql.DB, query string, full bool) (AdminVerifier, error) {
	tx, err := q.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AdminVerifier{}, err
	}
	defer tx.Rollback()
	var v AdminVerifier
	err = tx.QueryRowContext(ctx, query).Scan(
		&v.FormatVersion, &v.Argon2Version, &v.TimeCost, &v.MemoryKiB,
		&v.Parallelism, &v.Salt, &v.DerivedKey)
	if full {
		_ = full // guarded select admits exactly the full projection shape
	}
	if errors.Is(err, sql.ErrNoRows) {
		return AdminVerifier{}, fmt.Errorf("%w: no well-formed admin verifier", domain.ErrNotFound)
	}
	if err != nil {
		return AdminVerifier{}, err
	}
	// The guarded query already projected the only columns it admits; the
	// fixed-length slices are the validated bytes themselves.
	// Defensive exact-constant re-check after the guarded projection: the
	// returned record must equal the frozen set. This is a copy of validated
	// data, never a narrowing of unvalidated values.
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
