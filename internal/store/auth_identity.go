package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/suchimauz/raylane/internal/domain"
)

// V4 persisted admin identity bounds (docs/engineering T008 + the settled
// wire contract). Username length is counted in Unicode code points after
// valid-UTF-8 validation at the composition boundary; here the read proves
// storage class and byte well-formedness, and the byte length bounds.
const (
	adminUsernameMinBytes = 1
	adminUsernameMaxBytes = 1024 // 256 code points * up to 4 UTF-8 bytes each
)

// AdminIdentity is the immutable validated identity record: the exact
// username bytes the bootstrap operator supplied plus the frozen verifier.
// A malformed or absent identity row is reported as domain.ErrNotFound (the
// no-identity category), never a panic and never a success.
type AdminIdentity struct {
	Username []byte // 1..256 Unicode code points of valid UTF-8, exact bytes
	Verifier AdminVerifier
}

// k1GuardedIdentitySelect is the K1-style read boundary for the V4 identity:
// the WHERE clause enforces storage class (typeof), the exact signed-integer
// verifier values, the exact BLOB byte lengths, and that username is a TEXT
// blob whose BYTE length is within the hard bound INSIDE SQLite, so a
// wrong-class, wrong-value, NULL, oversized or unbacked row yields no rows at
// all. A v3 row whose username column is NULL therefore matches nothing and is
// the no-identity category. Well-formedness (valid UTF-8, code-point length)
// is re-proven in Go on the projected copy.
const k1GuardedIdentitySelect = `SELECT username, format_version, argon2_version, time_cost, memory_kib, parallelism, salt, derived_key
	FROM admin_verifier
	WHERE id = 1
	  AND typeof(username) = 'text'
	  AND length(username) >= 1
	  AND length(username) <= 1024
	  AND typeof(format_version) = 'integer' AND format_version = 1
	  AND typeof(argon2_version) = 'integer' AND argon2_version = 19
	  AND typeof(time_cost) = 'integer' AND time_cost = 3
	  AND typeof(memory_kib) = 'integer' AND memory_kib = 65536
	  AND typeof(parallelism) = 'integer' AND parallelism = 4
	  AND typeof(salt) = 'blob' AND length(salt) = 16
	  AND typeof(derived_key) = 'blob' AND length(derived_key) = 32`

// AdminIdentity returns the single validated admin identity (username plus
// verifier), or domain.ErrNotFound when no well-formed identity row exists —
// including a v3 row with a NULL username. The read runs in one read-only
// transaction through the K1-style guarded select; the projected copy is
// re-proven (valid UTF-8, code-point length, exact verifier constants) before
// it is returned.
func (s *Store) AdminIdentity(ctx context.Context) (AdminIdentity, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AdminIdentity{}, err
	}
	defer tx.Rollback()
	var id AdminIdentity
	err = tx.QueryRowContext(ctx, k1GuardedIdentitySelect).Scan(
		&id.Username,
		&id.Verifier.FormatVersion, &id.Verifier.Argon2Version, &id.Verifier.TimeCost,
		&id.Verifier.MemoryKiB, &id.Verifier.Parallelism, &id.Verifier.Salt, &id.Verifier.DerivedKey)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminIdentity{}, fmt.Errorf("%w: no well-formed admin identity", domain.ErrNotFound)
	}
	if err != nil {
		return AdminIdentity{}, err
	}
	// Post-read re-proof of the projected copy (never a narrowing of
	// unvalidated values): valid UTF-8, code-point length in 1..256, and the
	// exact frozen verifier constants and material lengths.
	if !validAdminUsername(id.Username) {
		return AdminIdentity{}, fmt.Errorf("%w: admin identity failed post-read validation", domain.ErrNotFound)
	}
	if id.Verifier.FormatVersion != authFormatVersion || id.Verifier.Argon2Version != authArgon2Version ||
		id.Verifier.TimeCost != authTimeCost || id.Verifier.MemoryKiB != authMemoryKiB || id.Verifier.Parallelism != authParallelism ||
		len(id.Verifier.Salt) != authSaltBytes || len(id.Verifier.DerivedKey) != authDerivedKeyByte {
		return AdminIdentity{}, fmt.Errorf("%w: admin identity failed post-read validation", domain.ErrNotFound)
	}
	return id, nil
}

// validAdminUsername reports whether bs is valid UTF-8 of 1..256 Unicode code
// points. The exact decoded bytes are preserved for hashing; nothing is
// trimmed or normalized.
func validAdminUsername(bs []byte) bool {
	if len(bs) < adminUsernameMinBytes || len(bs) > adminUsernameMaxBytes {
		return false
	}
	if !utf8.Valid(bs) {
		return false
	}
	n := utf8.RuneCount(bs)
	return n >= 1 && n <= 256
}

// CreateAdminIdentityAndConsumeBootstrap atomically inserts the first admin
// identity (username + verifier) and permanently closes bootstrap in ONE
// transaction: no partial state (username without verifier, or verifier
// without username) is ever observable. Exactly one winner under concurrency;
// losers receive domain.ErrConflict and persist nothing. The username is
// stored as the exact supplied bytes after the caller proves it is valid
// UTF-8 of 1..256 code points; the verifier metadata and material are
// re-checked against the frozen set. The closure, once committed, is
// permanent: no production operation resets it or overwrites the admin.
func (s *Store) CreateAdminIdentityAndConsumeBootstrap(ctx context.Context, username []byte, v AdminVerifier) error {
	if !validAdminUsername(username) {
		return fmt.Errorf("%w: admin username outside 1..256 code points", domain.ErrConflict)
	}
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
	// Identity, verifier and closure commit together or not at all. The
	// username is bound as a Go string so SQLite stores it as TEXT (a []byte
	// would bind as a BLOB and defeat the typeof(username)='text' read guard);
	// the exact decoded UTF-8 bytes are preserved because a Go string is an
	// immutable byte sequence and SQLite TEXT round-trips the bytes verbatim.
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO admin_verifier (id, format_version, argon2_version, time_cost, memory_kib, parallelism, salt, derived_key, username)
		 VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)`,
		authFormatVersion, authArgon2Version, authTimeCost, authMemoryKiB, authParallelism, v.Salt, v.DerivedKey, string(username)); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: admin already exists", domain.ErrConflict)
		}
		return err
	}
	// The closure row carries the consumed=1 invariant itself; INSERT (never
	// UPDATE/OR-REPLACE) makes a committed closure permanent and race-safe.
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO bootstrap_state (id, consumed) VALUES (1, 1)`); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: bootstrap already consumed", domain.ErrConflict)
		}
		return err
	}
	if err = tx.Commit(); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: bootstrap already consumed", domain.ErrConflict)
		}
		return err
	}
	return nil
}
