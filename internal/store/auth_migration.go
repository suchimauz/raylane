package store

import (
	"context"
	"database/sql"
)

// migrateAuthStore is the T008 storage-only schema step (version 3). It only
// ADDS the auth-store tables; migrations 1 and 2 and every existing row stay
// byte-unchanged, and a v1/v2 database upgrades through this single
// transactional step (the same applyMigration wrapper proves rollback and
// version-row atomicity).
//
// admin_verifier holds the frozen logical KDF record
// (docs/engineering/T008-kdf-record-decision.md) for the single administrator:
//
//	id                singletons are pinned to exactly 1 — no second admin row
//	format_version    1 (implies ONLY Argon2id for this private format)
//	argon2_version    19 (0x13)
//	time_cost         3
//	memory_kib        65536
//	parallelism       4
//	salt              exactly 16 raw bytes
//	derived_key       exactly 32 raw bytes
//
// CHECK constraints describe the invariants for NEW writes; they are NOT the
// read proof. The typed read guard in auth.go independently validates
// storage class, values and lengths at the SQL boundary before any BLOB is
// projected (K1), because stored data may be corrupt or hostile.
//
// bootstrap_state holds the PERMANENT closure flag: consumed=1 can never be
// reset by any production operation in this file set.
//
// Scope: this is a private persistence primitive only. No token, no issuer,
// no password verification, no Argon2 invocation, no HTTP/CLI wiring, no
// session concept lives here.
func migrateAuthStore(ctx context.Context, tx *sql.Tx) error {
	const adminDDL = `CREATE TABLE admin_verifier (
	id             INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
	format_version INTEGER NOT NULL CHECK (format_version = 1),
	argon2_version INTEGER NOT NULL CHECK (argon2_version = 19),
	time_cost      INTEGER NOT NULL CHECK (time_cost = 3),
	memory_kib     INTEGER NOT NULL CHECK (memory_kib = 65536),
	parallelism    INTEGER NOT NULL CHECK (parallelism = 4),
	salt           BLOB NOT NULL CHECK (length(salt) = 16),
	derived_key    BLOB NOT NULL CHECK (length(derived_key) = 32),
	created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
)`
	const bootstrapDDL = `CREATE TABLE bootstrap_state (
	id       INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
	consumed INTEGER NOT NULL CHECK (consumed = 1)
)`
	if _, err := tx.ExecContext(ctx, adminDDL); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, bootstrapDDL); err != nil {
		return err
	}
	return nil
}
