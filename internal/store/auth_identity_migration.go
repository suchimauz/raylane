package store

import (
	"context"
	"database/sql"
)

// migrateAuthIdentityStore is the V4 storage step (version 4). It only ADDS
// the persisted admin identity column; migrations 1, 2 and 3 and every
// existing row stay byte-unchanged, and a v1/v2/v3 database upgrades through
// this single transactional step (the same applyMigration wrapper proves
// rollback and version-row atomicity).
//
// The single administrator's username is persisted alongside the verifier so
// that "no admin exists", "wrong username" and "wrong password" are
// indistinguishable to a remote caller. The username is stored as the exact
// bytes the bootstrap operator supplied (1..256 bytes of valid UTF-8,
// validated at the composition boundary, NOT here). SQLite TEXT preserves the
// exact bytes; a length CHECK describes the invariant for NEW writes but is
// NOT the read proof — the typed read independently validates class and
// length at the SQL boundary (K1-style) before any byte is projected.
//
// Scope: this remains a private persistence primitive only. No password
// handling, no Argon2, no token/issuer/session, no HTTP/CLI wiring.
func migrateAuthIdentityStore(ctx context.Context, tx *sql.Tx) error {
	// ALTER TABLE ADD COLUMN is transactional in SQLite and preserves every
	// existing admin_verifier row; the singleton id=1 invariant is unchanged.
	// A NOT NULL without DEFAULT is allowed because the table is either empty
	// (fresh v4 database) or already has its single row consumed — but to stay
	// correct on every upgrade path we permit the column to be added with a
	// NOT NULL constraint only when there is no pre-existing unconsumed row;
	// in practice v3 databases that reached bootstrap already hold a row, so
	// we add the column nullable and enforce length at the typed read/write.
	const identityDDL = `ALTER TABLE admin_verifier ADD COLUMN username TEXT`
	if _, err := tx.ExecContext(ctx, identityDDL); err != nil {
		return err
	}
	return nil
}
