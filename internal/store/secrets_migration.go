package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
)

// migrateSecretStore is the T007 schema step (version 2). It only ADDS the
// secret-store table; the applied core migration and all T006 configuration
// rows stay byte-unchanged, and an existing v1 database upgrades through this
// single transactional step.
//
// sealed_secrets holds SecretRef-linked authenticated envelopes:
//
//	ref         the domain SecretRef the configuration points at
//	purpose     why the value was sealed; bound into the AEAD AAD, so asking
//	            the wrong purpose cannot disclose a valid value
//	format      envelope format version (currently only 1)
//	key_version key generation this record was sealed under (currently fixed
//	            at 1; recorded so a future step can classify, no rotation is
//	            implemented here)
//	blob        authenticated nonce-prefixed ciphertext (AEAD Seal output);
//	            never plaintext, never the master key
//
// Rows are immutable: no UPDATE path exists. A secret "replacement" seals a
// NEW ref and is referenced by NEWER revisions; material behind an older
// immutable revision's ref never changes. No deletion, GC, retention or
// rotation feature is implemented in T007.
//
// Presence of a value is row existence in THIS table — a secret_refs
// placeholder row (T006 reference metadata) is explicitly not proof that any
// value exists.
func migrateSecretStore(ctx context.Context, tx *sql.Tx) error {
	const ddl = `CREATE TABLE sealed_secrets (
	ref         TEXT NOT NULL,
	purpose     TEXT NOT NULL,
	format      INTEGER NOT NULL CHECK (format >= 1),
	key_version INTEGER NOT NULL CHECK (key_version >= 1),
	blob        BLOB NOT NULL,
	created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
	PRIMARY KEY (ref, purpose)
)`
	_, err := tx.ExecContext(ctx, ddl)
	return err
}

// OpenLegacyV1ForTests opens a database that has ONLY the core migration
// applied — a faithful stand-in for a pre-T007 installation. It is test
// support inside the allowed file set (it touches no existing behavior);
// production always goes through Open. Tests then reopen it via Open to
// prove the v2 upgrade is transactional and never rewrites core data.
func OpenLegacyV1ForTests(ctx context.Context, path string) (*Store, error) {
	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if _, err := db.ExecContext(ctx, schemaMigrationsDDL); err != nil {
		db.Close()
		return nil, err
	}
	if err := applyMigration(ctx, db, migrations[0]); err != nil {
		db.Close()
		return nil, fmt.Errorf("legacy v1 fixture: %w", err)
	}
	return s, nil
}
