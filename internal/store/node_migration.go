package store

import (
	"context"
	"database/sql"
)

// migrateManagedNode is the V4 US1/T012 storage step (version 5). It only ADDS
// the managed-node tables; steps 1-4 stay byte-unchanged, and an existing v4
// database upgrades through this single transactional step.
//
// The managed tables deliberately hold ONLY safe, non-secret content:
//
//	node_validation   the CLOSED, value-free nodes.Result snapshot (status,
//	                  applicability, closed issues, secret/unknown NAME lists,
//	                  chain/structured check enums) at the recorded revision,
//	                  plus the exact authority digest the verdict was produced
//	                  under. No values, ciphertext or original protocol bytes.
//	node_preservation owner/link metadata pointing at the single sealed
//	                  preservation container (its ciphertext lives only in the
//	                  existing sealed_secrets table; nothing is duplicated here).
//	node_secret_fields owner/link metadata per declared secret field, so a cold
//	                  keyless reader can derive CURRENT presence from row
//	                  existence without selecting any ciphertext.
//
// All new node foreign keys keep the accepted deferred/restrict semantics, so
// neither a node nor a referenced secret can be removed out from under the
// binding rows.
func migrateManagedNode(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE node_validation (
	node_id         TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
	node_revision   INTEGER NOT NULL CHECK (node_revision >= 1),
	authority_digest BLOB NOT NULL CHECK (length(authority_digest) = 32),
	result          TEXT NOT NULL CHECK (json_valid(result))
)`,
		`CREATE TABLE node_preservation (
	node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
	ref     TEXT NOT NULL REFERENCES secret_refs(ref),
	purpose TEXT NOT NULL
)`,
		`CREATE TABLE node_secret_fields (
	node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
	field   TEXT NOT NULL CHECK (length(field) > 0),
	ref     TEXT NOT NULL REFERENCES secret_refs(ref),
	purpose TEXT NOT NULL,
	PRIMARY KEY (node_id, field)
)`,
	}
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}
