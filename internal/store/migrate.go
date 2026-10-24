package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
)

// migration is one versioned schema step. Steps are ordered by Version and
// applied inside a single transaction together with their schema_migrations
// row, so a failed step leaves neither partial schema nor a version row
// behind (T006 point 7).
type migration struct {
	Version int
	Name    string
	Apply   func(ctx context.Context, tx *sql.Tx) error
}

// migrations is the ordered, embedded migration set. Adding a step later means
// appending a new higher version; existing steps never change.
var migrations = []migration{
	{Version: 1, Name: "core-config", Apply: migrateCore},
	// T007 appends the secret-store step; the core migration above stays
	// byte-unchanged and applied v1 databases upgrade transactionally.
	{Version: 2, Name: "secret-store", Apply: migrateSecretStore},
}

const schemaMigrationsDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	name    TEXT NOT NULL,
	applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
)`

// migrate applies every pending migration, each in its own transaction. It is
// repeatable and restart-safe: applied versions are recorded and skipped on
// later opens.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaMigrationsDDL); err != nil {
		return err
	}
	applied, err := appliedVersions(ctx, s.db)
	if err != nil {
		return err
	}
	pending := make([]migration, 0, len(migrations))
	for _, m := range migrations {
		if !applied[m.Version] {
			pending = append(pending, m)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].Version < pending[j].Version })
	for _, m := range pending {
		if err := applyMigration(ctx, s.db, m); err != nil {
			return fmt.Errorf("migration %d (%s): %w", m.Version, m.Name, err)
		}
	}
	return nil
}

func appliedVersions(ctx context.Context, db *sql.DB) (map[int]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func applyMigration(ctx context.Context, db *sql.DB, m migration) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			err = fmt.Errorf("panic during migration: %v", p)
		}
	}()
	if err := m.Apply(ctx, tx); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name) VALUES (?, ?)`, m.Version, m.Name); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

// migrateCore creates the T006 tables:
//
// revisions      immutable configuration snapshots (draft history)
// draft_head     single-row pointer to the current draft revision + counter
// active_state   single-row pointer to the last applied revision + generation
// nodes          entities with their own optimistic revisions; active
//
//	membership lives in the active snapshot, never as a flag here
//
// sources        subscription / ruleset sources; settings revision (rev) and
//
//	content versions (draft_version/active_version) are distinct columns
//
// node_secret_refs  draft-side references from a saved node to a SecretRef
//
//	(FK-protected: the draft's references survive; dangling rows are rejected)
//
// active_revision_nodes membership rows between the active revision snapshot
//
//	and node entities: FK-protected both ways, so neither the active snapshot
//
//	nor a referenced node can be deleted out from under the other (data model:
//
//	active membership lives in the snapshot, not as a flag on the node)
//
// source_jobs    refresh jobs holding the server-side captured revision
// secret_refs    SecretRef placeholders; no ciphertext or plaintext material
//
//	(T007 owns encryption; this table only exists to reference and protect)
//
// restore_tx_marker  minimal boundary marker for the future atomic
//
//	encrypted-secrets + new-draft restore transaction (boundary only, no
//	backup/restore implementation in T006)
func migrateCore(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE revisions (
	id            TEXT PRIMARY KEY,
	seq           INTEGER NOT NULL UNIQUE,
	parent_id     TEXT NOT NULL DEFAULT '',
	doc           TEXT NOT NULL,
	valid         INTEGER NOT NULL CHECK (valid IN (0,1,2)), -- 0 not_run, 1 valid, 2 invalid (NOT_RUN ≠ PASS)
	findings      TEXT NOT NULL DEFAULT '[]',
	created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
)`,
		`CREATE TABLE secret_refs (
	ref TEXT PRIMARY KEY
)`,
		`CREATE TABLE revision_secrets (
	revision_id TEXT NOT NULL REFERENCES revisions(id),
	secret_ref  TEXT NOT NULL REFERENCES secret_refs(ref),
	PRIMARY KEY (revision_id, secret_ref)
)`,
		`CREATE TABLE draft_head (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	revision_id TEXT NOT NULL REFERENCES revisions(id) DEFERRABLE INITIALLY DEFERRED,
	revision    INTEGER NOT NULL CHECK (revision >= 0)
)`,
		`CREATE TABLE active_state (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	revision_id TEXT NOT NULL REFERENCES revisions(id),
	generation  INTEGER NOT NULL CHECK (generation >= 1)
)`,
		`CREATE TABLE nodes (
	id       TEXT PRIMARY KEY,
	revision INTEGER NOT NULL CHECK (revision >= 1), -- optimistic per-entity revision
	doc      TEXT NOT NULL CHECK (json_valid(doc))  -- stored only after the syntax gate
)`,
		`CREATE TABLE node_secret_refs (
	node_id    TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
	secret_ref TEXT NOT NULL REFERENCES secret_refs(ref),
	PRIMARY KEY (node_id, secret_ref)
)`,
		`CREATE TABLE sources (
	id             TEXT PRIMARY KEY,
	kind           TEXT NOT NULL CHECK (kind IN ('subscription','ruleset')),
	revision       INTEGER NOT NULL CHECK (revision >= 1), -- settings revision (optimistic guard)
	draft_version  INTEGER NOT NULL DEFAULT 0 CHECK (draft_version >= 0),  -- content versions:
	active_version INTEGER NOT NULL DEFAULT 0 CHECK (active_version >= 0), -- distinct from revision
	doc            TEXT NOT NULL CHECK (json_valid(doc))
)`,
		`CREATE TABLE source_jobs (
	id                TEXT PRIMARY KEY,
	source_id         TEXT NOT NULL REFERENCES sources(id),
	captured_revision INTEGER NOT NULL CHECK (captured_revision >= 1),
	status            TEXT NOT NULL CHECK (status IN ('running','committed','rejected','failed')),
	content_version   INTEGER NOT NULL DEFAULT 0 CHECK (content_version >= 0)
)`,
		// Only one RUNNING job per source (busy conflict, enforced by a unique
		// index); terminal states accumulate as per-source refresh history.
		`CREATE UNIQUE INDEX source_jobs_one_running ON source_jobs (source_id) WHERE status = 'running'`,
		`CREATE TABLE active_revision_nodes (
	revision_id TEXT NOT NULL REFERENCES revisions(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
	node_id     TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
	PRIMARY KEY (revision_id, node_id)
)`,
		`CREATE TABLE restore_tx (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	state TEXT NOT NULL CHECK (state IN ('prepared','committed','rolledback')),
	revision_id TEXT REFERENCES revisions(id)
)`,
	}
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return errors.New(q[:40] + ": " + err.Error())
		}
	}
	return nil
}
