package store

import (
	"context"
	"database/sql"
)

// This file is the idiomatic Go test-adapter surface: declarations compiled
// ONLY into test builds, visible to the external package store_test tests
// (and the in-package white-box tests) that need raw-pool inspection and
// mid-transaction fault injection. Production builds exclude it entirely, so
// the raw *sql.DB handle, the pragma probe and the write hook are NOT part of
// the product API surface. They exist solely to prove the accepted behaviour:
// connection invariants hold on every pooled connection, migrations and
// identity creation are atomic, and a mid-transaction cancel/fail leaves no
// partial publication. No production caller uses them (T008 composition
// boundary, architect decision §1 "Store API closure — settled minimal
// approach").

// SetHookOnlyForTests installs a mid-transaction interception hook used by
// tests to cancel or fail a write between revision insert and draft-head move.
// It is not part of the product behaviour; production code never calls it.
func (s *Store) SetHookOnlyForTests(hook func() error) { s.hook = hook }

// DB exposes the pool for read-only inspection in tests. It is not part of
// the product API surface; callers must not issue schema changes through it.
func (s *Store) DB() *sql.DB { return s.db }

// ConnectionInvariants reports the per-connection pragmas actually observed on
// one live pool connection. Tests call it repeatedly to prove foreign_keys and
// WAL hold on more than one connection, not just the first opened.
func ConnectionInvariants(db *sql.DB) (foreignKeysOn, wal bool, err error) {
	conn, err := db.Conn(context.Background())
	if err != nil {
		return false, false, err
	}
	defer conn.Close()
	if err := conn.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&foreignKeysOn); err != nil {
		return false, false, err
	}
	var mode string
	if err := conn.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&mode); err != nil {
		return false, false, err
	}
	return foreignKeysOn, mode == "wal", nil
}
