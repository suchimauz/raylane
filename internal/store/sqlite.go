// Package store persists the domain configuration model in SQLite using the
// standard database/sql interface and the pinned modernc.org/sqlite driver.
//
// Connection invariants: every pooled connection gets foreign_keys=ON,
// journal_mode=WAL and busy_timeout through DSN pragmas applied by the driver
// at connect time, so the invariants hold for each connection the pool opens,
// not only the first one. The pool is deliberately larger than one connection
// and tests prove the per-connection enforcement.
//
// Scope note (T006): this package is the durable configuration store only. It
// runs no HTTP server, fetches no sources, and stores no plaintext secrets —
// configuration carries domain.SecretRef values inside documents only.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	_ "modernc.org/sqlite" // pure-Go driver pinned in packaging/versions.lock §4
)

// Store is the SQLite-backed configuration store. It is safe for concurrent
// use: all write invariants are enforced inside database transactions.
//
// hook is a test-only interception point executed inside a transaction after
// the revision row is inserted and before the draft head moves. Production
// leaves it nil; tests use it to cancel or fail mid-transaction and prove no
// partial publication occurs (T006 point 4). SetOnlyForTests configures it.
type Store struct {
	db   *sql.DB
	hook func() error
}

// SetHookOnlyForTests installs a mid-transaction interception hook used by
// tests to cancel or fail a write between revision insert and draft-head move.
// It is not part of the product behaviour; production code never calls it.
func (s *Store) SetHookOnlyForTests(hook func() error) { s.hook = hook }

// Open creates (or opens) the SQLite database at path, applies connection
// invariants to every pooled connection, runs versioned migrations, and
// returns a ready Store. Closing the returned Store closes the pool.
func Open(ctx context.Context, path string) (*Store, error) {
	db, err := openPool(path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return s, nil
}

// openPool opens the pool without migrating, for tests of migration failure.
func openPool(path string) (*sql.DB, error) {
	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// More than one connection is deliberate: the DSN pragmas must hold on
	// every pooled connection, and the tests prove that (T006 point 7).
	db.SetMaxOpenConns(4)
	db.SetConnMaxIdleTime(0)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Close closes the underlying pool.
func (s *Store) Close() error { return s.db.Close() }

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
