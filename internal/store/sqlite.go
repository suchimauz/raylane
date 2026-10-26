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
// leaves it nil; tests use it (via SetHookOnlyForTests, declared in
// export_test.go) to cancel or fail mid-transaction and prove no partial
// publication occurs (T006 point 4).
type Store struct {
	db   *sql.DB
	hook func() error
}

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
