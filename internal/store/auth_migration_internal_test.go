package store

// White-box tests for the T008 storage-only v3 migration: fresh application,
// reopen persistence, idempotence, genuine v1/v2-only upgrade preserving prior
// data, and failed/cancelled v3 migration leaving nothing behind. Legacy
// fixtures are built here (or via OpenLegacyV1V2ForTests in this file's own
// helper usage), never by editing old tests.

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestT008StorageFreshV3AppliesAndReopens(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v3.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 3 AND name = 'auth-store'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("v3 not recorded")
	}
	// Tables exist and are empty.
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM admin_verifier`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("admin_verifier: n=%d err=%v", n, err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM bootstrap_state`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("bootstrap_state: n=%d err=%v", n, err)
	}
	// Idempotent: migrate again is a no-op.
	if err := s.migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	s.Close()
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 3`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("after reopen v3 rows=%d err=%v", n, err)
	}
}

func TestT008StorageLegacyV1V2UpgradePreservesData(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := OpenLegacyV1ForTests(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	// Seed v1 data.
	if _, err := s.CreateNode(ctx, "node-1", []byte(`{"name":"keep-me"}`)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	// v2 layer via the secret store Open path: open normally applies v2 and
	// (now) v3; but to prove the v1/v2-only fixture upgrades, first apply v2
	// exactly like an old installation.
	db, err := openPool(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyMigration(ctx, db, migration{Version: 2, Name: "secret-store", Apply: migrateSecretStore}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Now upgrade through production Open: only v3 must be added.
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade open: %v", err)
	}
	defer s2.Close()
	var versions []int
	rows, err := s2.db.Query(`SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		versions = append(versions, v)
	}
	rows.Close()
	if len(versions) != 3 || versions[0] != 1 || versions[1] != 2 || versions[2] != 3 {
		t.Fatalf("versions=%v want [1 2 3]", versions)
	}
	// Prior v1/v2 data intact.
	if nd, err := s2.GetNode(ctx, "node-1"); err != nil || string(nd.Doc.Raw) != `{"name":"keep-me"}` {
		t.Fatalf("node preserved: %+v err=%v", nd, err)
	}
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM sealed_secrets`).Scan(new(int)); err != nil {
		t.Fatalf("v2 table unreadable: %v", err)
	}
}

func TestT008StorageV3FailureRollsBackSchemaAndVersion(t *testing.T) {
	defer func(saved []migration) { migrations = saved }(migrations)
	sentinel := errors.New("t008 v3 boom")
	migrations = append([]migration{}, migrations...)
	// Replace only the just-appended v3 with a failing variant that first
	// creates a table; the original steps 1/2 objects stay identical.
	migrations[len(migrations)-1] = migration{Version: 3, Name: "auth-store", Apply: func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE admin_verifier (x INTEGER)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO bootstrap_state VALUES (1,1)`); err != nil {
			return err // must fail: table does not exist yet
		}
		return sentinel
	}}
	path := filepath.Join(t.TempDir(), "v3fail.db")
	if _, err := Open(context.Background(), path); err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("Open err=%v want wrapped sentinel", err)
	}
	// Restore clean set and reopen: no partial schema, no version row.
	migrations = migrations[:len(migrations)-1]
	db, err := openPool(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 3`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("failed v3 left version row")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('admin_verifier','bootstrap_state')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("failed v3 left partial schema")
	}
}

func TestT008StorageV3CancelledContextLeavesNothing(t *testing.T) {
	ctx := context.Background()
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(t.TempDir(), "v3cancel.db")
	// Fresh open with a cancelled context must fail without recording v3.
	db, err := openPool(path)
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{db: db}
	if err := s.migrate(cctx); err == nil {
		db.Close()
		t.Fatal("cancelled migrate unexpectedly succeeded")
	}
	db.Close()
	// Clean reopen applies everything normally.
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("clean reopen: %v", err)
	}
	defer s2.Close()
	var n int
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 3`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("v3 after clean open n=%d err=%v", n, err)
	}
}
