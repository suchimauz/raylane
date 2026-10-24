package store

// White-box tests for the T008 storage-only v3 migration: fresh application,
// reopen persistence, idempotence, genuine v1/v2-only upgrade preserving prior
// data (fixture lives in auth_internal_test.go as an unexported test helper —
// production has no partially migrated Store bypass, finding S1), and
// failed/cancelled v3 migration leaving nothing behind.

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
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM admin_verifier`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("admin_verifier: n=%d err=%v", n, err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM bootstrap_state`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("bootstrap_state: n=%d err=%v", n, err)
	}
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
	if _, err := s.CreateNode(ctx, "node-1", []byte(`{"name":"keep-me"}`)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	// Apply the REAL step 2 exactly as an old installation did, through the
	// unexported test fixture (openLegacyV1V2ForTests re-applies 1+2
	// idempotently on a fresh path below; here the DB is already v1, so apply
	// v2 via the same wrapper the production migrator uses).
	db, err := openBarePoolForTests(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyMigrationForTests(ctx, db, migrations[1]); err != nil {
		t.Fatal(err)
	}
	db.Close()
	// Upgrade through production Open: ONLY v3 must be added on top of 1+2.
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
	if nd, err := s2.GetNode(ctx, "node-1"); err != nil || string(nd.Doc.Raw) != `{"name":"keep-me"}` {
		t.Fatalf("node preserved: %+v err=%v", nd, err)
	}
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM sealed_secrets`).Scan(new(int)); err != nil {
		t.Fatalf("v2 table unreadable: %v", err)
	}
}

// TestT008StorageLegacyFixtureIsGenuineV1V2 verifies the unexported fixture
// helper builds a real v1+v2 database (closed) that production Open upgrades
// to v3 while preserving data — the S1 replacement for the removed exported
// production bypass.
func TestT008StorageLegacyFixtureIsGenuineV1V2(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy2.db")
	if err := openLegacyV1V2ForTests(ctx, path); err != nil {
		t.Fatal(err)
	}
	db, err := openBarePoolForTests(path)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("fixture must hold exactly v1+v2: n=%d err=%v", n, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'admin_verifier'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("fixture must NOT contain v3 schema: n=%d err=%v", n, err)
	}
	db.Close()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer s.Close()
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 3`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("v3 after upgrade: n=%d err=%v", n, err)
	}
}

// TestT008StorageV3FailureRollsBackSchemaAndVersion injects a v3 step that
// performs REAL partial schema work and only THEN fails with the known
// sentinel (finding F1: the previous fixture demanded a sentinel that was
// unreachable behind a missing-table error). Rollback must leave NEITHER the
// partial auth schema NOR the v3 version row, and prior migration state must
// remain valid and usable.
func TestT008StorageV3FailureRollsBackSchemaAndVersion(t *testing.T) {
	defer func(saved []migration) { migrations = saved }(migrations)
	sentinel := errors.New("t008 v3 boom")
	inject := func(attempt *int) {
		migrations = append([]migration{}, migrations...)
		migrations[len(migrations)-1] = migration{Version: 3, Name: "auth-store", Apply: func(ctx context.Context, tx *sql.Tx) error {
			// Actual partial v3 work FIRST — identical DDL to the real step.
			if err := migrateAuthStore(ctx, tx); err != nil {
				return err
			}
			*attempt++
			// Known sentinel AFTER partial state exists on the FIRST
			// attempt. Mechanism (source, migrate.go): applyMigration calls
			// m.Apply on a tx; when Apply returns an ERROR, applyMigration
			// synchronously calls tx.Rollback() (migrate.go:93-96) BEFORE
			// Open returns — database/sql marks the tx done and the driver
			// issues ROLLBACK on its connection. That error-path rollback,
			// not a later pool close, undoes the partial DDL. (The defer at
			// migrate.go:88-91 is the PANIC branch and is NOT the normal
			// error path.) The bounded pre-reopen witness below verifies no
			// partial v3 object and no v3 version row became visible; the
			// reopen verifies clean retry. The second attempt is the REAL
			// production v3 step, so the clean retry must succeed after the
			// failing one.
			if *attempt == 1 {
				return sentinel
			}
			return nil
		}}
	}
	attempt := 0
	inject(&attempt)
	path := filepath.Join(t.TempDir(), "v3fail.db")
	if _, err := Open(context.Background(), path); err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("Open err=%v want wrapped sentinel", err)
	}
	if attempt != 1 {
		t.Fatalf("failing step invocations=%d want 1", attempt)
	}
	// Bounded pre-reopen witness (measured this run, not inferred from the
	// error): v1/v2 committed state survived the failed attempt — the v2
	// table is readable and exactly the two applied versions remain — AND
	// M2: sqlite_master shows ZERO objects named admin_verifier or
	// bootstrap_state, i.e. the synchronous error-path tx.Rollback
	// (migrate.go:93-96, a source fact) left no partial v3 schema visible
	// and no v3 version row. Honest limits: a closed WAL pool may
	// legitimately leave empty -wal/-shm sidecars, so sidecar absence is
	// NOT asserted; the witness shows the rollback's durable postcondition
	// (nothing partial visible to a fresh connection), not an engine-internal
	// undo trace. The conclusive operational guarantee below is the clean-
	// retry behavior on the real production step.
	{
		dbW, err := openBarePoolForTests(path)
		if err != nil {
			t.Fatal(err)
		}
		var okV2 int
		if err := dbW.QueryRow(`SELECT COUNT(*) FROM sealed_secrets`).Scan(&okV2); err != nil {
			t.Fatalf("v1/v2 committed state unreadable after failed attempt: %v", err)
		}
		var verCount int
		if err := dbW.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&verCount); err != nil || verCount != 2 {
			t.Fatalf("pre-v3 version state damaged: n=%d err=%v", verCount, err)
		}
		var partialObj int
		if err := dbW.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('admin_verifier','bootstrap_state')`).Scan(&partialObj); err != nil || partialObj != 0 {
			t.Fatalf("partial v3 schema visible after failed attempt: n=%d err=%v", partialObj, err)
		}
		var v3Row int
		if err := dbW.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 3`).Scan(&v3Row); err != nil || v3Row != 0 {
			t.Fatalf("v3 version row visible after failed attempt: n=%d err=%v", v3Row, err)
		}
		dbW.Close()
	}
	// Reopen with the SAME injection: attempt 2 is the real production step.
	// The failing tx was rolled back synchronously by applyMigration before
	// the first Open returned — no partial schema, no version row may
	// pre-exist here.
	inject(&attempt)
	s2, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen after failed v3: %v", err)
	}
	defer s2.Close()
	var n int
	// Assert the ROLLED-BACK state was clean on reopen by counting the v1/v2
	// tables that must remain, then the completed v3 (schema+version row),
	// all on the successfully retried database.

	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('admin_verifier','bootstrap_state')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("v3 schema after clean retry: n=%d err=%v", n, err)
	}
	// v1/v2 state survived (prior tables exist and are usable):
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('revisions','sealed_secrets')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("prior migration tables damaged: n=%d err=%v", n, err)
	}
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 3`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("v3 version row after clean retry: n=%d err=%v", n, err)
	}
	if attempt != 2 {
		t.Fatalf("v3 step invocations=%d want 2 (one failing, one clean retry)", attempt)
	}
	v := AdminVerifier{
		FormatVersion: 1, Argon2Version: 19, TimeCost: 3, MemoryKiB: 65536, Parallelism: 4,
		Salt: bytesOf(0x5A, 16), DerivedKey: bytesOf(0x6B, 32),
	}
	if err := s2.CreateAdminAndConsumeBootstrap(context.Background(), v); err != nil {
		t.Fatalf("boundary unusable after recovery: %v", err)
	}
}

func TestT008StorageV3CancelledContextLeavesNothing(t *testing.T) {
	ctx := context.Background()
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(t.TempDir(), "v3cancel.db")
	db, err := openBarePoolForTests(path)
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{db: db}
	if err := s.migrate(cctx); err == nil {
		db.Close()
		t.Fatal("cancelled migrate unexpectedly succeeded")
	}
	db.Close()
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
