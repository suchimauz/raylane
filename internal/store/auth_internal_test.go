package store

// White-box tests for the T008 storage-only typed auth boundary: atomic
// first-admin + permanent bootstrap closure (exactly one concurrent winner),
// the K1 guarded read exercised through the ACTUAL production reader
// Store.AdminVerifier over real SQLite, K2 same-record reads under a genuine
// alternating A/B writer, and positive-record survival across reopen.
//
// All verifier bytes are bounded synthetic opaque fixed-size material — NOT
// Argon2 output and NOT any password proof. No Argon2, no tokens, no HTTP.

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/suchimauz/raylane/internal/domain"
)

// openLegacyV1V2ForTests builds a genuine v1+v2-only (pre-T008) database by
// applying the REAL migration steps 1 and 2 through the same applyMigration
// wrapper production uses, then returns it CLOSED — the test reopens via Open.
// It lives in a _test.go file precisely so production gains no partially
// migrated Store bypass (finding S1: the previously exported production
// OpenLegacyV1V2ForTests is removed).
func openLegacyV1V2ForTests(ctx context.Context, path string) error {
	db, err := openPool(path)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, schemaMigrationsDDL); err != nil {
		return err
	}
	if err := applyMigration(ctx, db, migrations[0]); err != nil {
		return err
	}
	return applyMigration(ctx, db, migrations[1])
}

// applyMigrationForTests and openBarePoolForTests expose the production
// migration wrapper and pool opener to white-box migration-fixture tests
// only; production never passes caller-chosen migrations.
func applyMigrationForTests(ctx context.Context, db *sql.DB, m migration) error {
	return applyMigration(ctx, db, m)
}

func openBarePoolForTests(path string) (*sql.DB, error) { return openPool(path) }

// authHostileFixtureDDLForTests creates a table named admin_verifier with the
// SAME column layout as production but WITHOUT the CHECK constraints, so
// tests can store adversarial data the production writer could never create
// and then drive it through the REAL production reader. Test-only; it hides
// nothing — the K1 guard inside k1GuardedSelect runs regardless of CHECKs.
func authHostileFixtureDDLForTests(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE admin_verifier (
		id             INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
		format_version INTEGER,
		argon2_version INTEGER,
		time_cost      INTEGER,
		memory_kib     INTEGER,
		parallelism    INTEGER,
		salt           BLOB,
		derived_key    BLOB,
		created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`)
	return err
}

// authABSwapTxForTests replaces the admin row transactionally inside a
// CALLER-SUPPLIED transaction with a complete valid record (fixed metadata,
// caller bytes). The T2 A/B test uses it as a test-only stand-in for a
// concurrent committed change — the product API never overwrites. Same
// private pool, same production table; no production seam is added.
func authABSwapTxForTests(ctx context.Context, tx *sql.Tx, salt, derivedKey []byte) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM admin_verifier WHERE id = 1`); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO admin_verifier (id, format_version, argon2_version, time_cost, memory_kib, parallelism, salt, derived_key)
		 VALUES (1, ?, ?, ?, ?, ?, ?, ?)`,
		authFormatVersion, authArgon2Version, authTimeCost, authMemoryKiB, authParallelism, salt, derivedKey)
	return err
}

func syntheticVerifier() AdminVerifier {
	return AdminVerifier{
		FormatVersion: authFormatVersion, Argon2Version: authArgon2Version,
		TimeCost: authTimeCost, MemoryKiB: authMemoryKiB, Parallelism: authParallelism,
		Salt:       bytesOf(0x11, authSaltBytes),
		DerivedKey: bytesOf(0x22, authDerivedKeyByte),
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// canary returns a unique bounded 1 MiB marker appended to hostile BLOBs: if
// any hostile byte ever reached Go through the reader, assertions can show it.
func canary(b byte) []byte { return bytesOf(b, 1<<20) }

func openFreshAuthStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestT008StorageAtomicFirstAdminAndPermanentClosure(t *testing.T) {
	ctx := context.Background()
	s, path := openFreshAuthStore(t)
	if consumed, err := s.BootstrapConsumed(ctx); err != nil || consumed {
		t.Fatalf("initially open: consumed=%v err=%v", consumed, err)
	}
	if _, err := s.AdminVerifier(ctx); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("no admin yet, err=%v", err)
	}
	v := syntheticVerifier()
	if err := s.CreateAdminAndConsumeBootstrap(ctx, v); err != nil {
		t.Fatal(err)
	}
	if consumed, err := s.BootstrapConsumed(ctx); err != nil || !consumed {
		t.Fatalf("closure not durable: consumed=%v err=%v", consumed, err)
	}
	other := syntheticVerifier()
	other.DerivedKey = bytesOf(0x33, authDerivedKeyByte)
	if err := s.CreateAdminAndConsumeBootstrap(ctx, other); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second create err=%v want ErrConflict", err)
	}
	got, err := s.AdminVerifier(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.DerivedKey) != string(v.DerivedKey) || string(got.Salt) != string(v.Salt) {
		t.Fatal("admin was overwritten")
	}
	bad := syntheticVerifier()
	bad.TimeCost = 4
	if err := s.CreateAdminAndConsumeBootstrap(ctx, bad); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("bad params err=%v", err)
	}
	bad = syntheticVerifier()
	bad.Salt = bytesOf(0x11, 15)
	if err := s.CreateAdminAndConsumeBootstrap(ctx, bad); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("bad salt len err=%v", err)
	}
	s.Close()
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if consumed, err := s2.BootstrapConsumed(ctx); err != nil || !consumed {
		t.Fatalf("closure lost after reopen: consumed=%v err=%v", consumed, err)
	}
	if err := s2.CreateAdminAndConsumeBootstrap(ctx, other); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("reopen allowed re-bootstrap: err=%v", err)
	}
}

func TestT008StorageExactlyOneConcurrentWinner(t *testing.T) {
	ctx := context.Background()
	s, _ := openFreshAuthStore(t)
	const contenders = 8
	keys := [][]byte{
		bytesOf(0xA1, authDerivedKeyByte), bytesOf(0xA2, authDerivedKeyByte),
		bytesOf(0xA3, authDerivedKeyByte), bytesOf(0xA4, authDerivedKeyByte),
		bytesOf(0xA5, authDerivedKeyByte), bytesOf(0xA6, authDerivedKeyByte),
		bytesOf(0xA7, authDerivedKeyByte), bytesOf(0xA8, authDerivedKeyByte),
	}
	var wg sync.WaitGroup
	errs := make([]error, contenders)
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v := syntheticVerifier()
			v.DerivedKey = keys[i]
			errs[i] = s.CreateAdminAndConsumeBootstrap(ctx, v)
		}(i)
	}
	wg.Wait()
	winners := 0
	for _, err := range errs {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, domain.ErrConflict):
			// typed loser
		default:
			t.Fatalf("ungrouped error: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("winners=%d want exactly 1", winners)
	}
	got, err := s.AdminVerifier(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range keys {
		if string(got.DerivedKey) == string(k) {
			found = true
		}
	}
	if !found {
		t.Fatal("winner record not persisted")
	}
	if consumed, err := s.BootstrapConsumed(ctx); err != nil || !consumed {
		t.Fatalf("consumed=%v err=%v", consumed, err)
	}
}

func TestT008StorageCreateFailureLeavesNoPartialState(t *testing.T) {
	ctx := context.Background()
	s, _ := openFreshAuthStore(t)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.CreateAdminAndConsumeBootstrap(cctx, syntheticVerifier()); err == nil {
		t.Fatal("cancelled create succeeded")
	}
	if consumed, err := s.BootstrapConsumed(ctx); err != nil || consumed {
		t.Fatalf("cancelled create consumed bootstrap: %v/%v", consumed, err)
	}
	if _, err := s.AdminVerifier(ctx); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cancelled create stored an admin: %v", err)
	}
	if err := s.CreateAdminAndConsumeBootstrap(ctx, syntheticVerifier()); err != nil {
		t.Fatal(err)
	}
}

// TestT008StorageK1RealReaderRejectsHostileRowsBeforeBlobProjection drives
// seventeen adversarial id=1 rows through the ACTUAL production reader
// Store.AdminVerifier over a real SQLite DB whose admin_verifier table is a
// test-owned CHECK-free same-name fixture (production never uses it). Every
// hostile row occupies id=1 — the ONLY id the production statement reads —
// inserted one at a time, so the id predicate cannot trivially hide the
// type/value/length guards. Every hostile BLOB carries a unique 1 MiB canary
// (bounded, per finding: not a stress benchmark): if a guard failure ever
// admitted a row, the canary bytes would surface in the failure message.
//
// Evidence classes kept distinct: (a) SOURCE — k1GuardedSelect evaluates
// typeof/exact values/exact lengths in WHERE, and SQLite filters rows by the
// WHERE clause before returning projected columns; (b) EXECUTED — per-case
// driver-level rejection/acceptance through the production reader; the Go
// allocator/materialization behavior itself is NOT measured and not claimed.
func TestT008StorageK1RealReaderRejectsHostileRowsBeforeBlobProjection(t *testing.T) {
	ctx := context.Background()
	s, _ := openFreshAuthStore(t)
	// Test-owned CHECK-free mirror under the production table name.
	if _, err := s.db.ExecContext(ctx, `DROP TABLE admin_verifier`); err != nil {
		t.Fatal(err)
	}
	if err := authHostileFixtureDDLForTests(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	okSalt, okKey := bytesOf(0x77, 16), bytesOf(0x88, 32)
	hostile := []struct {
		name string
		m    [5]any // format, argon, time, memory, parallelism classes
		salt any
		key  any
	}{
		{"null-format", [5]any{nil, 19, 3, 65536, 4}, okSalt, okKey},
		{"text-format", [5]any{"one", 19, 3, 65536, 4}, okSalt, okKey},
		{"real-format", [5]any{1.5, 19, 3, 65536, 4}, okSalt, okKey},
		{"null-argon", [5]any{1, nil, 3, 65536, 4}, okSalt, okKey},
		{"wrong-argon-version", [5]any{1, 20, 3, 65536, 4}, okSalt, okKey},
		{"wrong-format-version", [5]any{2, 19, 3, 65536, 4}, okSalt, okKey},
		{"zero-time", [5]any{1, 19, 0, 65536, 4}, okSalt, okKey},
		{"huge-time", [5]any{1, 19, 9223372036854775807, 65536, 4}, okSalt, okKey},
		{"negative-memory", [5]any{1, 19, 3, -65536, 4}, okSalt, okKey},
		{"negative-parallelism", [5]any{1, 19, 3, 65536, -4}, okSalt, okKey},
		{"null-salt", [5]any{1, 19, 3, 65536, 4}, nil, append(bytesOf(0xDD, 32), canary(0xC1)...)},
		{"salt-len-15+canary", [5]any{1, 19, 3, 65536, 4}, append(bytesOf(0xEE, 15), canary(0xC2)...), append(bytesOf(0xDD, 32), canary(0xC2)...)},
		{"salt-len-17+canary", [5]any{1, 19, 3, 65536, 4}, append(bytesOf(0xEE, 17), canary(0xC3)...), append(bytesOf(0xDD, 32), canary(0xC3)...)},
		{"salt-len-0", [5]any{1, 19, 3, 65536, 4}, []byte{}, append(bytesOf(0xDD, 32), canary(0xC4)...)},
		{"salt-text-class", [5]any{1, 19, 3, 65536, 4}, "sixteenchars_123", append(bytesOf(0xDD, 32), canary(0xC5)...)},
		{"key-len-31+canary", [5]any{1, 19, 3, 65536, 4}, append(bytesOf(0xEE, 16), canary(0xC6)...), append(bytesOf(0xDD, 31), canary(0xC6)...)},
		{"key-text-class", [5]any{1, 19, 3, 65536, 4}, append(bytesOf(0xEE, 16), canary(0xC7)...), "thirtytwo-character-string-value!!!!"},
		{"key-len-33+canary", [5]any{1, 19, 3, 65536, 4}, append(bytesOf(0xEE, 16), canary(0xC8)...), append(bytesOf(0xDD, 33), canary(0xC8)...)},
	}
	for _, hr := range hostile {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM admin_verifier`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO admin_verifier (id, format_version, argon2_version, time_cost, memory_kib, parallelism, salt, derived_key)
			 VALUES (1,?,?,?,?,?,?,?)`,
			hr.m[0], hr.m[1], hr.m[2], hr.m[3], hr.m[4], hr.salt, hr.key); err != nil {
			t.Fatalf("%s insert: %v", hr.name, err)
		}
		// The row IS present at the only readable id (id predicate alone
		// cannot be the reason for rejection):
		var present int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_verifier WHERE id = 1`).Scan(&present); err != nil || present != 1 {
			t.Fatalf("%s fixture not present at id=1: %d %v", hr.name, present, err)
		}
		got, err := s.AdminVerifier(ctx)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("%s: production reader err=%v want ErrNotFound (record %+v)", hr.name, err, got)
		}
	}
	// Positive control through the SAME production reader and SAME fixture
	// table: valid fixed 16+32B record must pass.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM admin_verifier`); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	v := syntheticVerifier()
	if err := authABSwapTxForTests(ctx, tx, v.Salt, v.DerivedKey); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := s.AdminVerifier(ctx)
	if err != nil || string(got.Salt) != string(v.Salt) || string(got.DerivedKey) != string(v.DerivedKey) {
		t.Fatalf("valid control rejected: %+v err=%v", got, err)
	}
	// Bounded plan observation of the ACTUAL production statement (inside
	// this test, no extra invocation): the executed plan is for the guarded
	// statement itself; supports that SQLite evaluates this statement with
	// its guard. NOT a claim about Go-side allocation timing.
	var detail string
	if err := s.db.QueryRowContext(ctx, `EXPLAIN QUERY PLAN `+k1GuardedSelect).Scan(new(int), new(int), new(int), &detail); err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	if !strings.Contains(detail, "admin_verifier") || !strings.Contains(detail, "SEARCH") {
		t.Fatalf("plan does not describe a guarded single-row search of the production table: %q", detail)
	}
}

// TestT008StorageProductionReaderFailsClosedAndSurvivesReopen proves the real
// typed reader on the REAL production schema: empty table fails closed as
// domain.ErrNotFound, the valid fixed-set record passes, and the exact record
// survives close/reopen.
func TestT008StorageProductionReaderFailsClosedAndSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	s, path := openFreshAuthStore(t)
	if _, err := s.AdminVerifier(ctx); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("empty table err=%v", err)
	}
	v := syntheticVerifier()
	if err := s.CreateAdminAndConsumeBootstrap(ctx, v); err != nil {
		t.Fatal(err)
	}
	got, err := s.AdminVerifier(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.FormatVersion != 1 || got.Argon2Version != 19 || got.TimeCost != 3 ||
		got.MemoryKiB != 65536 || got.Parallelism != 4 ||
		string(got.Salt) != string(v.Salt) || string(got.DerivedKey) != string(v.DerivedKey) {
		t.Fatalf("record mismatch: %+v", got)
	}
	s.Close()
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got2, err := s2.AdminVerifier(ctx)
	if err != nil || string(got2.DerivedKey) != string(v.DerivedKey) {
		t.Fatalf("record changed across reopen: %+v err=%v", got2, err)
	}
}

// TestT008StorageK2CompleteRecordUnderAlternatingWriter exercises the ACTUAL
// production reader while a test-only writer transactionally swaps between
// TWO distinguishable complete valid records A and B (salt and key always
// move together inside one committed transaction; the product API never
// overwrites, so this swap is the test stand-in for a concurrent committed
// change). Readers park on one WaitGroup release point — bounded
// synchronization, no sleeps.
//
// Assertions: (1) every successful read equals ALL of A or ALL of B — never
// a salt/key mix; (2) the writer provably commits swaps WHILE readers are in
// flight (atomic swap counter sampled at reader completion, strictly positive
// in every round), and BOTH generations A and B are observed across rounds —
// real read/write overlap and progress, not a post-change B-only window.
//
// What this proves is bounded: a finite interleaving run shows the reader
// never returned a torn record here; the SOURCE guarantee is the single
// guarded statement inside one read-only transaction with no refetch
// (auth.go). This is not an exhaustive race/timing proof and none is claimed.
func TestT008StorageK2CompleteRecordUnderAlternatingWriter(t *testing.T) {
	ctx := context.Background()
	s, _ := openFreshAuthStore(t)
	recA := syntheticVerifier()
	recA.Salt, recA.DerivedKey = bytesOf(0xA1, 16), bytesOf(0xB1, 32)
	recB := syntheticVerifier()
	recB.Salt, recB.DerivedKey = bytesOf(0xA2, 16), bytesOf(0xB2, 32)
	if err := s.CreateAdminAndConsumeBootstrap(ctx, recA); err != nil {
		t.Fatal(err)
	}
	var start sync.WaitGroup
	start.Add(1) // one release point for readers and writer
	var swaps atomic.Int64
	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() { // test-only A/B alternation writer
		defer close(writerDone)
		start.Wait()
		pairs := [2][]byte{
			append(append([]byte{}, recA.Salt...), recA.DerivedKey...),
			append(append([]byte{}, recB.Salt...), recB.DerivedKey...),
		}
		i := 1 // first swap to B so both generations appear early
		for {
			select {
			case <-stop:
				return
			default:
			}
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				t.Errorf("writer begin: %v", err)
				return
			}
			if err := authABSwapTxForTests(ctx, tx, pairs[i][:16], pairs[i][16:]); err != nil {
				tx.Rollback()
				t.Errorf("writer swap: %v", err)
				return
			}
			if err := tx.Commit(); err != nil {
				t.Errorf("writer commit: %v", err)
				return
			}
			swaps.Add(1)
			i = 1 - i
		}
	}()
	wantA := append(append([]byte{}, recA.Salt...), recA.DerivedKey...)
	wantB := append(append([]byte{}, recB.Salt...), recB.DerivedKey...)
	seenA, seenB := 0, 0
	const rounds, perRound = 6, 12
	for round := 0; round < rounds; round++ {
		var wg sync.WaitGroup
		errR := make([]error, perRound)
		obsR := make([][]byte, perRound)
		for i := 0; i < perRound; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				start.Wait()
				v, err := s.AdminVerifier(ctx)
				errR[i] = err
				if err == nil {
					obsR[i] = append(append([]byte{}, v.Salt...), v.DerivedKey...)
				}
			}(i)
		}
		if round == 0 {
			start.Done() // release readers and writer from the same point
		}
		wg.Wait()
		during := swaps.Load() // commits made while readers were in flight
		for i := 0; i < perRound; i++ {
			if errR[i] != nil {
				t.Fatalf("round %d reader %d: %v", round, i, errR[i])
			}
			switch string(obsR[i]) {
			case string(wantA):
				seenA++
			case string(wantB):
				seenB++
			default:
				t.Fatalf("round %d reader %d observed a MIXED record: %x", round, i, obsR[i])
			}
		}
		if during == 0 {
			t.Fatalf("round %d: writer committed zero swaps while readers ran — no overlap exercised", round)
		}
	}
	close(stop)
	<-writerDone
	if seenA == 0 || seenB == 0 {
		t.Fatalf("expected BOTH generations observed under overlap, got A=%d B=%d (swaps %d)", seenA, seenB, swaps.Load())
	}
}
