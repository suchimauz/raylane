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
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

// authHostileFixtureDDLForTests creates a CHECK-free, typeless table named
// admin_verifier for hostile-data cases. Two schema facts frame it, both
// measured during this patch (see logs run7/run8):
//   - the REAL production v3 table (auth_migration.go migrateAuthStore,
//     read-only to this patch) uses plain INTEGER/BLOB affinity plus NOT NULL
//     and value/length CHECK constraints; and
//   - a STRICT variant of the same shape refuses to STORE wrong-class values
//     at all ("cannot store TEXT value in INTEGER column", driver error 3091)
//     — a measured fact about SQLite STRICT tables, recorded here as evidence
//     for why the fixture deliberately is NOT type-restricted.
//
// With CHECK constraints removed and columns left typeless, every named
// hostile class stores exactly as given (TEXT stays TEXT, REAL stays REAL —
// no affinity coercion), so the guard under test is forced to be the
// production reader's own WHERE predicate (k1GuardedSelect), not schema
// CHECKs or storage-class rules.
//
// Measurement honesty (limitations recorded, not hidden):
//   - what is MEASURED here is executed-driver rejection: for each stored
//     hostile row, Store.AdminVerifier returns domain.ErrNotFound (auth.go:
//     "no well-formed admin verifier");
//   - what is NOT measured is Go allocator behavior for SQLite-internal
//     non-projection — that remains the source-level guarantee of the
//     WHERE-clause guard, stated in auth.go;
//   - the EXPLAIN QUERY PLAN assertion below is plan-shape evidence only;
//     it does not measure projection order or allocations and is not
//     claimed to.
func authHostileFixtureDDLForTests(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE admin_verifier (
		format_version,
		argon2_version,
		time_cost,
		memory_kib,
		parallelism,
		salt,
		derived_key,
		id             INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
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
// adversarial id=1 rows through the ACTUAL production reader
// Store.AdminVerifier over a real SQLite DB whose admin_verifier table is the
// test-owned CHECK-free same-name fixture (authHostileFixtureDDLForTests;
// production never uses it). Every case invalidates ONLY its named field
// (T1): all other fields hold the exact valid fixed values, so a rejection
// attributes to the intended guard rather than a co-invalidated one. Each
// hostile row occupies id=1 — the ONLY id the production statement reads —
// inserted alone with presence verified, so the id predicate cannot hide
// whether the type/value/length guards ran. Oversized cases are separate
// bounded cases (not canary-padded length cases).
//
// Evidence classes stay distinct: (a) SOURCE — k1GuardedSelect evaluates
// typeof/exact values/exact lengths in WHERE, and SQLite filters rows by the
// WHERE clause of that statement; (b) EXECUTED — per-case production-reader
// rejection/acceptance through the real driver; (c) UNMEASURED — Go-side
// allocation/materialization timing is NOT measured and not claimed.
func TestT008StorageK1RealReaderRejectsHostileRowsBeforeBlobProjection(t *testing.T) {
	ctx := context.Background()
	s, _ := openFreshAuthStore(t)
	if _, err := s.db.ExecContext(ctx, `DROP TABLE admin_verifier`); err != nil {
		t.Fatal(err)
	}
	if err := authHostileFixtureDDLForTests(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	okSalt, okKey := bytesOf(0x77, 16), bytesOf(0x88, 32)
	// Every case: [format,argon,time,mem,par] + salt + key, with EXACTLY one
	// field outside the frozen set (NULL/text/real class, wrong value, or
	// wrong exact length; oversize is its own case).
	cases := []struct {
		name string
		m    [5]any
		salt any
		key  any
	}{
		// Each case invalidates EXACTLY ONE field; all others hold the exact
		// valid frozen values. Class cases use genuinely non-coercible
		// payloads (non-numeric TEXT, non-integral REAL); length cases use
		// EXACT byte counts with the other BLOB valid.
		{"format-NULL", [5]any{nil, 19, 3, 65536, 4}, okSalt, okKey},
		{"format-TEXT-invalid-class", [5]any{"one", 19, 3, 65536, 4}, okSalt, okKey},
		{"format-REAL-nonintegral-class", [5]any{1.5, 19, 3, 65536, 4}, okSalt, okKey},
		{"format-wrong-value-2", [5]any{2, 19, 3, 65536, 4}, okSalt, okKey},
		{"argon-NULL", [5]any{1, nil, 3, 65536, 4}, okSalt, okKey},
		{"argon-TEXT-invalid-class", [5]any{1, "nineteen", 3, 65536, 4}, okSalt, okKey},
		{"argon-REAL-nonintegral-class", [5]any{1, 19.5, 3, 65536, 4}, okSalt, okKey},
		{"argon-wrong-value-20", [5]any{1, 20, 3, 65536, 4}, okSalt, okKey},
		{"time-NULL", [5]any{1, 19, nil, 65536, 4}, okSalt, okKey},
		{"time-REAL-nonintegral-class", [5]any{1, 19, 3.5, 65536, 4}, okSalt, okKey},
		{"time-wrong-value-0", [5]any{1, 19, 0, 65536, 4}, okSalt, okKey},
		{"time-wrong-value-maxint64", [5]any{1, 19, 9223372036854775807, 65536, 4}, okSalt, okKey},
		{"memory-NULL", [5]any{1, 19, 3, nil, 4}, okSalt, okKey},
		{"memory-TEXT-invalid-class", [5]any{1, 19, 3, "sixtyfivek", 4}, okSalt, okKey},
		{"memory-wrong-value-negative", [5]any{1, 19, 3, -65536, 4}, okSalt, okKey},
		{"memory-wrong-value-65535", [5]any{1, 19, 3, 65535, 4}, okSalt, okKey},
		{"parallelism-NULL", [5]any{1, 19, 3, 65536, nil}, okSalt, okKey},
		{"parallelism-REAL-nonintegral-class", [5]any{1, 19, 3, 65536, 4.5}, okSalt, okKey},
		{"parallelism-wrong-value-negative", [5]any{1, 19, 3, 65536, -4}, okSalt, okKey},
		{"parallelism-wrong-value-5", [5]any{1, 19, 3, 65536, 5}, okSalt, okKey},
		{"salt-NULL", [5]any{1, 19, 3, 65536, 4}, nil, okKey},
		{"salt-TEXT-class", [5]any{1, 19, 3, 65536, 4}, "sixteenchars_123", okKey},
		{"salt-len-15", [5]any{1, 19, 3, 65536, 4}, bytesOf(0xEE, 15), okKey},
		{"salt-len-17", [5]any{1, 19, 3, 65536, 4}, bytesOf(0xEE, 17), okKey},
		{"salt-len-0", [5]any{1, 19, 3, 65536, 4}, []byte{}, okKey},
		{"salt-oversized-bounded", [5]any{1, 19, 3, 65536, 4}, bytesOf(0xEE, 1024), okKey},
		{"key-NULL", [5]any{1, 19, 3, 65536, 4}, okSalt, nil},
		{"key-TEXT-class", [5]any{1, 19, 3, 65536, 4}, okSalt, "thirtytwo-character-string-value!!!!"},
		{"key-len-31", [5]any{1, 19, 3, 65536, 4}, okSalt, bytesOf(0xDD, 31)},
		{"key-len-33", [5]any{1, 19, 3, 65536, 4}, okSalt, bytesOf(0xDD, 33)},
		{"key-len-0", [5]any{1, 19, 3, 65536, 4}, okSalt, []byte{}},
		{"key-oversized-bounded", [5]any{1, 19, 3, 65536, 4}, okSalt, bytesOf(0xDD, 1024)},
	}
	for _, hc := range cases {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM admin_verifier`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO admin_verifier (id, format_version, argon2_version, time_cost, memory_kib, parallelism, salt, derived_key)
			 VALUES (1,?,?,?,?,?,?,?)`,
			hc.m[0], hc.m[1], hc.m[2], hc.m[3], hc.m[4], hc.salt, hc.key); err != nil {
			t.Fatalf("%s insert: %v", hc.name, err)
		}
		var present int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_verifier WHERE id = 1`).Scan(&present); err != nil || present != 1 {
			t.Fatalf("%s fixture not present at id=1: %d %v", hc.name, present, err)
		}
		got, err := s.AdminVerifier(ctx)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("%s: production reader err=%v want ErrNotFound (record %+v)", hc.name, err, got)
		}
	}
	// Positive control through the SAME production reader and SAME fixture
	// table: valid fixed16+32B record must pass.
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
	// this test, no extra invocation): confirms the executed statement is the
	// guarded single-row SEARCH of the production table. It does NOT measure
	// projection order or allocations and is not claimed to.
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

// --- T2 test-only writer with a credit-gated pipeline (design notes) ------
//
// The writer commits COMPLETE admin records transactionally (salt+key always
// move together; the product API never overwrites, so this fixture stands in
// for a concurrent committed change). The test orchestrates it with a CLOSED
// pipeline used as an overlap witness:
//
//	pump --credit(w.commit)--> writer swap --completion(w.commitDone)-->
//	pump mirror --pumpDone--> owner collect
//
// The pump grants a bounded budget of credits per OPEN read-window, hands at
// most ONE credit at a time, and only from the state "previous swap already
// drained" — so at most one swap is live and mirrored completions reach the
// owner in exact COMMIT order. A window switch (open/close) is an exact
// sync point via a SETTLE barrier: a switch accepted while a swap is live
// is remembered and its ack (an unbuffered rendezvous for OPENs, a channel
// close for quiet CLOSEs) fires only after the live swap's completion has
// been mirrored — so when switchWindow returns, zero swaps are unobserved
// and zero credits are undelivered, and every completion the owner then
// collects belongs to a swap HANDED strictly after that sync point. Each
// round therefore forces minOverlapPerRound commits that were authorized,
// executed and committed AFTER the production read call started — durable
// A<->B progress racing the read — and strict generation alternation,
// checked continuously ACROSS sync points, proves both generations moved
// with no lost or reordered witness.
//
// Boundedness (N1): every handshake is a select on ctx.Done/stop/stopRun/
// exit/fatal/watch — no busy spin, no sleep, no polling. Writer, pump and
// helpers NEVER touch testing.T; failures go to a bounded error channel
// (w.err + w.fatal) the owner drains while alive. Cleanup order is
// load-bearing: the owner QUIET-STOPS the writer (quiet flag set, stopRun
// closed) only after the close+drain protocol proved the pipeline quiet, so
// no legitimate swap is canceled and no spurious error races a dead test;
// close(stop) releases the pump; ctx cancel is the last-resort backstop for
// Fatal-mid-window paths. The cleanup join is itself bounded.
type abWriter struct {
	db         *sql.DB
	pairA      []byte
	pairB      []byte
	commit     chan int      // credit: commit generation gen next (blocks)
	commitDone chan int      // 1-buffered: gen of each committed swap
	err        chan error    // bounded (1); non-blocking send
	fatal      chan struct{} // closed when a writer failure was recorded
	stopRun    chan struct{} // owner-only quiet stop (closed AFTER draining)
	exit       chan struct{} // closed when the goroutine has returned

	mu    sync.Mutex // guards quiet; taken only on the writer's exit path
	quiet bool       // set before stopRun closes: swaps end silently
	log   [][2]int   // gen of every durable commit in order; guarded by mu, surfaced in alternation-failure diagnostics
}

func newABWriter(db *sql.DB, pairA, pairB []byte) *abWriter {
	return &abWriter{
		db: db, pairA: pairA, pairB: pairB,
		commit:     make(chan int),
		commitDone: make(chan int, 1),
		err:        make(chan error, 1),
		fatal:      make(chan struct{}),
		stopRun:    make(chan struct{}),
		exit:       make(chan struct{}),
	}
}

func (w *abWriter) isQuiet() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.quiet
}

// run handles owner credits only: begin+commit one COMPLETE record under the
// shared ctx per credit, report the completion, then block for the next
// credit (no DB work, no spinning while unauthorized).
func (w *abWriter) run(ctx context.Context) {
	defer close(w.exit)
	for {
		var gen int
		select {
		case gen = <-w.commit:
		case <-w.stopRun:
			return
		case <-ctx.Done():
			return
		}
		if err := w.swap(ctx, gen); err != nil {
			if !w.isQuiet() && !errors.Is(err, context.Canceled) {
				select {
				case w.err <- err:
				default:
				}
				close(w.fatal)
			}
			return
		}
		w.mu.Lock()
		w.log = append(w.log, [2]int{gen, len(w.log)})
		w.mu.Unlock()
		select {
		case w.commitDone <- gen:
		case <-w.stopRun:
			return
		case <-ctx.Done():
			return
		}
	}
}

// swap commits ONE COMPLETE record (fixed frozen metadata + caller bytes) in
// its own transaction on the private pool.
func (w *abWriter) swap(ctx context.Context, gen int) error {
	salt, key := w.pairB[:16], w.pairB[16:]
	if gen == 0 {
		salt, key = w.pairA[:16], w.pairA[16:]
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := authABSwapTxForTests(ctx, tx, salt, key); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// checkFailed surfaces a writer-recorded error while the OWNER is alive.
func (w *abWriter) checkFailed(t *testing.T, at string) {
	select {
	case err := <-w.err:
		t.Fatalf("%s: writer failure: %v", at, err)
	default:
	}
}

// deadlineWatcher bounds test-side waits with the TEST's own deadline
// (testing.common.Deadline), firing well before it so protocol waits fail
// with a precise message instead of the process-wide panic dump.
func deadlineWatcher(t *testing.T) (<-chan struct{}, func()) {
	fire := make(chan struct{})
	var stop func()
	if d, ok := t.Deadline(); ok {
		left := time.Until(d)
		if left < 60*time.Second {
			left = 60 * time.Second
		}
		timer := time.NewTimer(left - 30*time.Second)
		stop = func() { timer.Stop() }
		go func() { defer close(fire); <-timer.C }()
	} else {
		close(fire) // no test deadline: waits rely on ctx/exit bounds only
		stop = func() {}
	}
	return fire, stop
}

// TestT008StorageK2CompleteRecordUnderAlternatingWriter exercises the ACTUAL
// production read path (Store.AdminVerifier -> adminVerifierTx) while a
// concurrent writer commits COMPLETE admin records (salt+key always move
// together, transactionally), alternating between two full generations A<->B.
// The credit-gated pipeline (abWriter + pump below) witnesses COMMITTED A<->B
// progress completing AFTER the read call started, with zero mixed reads —
// the T2 criterion from the independent review: overlap must be proven by
// durable commits racing the read, not by a parked writer.
// Honest limits: the A/B swap is a TEST-ONLY fixture transaction (the product
// API never overwrites); the 8 rounds are interleaving evidence, not an
// exhaustive timing proof; single-statement/single-snapshot atomicity is a
// SOURCE property of auth.go, asserted by design, not measured here.
func TestT008StorageK2CompleteRecordUnderAlternatingWriter(t *testing.T) {
	// Explicit protocol bound far below the 900 s outer shell timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	watch, stopWatch := deadlineWatcher(t)
	defer stopWatch()
	s, _ := openFreshAuthStore(t)
	recA := syntheticVerifier()
	recA.Salt, recA.DerivedKey = bytesOf(0xA1, 16), bytesOf(0xB1, 32)
	recB := syntheticVerifier()
	recB.Salt, recB.DerivedKey = bytesOf(0xA2, 16), bytesOf(0xB2, 32)
	if err := s.CreateAdminAndConsumeBootstrap(ctx, recA); err != nil {
		t.Fatal(err)
	}
	pairA := append(append([]byte{}, recA.Salt...), recA.DerivedKey...)
	pairB := append(append([]byte{}, recB.Salt...), recB.DerivedKey...)
	w := newABWriter(s.db, pairA, pairB)
	go w.run(ctx)

	stop := make(chan struct{})
	pumpExit := make(chan struct{})
	// Registered AFTER openFreshAuthStore's cleanup => LIFO runs FIRST on
	// every exit path (including t.Fatal below), BEFORE the store closes the
	// pool: quiet-stop the writer (at normal end the close+drain protocol
	// provably left no swap in flight; on Fatal paths quiet suppresses the
	// cancellation error instead of racing a dead test), release the pump,
	// cancel as the last-resort backstop (kills stuck statements carrying
	// this ctx), then BOUNDED-join the writer.
	t.Cleanup(func() {
		w.mu.Lock()
		w.quiet = true
		w.mu.Unlock()
		close(w.stopRun)
		close(stop)
		cancel()
		select {
		case <-w.exit:
		case <-time.After(45 * time.Second):
			t.Fatalf("T2/N1 gap: writer goroutine never exited after stop — join NOT bounded")
		}
		select {
		case <-pumpExit:
		case <-time.After(45 * time.Second):
			t.Fatalf("T2/N1 gap: pump goroutine never exited after stop — join NOT bounded")
		}
	})

	const perRoundBudget = 3      // max swaps authorized per window (bound)
	const minOverlapPerRound = 2  // swaps required to COMPLETE during the read
	pumpDone := make(chan int, 1) // ordered completions mirrored by the pump
	pumpReq := make(chan struct {
		on     bool
		budget int
		ack    chan struct{}
	})

	go func() { // credit pump (never touches testing.T)
		defer close(pumpExit)
		// DETERMINISTIC pump: states are sequential blocks, not select races.
		// N1: every wait is a select bounded by stop/stopRun/ctx/exit/fatal
		// — no busy loop, no sleep, no polling; the pump can never starve a
		// window switch (requests are served between swaps, never after a
		// partial hand: unbuffered hands complete only at rendezvous).
		//   S_wait:  no window open. Wait for a switch request and CLOSE-ack
		//            it immediately (nothing live: exact sync by
		//            construction — the ack happens-before any later hand).
		//   S_run:   window open with budget. One iteration = one swap:
		//            (1) check pending switch FIRST (non-blocking): CLOSE
		//            before the hand stops the window exactly;
		//            (2) hand a credit — rendezvous == swap STARTED, strictly
		//            AFTER every event processed before it, including the
		//            OPEN-ack;
		//            (3) drain the swap's completion (writer writes
		//            w.commitDone AFTER the durable COMMIT) into pumpDone —
		//            exact COMMIT order (one live swap at a time);
		//            (4) check pending switch again: a CLOSE accepted here is
		//            acked ONLY after the swap's completion was mirrored, so
		//            a close-ack means "nothing authorized-but-unobserved".
		//   Budget:  per-window bound; an OPEN may arrive while swapping ->
		//            handled in S_run (re-armed budget, next hand post-ack).
		//   Stop:    the pump NEVER consumes w.err (the owner's transport);
		//            it exits on w.fatal, w.exit, stopRun, stop or ctx.
		type switchReq = struct {
			on     bool
			budget int
			ack    chan struct{}
		}
		open := false
		budget := 0
		nextGen := 1
		altGen := func() int {
			g := nextGen
			nextGen = 1 - g
			return g
		}
		ackNow := func(ack chan struct{}) bool {
			select {
			case ack <- struct{}{}: // rendezvous: owner has the ack
			case <-stop:
				return false
			case <-ctx.Done():
				return false
			}
			return true
		}
		// takeSwitch non-blocking: report a pending window request if any.
		takeSwitch := func() (switchReq, bool) {
			select {
			case p := <-pumpReq:
				return p, true
			default:
				return switchReq{}, false
			}
		}
		// serveSwitch applies a request and acks it. CLOSE acks are exact by
		// S_run ordering (acked only between swaps, post-drain). OPEN acks:
		// if called from S_run a swap MAY be mid-flight — in that case the
		// ack is deferred and sent after that swap's drain (S_run step 4).
		for {
			// S_wait
			for !open || budget <= 0 {
				select {
				case p := <-pumpReq:
					open, budget = p.on, p.budget
					if open {
						// Re-enter S_run after the ack.
						if !ackNow(p.ack) {
							return
						}
					} else {
						if !ackNow(p.ack) {
							return
						}
					}
					continue
				case <-w.fatal:
					return
				case <-w.exit:
					return
				case <-w.stopRun:
					return
				case <-stop:
					return
				case <-ctx.Done():
					return
				}
			}
			// S_run: one swap per iteration, switch-checked both sides.
			var req switchReq
			var haveReq bool
			if req, haveReq = takeSwitch(); haveReq {
				open, budget = req.on, req.budget
				if !ackNow(req.ack) {
					return
				}
				continue
			}
			// hand credit (rendezvous == start). Bounded + switch-aware:
			// a switch may NOT slip in mid-hand — the unbuffered send
			// completes only with the writer's take — but stop/fatal/exit
			// still bound the wait; a switch queued meanwhile is served on
			// the next loop's step (1), strictly before the NEXT hand.
			select {
			case w.commit <- altGen():
			case <-w.fatal:
				return
			case <-w.exit:
				return
			case <-w.stopRun:
				return
			case <-stop:
				return
			case <-ctx.Done():
				return
			}
			// drain: the ONLY consumer of w.commitDone; arrives AFTER the
			// durable COMMIT; mirror to pumpDone in exact commit order.
			var gen int
		drain:
			for {
				select {
				case gen = <-w.commitDone:
					break drain
				case <-w.fatal:
					return
				case <-w.exit:
					return
				case <-w.stopRun:
					return
				case <-ctx.Done():
					return
				}
			}
			select {
			case pumpDone <- gen:
			case <-stop:
				return
			case <-ctx.Done():
				return
			}
			budget--
			// Step 4: if a switch is pending NOW, it is acked only after
			// this swap's completion was mirrored — CLOSE exactness.
			if req, haveReq = takeSwitch(); haveReq {
				open, budget = req.on, req.budget
				if !ackNow(req.ack) {
					return
				}
			}
		}
	}()

	seenA, seenB := 0, 0
	prevGen := -1
	checkGen := func(gens []int, at string) {
		for _, g := range gens {
			if prevGen >= 0 && g == prevGen {
				w.mu.Lock()
				diag := fmt.Sprint(w.log)
				w.mu.Unlock()
				t.Fatalf("%s: writer gens not alternating: prev=%d batch=%v writerLog=%s", at, prevGen, gens, diag)
			}
			prevGen = g
		}
	}
	// switchWindow is an EXACT sync point with the pump.
	//
	// CLOSE: when the ack returns, no credit is undelivered and at most one
	// swap is live; the owner drains that completion (settle loop below), so
	// the round boundary is provably quiet.
	//
	// OPEN is a TWO-STEP barrier (settle): the request reaches the pump from
	// its post-credit state (hand or drain) — it can therefore never slip in
	// before an unobserved hand — and the pump ACKS ONLY AFTER the in-flight
	// swap is fully drained to pumpDone. The owner then consumes that one
	// settled completion. When switchWindow(true) returns: exactly zero
	// undelivered credits, zero undrained swaps — every completion collected
	// afterwards belongs to a swap the pump HANDED strictly after this sync
	// point, i.e. committed strictly after the round's read call started.
	switchWindow := func(on bool, budget int, at string) {
		ack := make(chan struct{})
		select {
		case pumpReq <- struct {
			on     bool
			budget int
			ack    chan struct{}
		}{on: on, budget: budget, ack: ack}:
		case <-watch:
			t.Fatalf("%s: test-deadline bound requesting window switch (on=%v)", at, on)
		}
		select {
		case <-ack:
		case err := <-w.err:
			t.Fatalf("%s: writer failure during window switch: %v", at, err)
		case <-w.exit:
			t.Fatalf("%s: writer exited during window switch", at)
		case <-pumpExit:
			t.Fatalf("%s: pump exited during window switch", at)
		case <-watch:
			t.Fatalf("%s: test-deadline bound awaiting window ack (on=%v)", at, on)
		}
	}

	// switchWindowOpen opens the window. The settle-ack guarantees: zero
	// swaps live, zero credits undelivered, and pumpDone holds AT MOST the
	// single completion drained for the switch (already checkGen'd here, so
	// generation continuity is verified across the round boundary). Every
	// completion collected after this point is a swap HANDED after the ack:
	// started and committed strictly after it.
	switchWindowOpen := func(at string) {
		switchWindow(true, perRoundBudget, at)
		select {
		case g := <-pumpDone:
			checkGen([]int{g}, fmt.Sprintf("%s settled-drain", at))
		default:
		}
	}
	// switchWindowClose revokes all further credits.
	switchWindowClose := func(at string) { switchWindow(false, 0, at) }

	collect := func(n int, at string) []int {
		gens := make([]int, 0, n)
		for len(gens) < n {
			select {
			case g := <-pumpDone:
				gens = append(gens, g)
			case err := <-w.err:
				t.Fatalf("%s: writer failure: %v", at, err)
				return nil
			case <-w.exit:
				t.Fatalf("%s: writer exited after %d/%d commits", at, len(gens), n)
				return nil
			case <-pumpExit:
				t.Fatalf("%s: pump exited after %d/%d commits", at, len(gens), n)
				return nil
			case <-ctx.Done():
				t.Fatalf("%s: ctx done after %d/%d commits: %v", at, len(gens), n, ctx.Err())
				return nil
			case <-watch:
				t.Fatalf("%s: test-deadline bound after %d/%d commits", at, len(gens), n)
				return nil
			}
		}
		return gens
	}

	const rounds = 8
	for round := 0; round < rounds; round++ {
		w.checkFailed(t, "pre-round")
		// OPEN: rendezvous-acked at the pump's decision point (S_wait, or
		// step (1)/(4) of S_run between swaps). From the instant the ack is
		// received, EVERY hand the pump makes starts strictly after it, so
		// every completion collected from now belongs to a swap started
		// after the ack. A swap that was mid-flight when the OPEN arrived
		// has its completion mirrored BEFORE the pump acks (S_run step (3)
		// precedes (4)); the drain below consumes it, preserving the
		// round-boundary invariant "nothing authorized-but-unobserved".
		switchWindowOpen(fmt.Sprintf("round %d open", round))
		// ACTIVE READ INTERVAL begins at this call.
		v, rerr := s.AdminVerifier(ctx)
		w.checkFailed(t, fmt.Sprintf("round %d post-read", round))
		if rerr != nil {
			t.Fatalf("round %d reader: %v", round, rerr)
		}
		got := append(append([]byte{}, v.Salt...), v.DerivedKey...)
		switch string(got) {
		case string(pairA):
			seenA++
		case string(pairB):
			seenB++
		default:
			t.Fatalf("round %d reader observed a MIXED record: %x", round, got)
		}
		// OVERLAP WITNESSES: the read returned; the read window stays open,
		// so the pump keeps handing credits (bounded by perRoundBudget) and
		// completions keep arriving. Collecting minOverlapPerRound=2 of
		// them — each mirrored only AFTER its durable COMMIT, each HANDED
		// after this round's OPEN ack which itself precedes the read call —
		// witnesses commits completing while the production read is active.
		gens := collect(minOverlapPerRound, fmt.Sprintf("round %d overlap", round))
		checkGen(gens, fmt.Sprintf("round %d overlap-alternation", round))
		// CLOSE: the ack is delivered only BETWEEN swaps, after that swap's
		// completion was mirrored (S_run step (4)) — a close-ack means the
		// pipeline is settled. A completion may already sit buffered in
		// pumpDone (mirrored just before the close was taken): consume it as
		// the round's last witness.
		switchWindowClose(fmt.Sprintf("round %d close", round))
		select {
		case g := <-pumpDone:
			checkGen([]int{g}, fmt.Sprintf("round %d settled-at-close", round))
		default:
		}
		// Post-close the window is revoked: no hand may start, nothing is
		// live (step-(4) exactness), so no further completion can appear.
		select {
		case g2 := <-pumpDone:
			t.Fatalf("round %d: completion gen=%d after settled close — pipeline accounting violated", round, g2)
		case err := <-w.err:
			t.Fatalf("round %d: writer failure after close: %v", round, err)
		case <-time.After(500 * time.Millisecond):
		}
	}
	if seenA == 0 || seenB == 0 {
		t.Fatalf("expected BOTH generations observed under overlap, got A=%d B=%d", seenA, seenB)
	}
}
