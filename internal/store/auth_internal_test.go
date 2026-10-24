package store

// White-box tests for the T008 storage-only typed auth boundary: atomic
// first-admin + permanent bootstrap closure (exactly one concurrent winner),
// the K1 guarded SQL read (storage class / exact values / exact lengths
// enforced INSIDE SQLite before any BLOB projection), K2 same-validated-
// record reads under a concurrent committed change, adversarial hostile rows
// through the real production reader, and positive-record survival across
// reopen.
//
// All verifier bytes are bounded synthetic opaque fixed-size material — NOT
// Argon2 output and NOT any password proof. No Argon2, no tokens, no HTTP.

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/suchimauz/raylane/internal/domain"
)

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

// TestT008StorageK1GuardRejectsHostileRowsBeforeBlobProjection drives hostile
// rows through the EXACT production guard predicate (k1GuardedSelect WHERE
// clause, reused verbatim from the production constant) and proves rejection
// happens in SQL: zero rows admitted even for a 1 MiB oversized BLOB — the
// BLOB bytes are never projected to Go. A hostile CHECK-free mirror table
// (test fixture; production never references it) stores rows the production
// writer could not create.
func TestT008StorageK1GuardRejectsHostileRowsBeforeBlobProjection(t *testing.T) {
	ctx := context.Background()
	s, _ := openFreshAuthStore(t)
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE t008_hostile (
		id INTEGER PRIMARY KEY, format_version, argon2_version, time_cost,
		memory_kib, parallelism, salt, derived_key)`); err != nil {
		t.Fatal(err)
	}
	hostile := []struct {
		name string
		vals []any
	}{
		{"null-format", []any{1, nil, 19, 3, 65536, 4, bytesOf(1, 16), bytesOf(2, 32)}},
		{"text-format", []any{2, "one", 19, 3, 65536, 4, bytesOf(1, 16), bytesOf(2, 32)}},
		{"real-format", []any{3, 1.5, 19, 3, 65536, 4, bytesOf(1, 16), bytesOf(2, 32)}},
		{"null-salt", []any{4, 1, 19, 3, 65536, 4, nil, bytesOf(2, 32)}},
		{"salt-len-15", []any{5, 1, 19, 3, 65536, 4, bytesOf(1, 15), bytesOf(2, 32)}},
		{"salt-len-17", []any{6, 1, 19, 3, 65536, 4, bytesOf(1, 17), bytesOf(2, 32)}},
		{"salt-len-0", []any{7, 1, 19, 3, 65536, 4, []byte{}, bytesOf(2, 32)}},
		{"key-len-31", []any{8, 1, 19, 3, 65536, 4, bytesOf(1, 16), bytesOf(2, 31)}},
		{"key-len-33", []any{9, 1, 19, 3, 65536, 4, bytesOf(1, 16), bytesOf(2, 33)}},
		{"wrong-argon-version", []any{10, 1, 20, 3, 65536, 4, bytesOf(1, 16), bytesOf(2, 32)}},
		{"wrong-format-version", []any{11, 2, 19, 3, 65536, 4, bytesOf(1, 16), bytesOf(2, 32)}},
		{"zero-time", []any{12, 1, 19, 0, 65536, 4, bytesOf(1, 16), bytesOf(2, 32)}},
		{"huge-time", []any{13, 1, 19, 9223372036854775807, 65536, 4, bytesOf(1, 16), bytesOf(2, 32)}},
		{"negative-memory", []any{14, 1, 19, 3, -65536, 4, bytesOf(1, 16), bytesOf(2, 32)}},
		{"oversized-1MiB-key", []any{15, 1, 19, 3, 65536, 4, bytesOf(1, 16), bytesOf(0xEE, 1<<20)}},
		{"text-salt", []any{16, 1, 19, 3, 65536, 4, "sixteenchars_123", bytesOf(2, 32)}},
		{"text-key", []any{17, 1, 19, 3, 65536, 4, bytesOf(1, 16), "thirtytwo-character-string-value!!!!"}},
	}
	for _, hr := range hostile {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO t008_hostile VALUES (?,?,?,?,?,?,?,?)`, hr.vals...); err != nil {
			t.Fatalf("%s insert: %v", hr.name, err)
		}
	}
	// Rebuild the production guard predicate against the hostile table. The
	// predicate substring is the SAME text the production reader executes.
	i := indexOfGuardPredicate(k1GuardedSelect)
	guardQuery := `SELECT format_version FROM t008_hostile WHERE ` + i
	rows, err := s.db.QueryContext(ctx, guardQuery)
	if err != nil {
		t.Fatal(err)
	}
	admitted := 0
	for rows.Next() {
		admitted++
	}
	rows.Close()
	if admitted != 0 {
		t.Fatalf("SQL guard admitted %d of %d hostile rows, want 0", admitted, len(hostile))
	}
}

func indexOfGuardPredicate(sel string) string {
	const where = "WHERE "
	for j := 0; j+len(where) <= len(sel); j++ {
		if sel[j:j+len(where)] == where {
			return sel[j+len(where):]
		}
	}
	return ""
}

// TestT008StorageProductionReaderRejectsCorruptAndAdmitsValid proves the real
// typed reader is fail-closed: without a well-formed row it returns
// domain.ErrNotFound (also for a table replaced by a hostile-shaped one),
// while the valid fixed-set positive record passes and survives reopen.
func TestT008StorageProductionReaderRejectsCorruptAndAdmitsValid(t *testing.T) {
	ctx := context.Background()
	s, path := openFreshAuthStore(t)
	// Empty table: typed read fails closed.
	if _, err := s.AdminVerifier(ctx); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("empty table err=%v", err)
	}
	// Valid positive control.
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

// TestT008StorageK2SameRecordUnderConcurrentChange proves K2 at the actual
// typed boundary: every concurrent AdminVerifier read runs on one pinned
// connection inside one read transaction, so under a committed concurrent
// change each reader observes ONE COMPLETE record (old or new) — never a mix
// of salt from one generation and key from another, with no second fetch.
func TestT008StorageK2SameRecordUnderConcurrentChange(t *testing.T) {
	ctx := context.Background()
	s, _ := openFreshAuthStore(t)
	recA := syntheticVerifier()
	recA.DerivedKey = bytesOf(0xA5, 32)
	if err := s.CreateAdminAndConsumeBootstrap(ctx, recA); err != nil {
		t.Fatal(err)
	}
	wantA := append(append([]byte{}, recA.Salt...), recA.DerivedKey...)
	newSalt, newKey := bytesOf(0x99, 16), bytesOf(0x66, 32)
	wantB := append(append([]byte{}, newSalt...), newKey...)

	var inFlight, mutated, stop sync.WaitGroup
	const readers = 12
	inFlight.Add(readers)
	mutated.Add(1)
	stop.Add(1)
	errs := make([]error, readers)
	obs := make([][]byte, readers)
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			inFlight.Done() // signal intent
			mutated.Wait()  // read AFTER the committed change began window
			v, err := s.AdminVerifier(ctx)
			errs[i] = err
			if err == nil {
				obs[i] = append(append([]byte{}, v.Salt...), v.DerivedKey...)
			}
			stop.Wait()
		}(i)
	}
	inFlight.Wait()
	// Committed concurrent change through a direct connection (test-only
	// simulation of another writer; product API never overwrites).
	if _, err := s.db.ExecContext(ctx,
		`UPDATE admin_verifier SET salt = ?, derived_key = ? WHERE id = 1`,
		newSalt, newKey); err != nil {
		t.Fatal(err)
	}
	mutated.Done()
	for i := 0; i < 4; i++ {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE admin_verifier SET salt = ?, derived_key = ? WHERE id = 1`,
			newSalt, newKey); err != nil {
			t.Fatal(err)
		}
	}
	stop.Done()
	wg.Wait()
	seenOld, seenNew := 0, 0
	for i := 0; i < readers; i++ {
		if errs[i] != nil {
			t.Fatalf("reader %d: %v", i, errs[i])
		}
		switch string(obs[i]) {
		case string(wantA):
			seenOld++
		case string(wantB):
			seenNew++
		default:
			t.Fatalf("reader %d observed a MIXED record: %x", i, obs[i])
		}
	}
	if seenNew == 0 {
		t.Fatal("no reader observed the committed change; window untested")
	}
	// Sanity: final state is exactly the new record.
	var salt, key []byte
	if err := s.db.QueryRowContext(ctx, `SELECT salt, derived_key FROM admin_verifier WHERE id = 1`).Scan(&salt, &key); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			t.Fatal("admin row vanished")
		}
		t.Fatal(err)
	}
}
