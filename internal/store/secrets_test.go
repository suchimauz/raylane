package store_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/store"
)

const testSecretPurpose = "unit-test-purpose"

// All fixtures in this file are synthetic: throwaway keys and the canary
// values below never represent real credentials, and nothing here is dumped
// to logs or Git.

// keyDir returns one stable key directory per test: re-opening the same DB
// after Close reuses the SAME key file, exactly as a service would.
var (
	dirsMu  sync.Mutex
	keyDirs = map[string]string{}
)

func keyDir(t *testing.T) string {
	dirsMu.Lock()
	defer dirsMu.Unlock()
	if d, ok := keyDirs[t.Name()]; ok {
		return d
	}
	d := trustedDir(t) // trusted chain (see key_access_test.go), no /tmp exemption
	keyDirs[t.Name()] = d
	return d
}

// openStoreCache keeps one open *store.Store per dbPath so a test can
// close/reopen deterministically; entries are registered via t.Cleanup.
var (
	openMu     sync.Mutex
	openStores = map[string]*store.Store{}
)

func storeFor(t *testing.T, dbPath string) *store.Store {
	t.Helper()
	openMu.Lock()
	defer openMu.Unlock()
	if s, ok := openStores[dbPath]; ok {
		return s
	}
	s, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("Open(%s): %v", dbPath, err)
	}
	openStores[dbPath] = s
	t.Cleanup(func() {
		openMu.Lock()
		defer openMu.Unlock()
		if cur, ok := openStores[dbPath]; ok && cur == s {
			s.Close()
			delete(openStores, dbPath)
		}
	})
	return s
}

func closeStore(t *testing.T, dbPath string) error {
	t.Helper()
	openMu.Lock()
	defer openMu.Unlock()
	s, ok := openStores[dbPath]
	if !ok {
		return nil
	}
	delete(openStores, dbPath)
	return s.Close()
}

func openSecretsAt(t *testing.T, dbPath, kdir string) *store.SecretStore {
	t.Helper()
	s := storeFor(t, dbPath)
	keyPath := writeKeyFile(t, kdir, "master.key", validTestKey(), 0o600)
	ss, err := openSecretStoreAt(t, s, keyPath)
	if err != nil {
		t.Fatalf("OpenSecretStore: %v", err)
	}
	return ss
}

// openSecretStoreAt initializes the secret store through the PRODUCTION
// constructor: fixtures are production-policy-compliant under the real "/"
// chain (fresh, test-owned directories only — see key_access_test.go), and
// no alternate-anchor seam exists in the package anymore.
func openSecretStoreAt(t *testing.T, s *store.Store, keyPath string) (*store.SecretStore, error) {
	t.Helper()
	return store.OpenSecretStore(s, keyPath) // production initialization boundary
}

func openSecrets(t *testing.T) (*store.SecretStore, string) {
	t.Helper()
	kdir := keyDir(t)
	dbDir := t.TempDir()
	if err := os.Chmod(dbDir, 0o700); err != nil {
		t.Fatalf("chmod dbdir: %v", err)
	}
	dbPath := filepath.Join(dbDir, "raylane.db")
	ss := openSecretsAt(t, dbPath, kdir)
	return ss, dbPath
}

// TestSealOpenPresenceReopen proves the core path: seal → purpose-bound
// internal use → presence metadata → close/reopen persistence, plus the
// wrong-purpose negative. Decryption is asserted only inside this
// purpose-bound unit test; it is not a public secret-read endpoint.
func TestSealOpenPresenceReopen(t *testing.T) {
	ctx := context.Background()
	ss, dbPath := openSecrets(t)
	ref := store.NewSecretRef()
	canary := []byte("CANARY-PLAINTEXT-0f3e")
	if err := ss.Seal(ctx, ref, testSecretPurpose, canary); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := ss.Open(ctx, ref, testSecretPurpose)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, canary) {
		t.Fatal("roundtrip mismatch")
	}
	present, err := ss.HasValue(ctx, ref, testSecretPurpose)
	if err != nil || !present {
		t.Fatalf("HasValue = %v,%v want true", present, err)
	}
	// Wrong purpose: the value exists, yet asking with the wrong purpose
	// must not disclose it.
	if _, err := ss.Open(ctx, ref, "wrong-purpose"); !errors.Is(err, store.ErrSealedSecretNotFound) {
		t.Fatalf("wrong purpose Open err = %v, want ErrSealedSecretNotFound", err)
	}
	// Reopen the same DB with the same key directory: sealed data and
	// presence survive close/reopen.
	if err := closeStore(t, dbPath); err != nil {
		t.Fatalf("close: %v", err)
	}
	ss2 := openSecretsAt(t, dbPath, keyDir(t))
	got2, err := ss2.Open(ctx, ref, testSecretPurpose)
	if err != nil || !bytes.Equal(got2, canary) {
		t.Fatalf("post-reopen Open = %q, %v", got2, err)
	}
	if p2, err := ss2.HasValue(ctx, ref, testSecretPurpose); err != nil || !p2 {
		t.Fatalf("post-reopen HasValue = %v,%v", p2, err)
	}
}

func TestSealedRowsAreImmutableAndConflictOnReseal(t *testing.T) {
	ctx := context.Background()
	ss, _ := openSecrets(t)
	ref := store.NewSecretRef()
	if err := ss.Seal(ctx, ref, testSecretPurpose, []byte("first-CANARY")); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	err := ss.Seal(ctx, ref, testSecretPurpose, []byte("second-CANARY"))
	if !errors.Is(err, store.ErrSecretRefConflict) {
		t.Fatalf("re-seal err = %v, want ErrSecretRefConflict", err)
	}
	// The first value is still the one behind the ref: no implicit overwrite.
	got, err := ss.Open(ctx, ref, testSecretPurpose)
	if err != nil || string(got) != "first-CANARY" {
		t.Fatalf("post-conflict Open = %q, %v", got, err)
	}
}

func TestSecretStoreLeavesNoPlaintextOrKeyInDBFiles(t *testing.T) {
	ctx := context.Background()
	ss, dbPath := openSecretsAt2(t)

	ref := store.NewSecretRef()
	plainCanary := "PLAINTEXT-CANARY-9d21"
	keyCanary := validTestKey()
	if err := ss.Seal(ctx, ref, testSecretPurpose, []byte(plainCanary)); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	s := storeFor(t, dbPath)
	if _, err := s.DB().ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint for inspection: %v", err)
	}
	dir := filepath.Dir(dbPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), filepath.Base(dbPath)) {
			continue // db plus its -wal/-shm siblings
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if i := bytes.Index(data, []byte(plainCanary)); i >= 0 {
			t.Fatalf("plaintext canary found in %s at offset %d", e.Name(), i)
		}
		if i := bytes.Index(data, keyCanary); i >= 0 {
			t.Fatalf("key material found in %s at offset %d", e.Name(), i)
		}
	}
}

func openSecretsAt2(t *testing.T) (*store.SecretStore, string) {
	t.Helper()
	return openSecrets(t)
}

func TestTamperAndForeignKeyFailClosed(t *testing.T) {
	ctx := context.Background()
	ss, dbPath := openSecretsAt2(t)
	s := storeFor(t, dbPath)
	ref := store.NewSecretRef()
	if err := ss.Seal(ctx, ref, testSecretPurpose, []byte("TARGET-CANARY-77")); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	var blob []byte
	if err := s.DB().QueryRowContext(ctx, `SELECT blob FROM sealed_secrets WHERE ref = ?`, string(ref)).Scan(&blob); err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if bytes.Contains(blob, []byte("TARGET-CANARY-77")) {
		t.Fatal("stored blob contains plaintext — AEAD not applied")
	}

	corrupt := append([]byte(nil), blob...)
	corrupt[len(corrupt)-1] ^= 0xff
	trunc := append([]byte(nil), blob...)[:len(blob)-10]

	cases := []struct {
		name string
		blob []byte
	}{
		{"corrupted-tag", corrupt},
		{"truncated", trunc},
	}
	for i, tc := range cases {
		alt := store.NewSecretRef()
		if _, err := s.DB().ExecContext(ctx,
			`INSERT INTO sealed_secrets (ref, purpose, format, key_version, blob) VALUES (?,?,?, ?,?)`,
			string(alt), testSecretPurpose, 1, 1, tc.blob); err != nil {
			t.Fatalf("plant %s: %v", tc.name, err)
		}
		if _, err := s.DB().ExecContext(ctx, `INSERT OR IGNORE INTO secret_refs (ref) VALUES (?)`, string(alt)); err != nil {
			t.Fatalf("plant ref %s: %v", tc.name, err)
		}
		if _, err := ss.Open(ctx, alt, testSecretPurpose); !errors.Is(err, store.ErrSecretAuth) {
			t.Fatalf("%s Open err = %v, want ErrSecretAuth", tc.name, err)
		}
		_ = i
	}

	// Unsupported format/key version fails closed.
	badFmt := store.NewSecretRef()
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO sealed_secrets (ref, purpose, format, key_version, blob) VALUES (?,?,?, ?,?)`,
		string(badFmt), testSecretPurpose, 99, 1, blob); err != nil {
		t.Fatalf("plant bad format: %v", err)
	}
	if _, err := ss.Open(ctx, badFmt, testSecretPurpose); !errors.Is(err, store.ErrSecretAuth) {
		t.Fatalf("unsupported format err = %v, want ErrSecretAuth", err)
	}
	badKey := store.NewSecretRef()
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO sealed_secrets (ref, purpose, format, key_version, blob) VALUES (?,?,?, ?,?)`,
		string(badKey), testSecretPurpose, 1, 99, blob); err != nil {
		t.Fatalf("plant bad key version: %v", err)
	}
	if _, err := ss.Open(ctx, badKey, testSecretPurpose); !errors.Is(err, store.ErrSecretAuth) {
		t.Fatalf("unsupported key version err = %v, want ErrSecretAuth", err)
	}

	// Record swap: a row whose binding was made for another purpose must not
	// open under the wrong purpose even if its ref is planted there.
	swapRef := store.NewSecretRef()
	other := store.NewSecretRef()
	if err := ss.Seal(ctx, other, "other-purpose", []byte("SWAP-CANARY")); err != nil {
		t.Fatalf("Seal other: %v", err)
	}
	var otherBlob []byte
	if err := s.DB().QueryRowContext(ctx, `SELECT blob FROM sealed_secrets WHERE ref = ?`, string(other)).Scan(&otherBlob); err != nil {
		t.Fatalf("read other blob: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO sealed_secrets (ref, purpose, format, key_version, blob) VALUES (?,?,?, ?,?)`,
		string(swapRef), testSecretPurpose, 1, 1, otherBlob); err != nil {
		t.Fatalf("plant swapped row: %v", err)
	}
	if out, err := ss.Open(ctx, swapRef, testSecretPurpose); !errors.Is(err, store.ErrSecretAuth) {
		t.Fatalf("purpose/record swap err = %v (%q), want ErrSecretAuth and no plaintext", err, out)
	}

	// Wrong key: same ciphertext, different key file, must not open.
	kdir2 := keyDir(t) + ".alt"
	if err := os.Mkdir(kdir2, 0o700); err != nil {
		t.Fatalf("mkdir alt keydir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(kdir2) })
	s3, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open for wrong-key case: %v", err)
	}
	defer s3.Close()
	altKey := make([]byte, 32)
	copy(altKey, validTestKey())
	altKey[0] ^= 0xa5
	ssWrong, err := openSecretStoreAt(t, s3, writeKeyFile(t, kdir2, "alt.key", altKey, 0o600))
	if err != nil {
		t.Fatalf("OpenSecretStore(wrong key): %v", err)
	}
	if out, err := ssWrong.Open(ctx, ref, testSecretPurpose); !errors.Is(err, store.ErrSecretAuth) {
		t.Fatalf("wrong key err = %v (%q), want ErrSecretAuth and no plaintext", err, out)
	}

	// The errors themselves are generic and leak nothing.
	if _, err := ssWrong.Open(ctx, ref, testSecretPurpose); err != nil &&
		strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("error text leaked canary: %v", err)
	}
}

func TestPlaceholderRefIsNotPresence(t *testing.T) {
	ctx := context.Background()
	ss, dbPath := openSecrets(t)
	s := storeFor(t, dbPath)
	// The T006 path registers a bare reference (placeholder metadata only).
	if _, err := s.DB().ExecContext(ctx, `INSERT INTO secret_refs (ref) VALUES ('placeholder-ref')`); err != nil {
		t.Fatalf("insert placeholder: %v", err)
	}
	present, err := ss.HasValue(ctx, domain.SecretRef("placeholder-ref"), testSecretPurpose)
	if err != nil {
		t.Fatalf("HasValue: %v", err)
	}
	if present {
		t.Fatal("a secret_refs placeholder row reported presence of a value")
	}
	if _, err := ss.Open(ctx, "placeholder-ref", testSecretPurpose); !errors.Is(err, store.ErrSealedSecretNotFound) {
		t.Fatalf("Open(placeholder) err = %v, want ErrSealedSecretNotFound", err)
	}
}

func TestSealRollbackLeavesNoPartialPublication(t *testing.T) {
	ctx := context.Background()
	ss, dbPath := openSecrets(t)
	s := storeFor(t, dbPath)
	canary := "ROLLBACK-CANARY-42"
	s.SetHookOnlyForTests(func() error { return errors.New("injected mid-transaction failure") })
	ref := store.NewSecretRef()
	if err := ss.Seal(ctx, ref, testSecretPurpose, []byte(canary)); err == nil {
		t.Fatal("Seal succeeded despite injected failure")
	}
	s.SetHookOnlyForTests(nil)
	// Neither the value row nor the reference row may exist afterwards.
	var n int
	if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM sealed_secrets WHERE ref = ?`, string(ref)).Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial value row published: n=%d err=%v", n, err)
	}
	if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM secret_refs WHERE ref = ?`, string(ref)).Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial reference row published: n=%d err=%v", n, err)
	}
	// Cancellation path: a context cancelled before the call must not
	// publish either row. (sql guarantees no statement runs on a dead
	// context; BeginTx itself fails.)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	ref2 := store.NewSecretRef()
	if err := ss.Seal(cctx, ref2, testSecretPurpose, []byte(canary)); err == nil {
		t.Fatal("Seal succeeded on cancelled context")
	}
	if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM sealed_secrets WHERE ref = ?`, string(ref2)).Scan(&n); err != nil || n != 0 {
		t.Fatalf("cancelled Seal published value rows: n=%d err=%v", n, err)
	}
}

func TestV1DatabaseUpgradesWithoutRewritingCore(t *testing.T) {
	ctx := context.Background()
	dbDir := t.TempDir()
	if err := os.Chmod(dbDir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	dbPath := filepath.Join(dbDir, "legacy.db")
	// Build a genuine v1-only database: apply only the core migration.
	plain, err := store.OpenLegacyV1ForTests(ctx, dbPath)
	if err != nil {
		t.Fatalf("v1 fixture: %v", err)
	}
	// Real configuration content written under v1.
	if _, err := plain.SaveDraft(ctx, []byte(`{"note":"v1 snapshot"}`), domain.ValidationNotRun, nil, nil, 0); err != nil {
		t.Fatalf("v1 SaveDraft: %v", err)
	}
	docBefore, hashBefore := readCoreSnapshotForTests(t, ctx, plain)
	if err := plain.Close(); err != nil {
		t.Fatalf("close v1: %v", err)
	}
	// Reopen through the current code: the v2 step must upgrade transactionally.
	s2, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("upgrade open: %v", err)
	}
	t.Cleanup(func() { s2.Close() })
	ss, err := openSecretStoreAt(t, s2, writeKeyFile(t, keyDir(t), "up.key", validTestKey(), 0o600))
	if err != nil {
		t.Fatalf("OpenSecretStore after upgrade: %v", err)
	}
	// The v1 configuration is intact and unchanged.
	docAfter, hashAfter := readCoreSnapshotForTests(t, ctx, s2)
	if docBefore != docAfter || hashBefore != hashAfter {
		t.Fatal("upgrade rewrote or lost core configuration")
	}
	// Secret operations work on the upgraded database.
	ref := store.NewSecretRef()
	if err := ss.Seal(ctx, ref, testSecretPurpose, []byte("UPGRADE-CANARY")); err != nil {
		t.Fatalf("Seal after upgrade: %v", err)
	}
	got, err := ss.Open(ctx, ref, testSecretPurpose)
	if err != nil || string(got) != "UPGRADE-CANARY" {
		t.Fatalf("Open after upgrade: %q %v", got, err)
	}
}

func readCoreSnapshotForTests(t *testing.T, ctx context.Context, s *store.Store) (string, string) {
	t.Helper()
	var doc, created string
	if err := s.DB().QueryRowContext(ctx,
		`SELECT doc, created_at FROM revisions ORDER BY seq LIMIT 1`).Scan(&doc, &created); err != nil {
		t.Fatalf("read core snapshot: %v", err)
	}
	return doc, created
}

// TestSamePlaintextTwoRefsDistinctEnvelopes is the committed nonce regression
// (T007-C1): sealing the SAME synthetic plaintext under the same key and
// purpose for two distinct refs must produce distinct random nonces and
// distinct full envelopes, and both must decrypt to the original plaintext.
// This is the stdlib cipher.NewGCMWithRandomNonce representation: every blob
// begins with its own fresh 96-bit nonce (GCM tag size 16, so overhead 28).
func TestSamePlaintextTwoRefsDistinctEnvelopes(t *testing.T) {
	ctx := context.Background()
	ss, dbPath := openSecrets(t)
	plaintext := []byte("SAME-PLAINTEXT-NONCE-CANARY-1a2b")
	refA, refB := store.NewSecretRef(), store.NewSecretRef()
	if err := ss.Seal(ctx, refA, testSecretPurpose, plaintext); err != nil {
		t.Fatalf("Seal A: %v", err)
	}
	if err := ss.Seal(ctx, refB, testSecretPurpose, plaintext); err != nil {
		t.Fatalf("Seal B: %v", err)
	}
	blobA := readEnvelopeBlobForTests(t, ctx, storeFor(t, dbPath), refA)
	blobB := readEnvelopeBlobForTests(t, ctx, storeFor(t, dbPath), refB)
	const nonceLen = 12
	if len(blobA) != len(plaintext)+28 || len(blobB) != len(plaintext)+28 {
		t.Fatalf("unexpected envelope size: %d %d", len(blobA), len(blobB))
	}
	if bytes.Equal(blobA[:nonceLen], blobB[:nonceLen]) {
		t.Fatal("identical random nonces for two seals of the same plaintext")
	}
	if bytes.Equal(blobA, blobB) {
		t.Fatal("identical ciphertext envelopes for two seals of the same plaintext")
	}
	for i, ref := range []domain.SecretRef{refA, refB} {
		got, err := ss.Open(ctx, ref, testSecretPurpose)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("Open ref %d: %q %v", i, got, err)
		}
	}
}

func readEnvelopeBlobForTests(t *testing.T, ctx context.Context, s *store.Store, ref domain.SecretRef) []byte {
	t.Helper()
	var blob []byte
	if err := s.DB().QueryRowContext(ctx,
		`SELECT blob FROM sealed_secrets WHERE ref = ? AND purpose = ?`, ref, testSecretPurpose).Scan(&blob); err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	return blob
}
