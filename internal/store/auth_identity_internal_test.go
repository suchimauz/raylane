package store

// Executable V4 persisted-identity tests: the admin username is committed in
// the SAME transaction as the verifier and the bootstrap closure, the typed
// read re-proves the projected copy, and a pre-existing v3 row (NULL username)
// is the no-identity category — never a panic, never success.

import (
	"context"
	"errors"
	"testing"

	"github.com/suchimauz/raylane/internal/domain"
)

func TestT008StorageV4IdentityRoundTripPreservesExactBytes(t *testing.T) {
	ctx := context.Background()
	s, _ := openFreshAuthStore(t)

	// Multibyte username: 3 Cyrillic runes = 6 UTF-8 bytes; the EXACT bytes
	// must round-trip, never trimmed or normalized.
	username := []byte("админ")
	if err := s.CreateAdminIdentityAndConsumeBootstrap(ctx, username, syntheticVerifier()); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	id, err := s.AdminIdentity(ctx)
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if string(id.Username) != string(username) {
		t.Fatalf("username round-trip = %q, want exact %q", id.Username, username)
	}
	// Closure is consumed; a second create is the typed conflict.
	if err := s.CreateAdminIdentityAndConsumeBootstrap(ctx, []byte("other"), syntheticVerifier()); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second create = %v, want ErrConflict", err)
	}
	// Bootstrap is durably closed.
	consumed, err := s.BootstrapConsumed(ctx)
	if err != nil || !consumed {
		t.Fatalf("bootstrap consumed = %v, %v; want true, nil", consumed, err)
	}
}

func TestT008StorageV4IdentityAbsentIsNoIdentityCategory(t *testing.T) {
	ctx := context.Background()
	s, _ := openFreshAuthStore(t)
	// No admin yet: the identity read is the no-identity category.
	if _, err := s.AdminIdentity(ctx); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("absent identity = %v, want ErrNotFound", err)
	}
}

func TestT008StorageV4IdentityRejectsMalformedUsername(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		user []byte
	}{
		{"empty", []byte{}},
		{"too-many-codepoints", make([]byte, 0)},
		{"invalid-utf8", []byte{0xff, 0xfe}},
	} {
		s, _ := openFreshAuthStore(t)
		user := tc.user
		if tc.name == "too-many-codepoints" {
			// 257 'a' runes exceeds the 256 code-point bound.
			for i := 0; i < 257; i++ {
				user = append(user, 'a')
			}
		}
		if err := s.CreateAdminIdentityAndConsumeBootstrap(ctx, user, syntheticVerifier()); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("%s: create = %v, want ErrConflict", tc.name, err)
		}
		// Rejected create must not have consumed bootstrap.
		if consumed, err := s.BootstrapConsumed(ctx); err != nil || consumed {
			t.Fatalf("%s: bootstrap consumed = %v, %v; want false, nil", tc.name, consumed, err)
		}
	}
}

// A v3-created admin (verifier + closure, but the username column is NULL)
// reads as the no-identity category: the K1-style select requires a TEXT
// username, so the NULL-username row matches nothing. This is the fail-closed
// behaviour for a pre-V4 admin — no invented identity, no reopened bootstrap.
func TestT008StorageV4V3RowWithoutUsernameIsNoIdentity(t *testing.T) {
	ctx := context.Background()
	s, _ := openFreshAuthStore(t)
	// Create via the v3 path (verifier only, no username).
	if err := s.CreateAdminAndConsumeBootstrap(ctx, syntheticVerifier()); err != nil {
		t.Fatalf("v3 create: %v", err)
	}
	// v3 admin exists and verifies...
	if _, err := s.AdminVerifier(ctx); err != nil {
		t.Fatalf("v3 verifier read: %v", err)
	}
	// ...but has no persisted identity.
	if _, err := s.AdminIdentity(ctx); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("v3-row identity = %v, want ErrNotFound (no-identity category)", err)
	}
}

// Embedded-NUL byte bound: a row whose username is "x\x00" followed by a
// large tail reports length(TEXT)=1 (SQLite counts code points only up to the
// first NUL), so a length(TEXT) guard would pass it and project an unbounded
// username. The byte-length guard length(CAST(username AS BLOB)) must reject
// it at the SQL boundary — the read is the no-identity category, and the
// oversized bytes are never projected into Go.
func TestT008StorageV4EmbeddedNULUsernameIsRejected(t *testing.T) {
	ctx := context.Background()
	s, path := openFreshAuthStore(t)
	// Plant a hostile row directly through the private pool, bypassing the
	// validated create, to plant a TEXT username whose BYTE length far exceeds
	// the bound but whose length(TEXT) is 1 (NUL at index 1).
	hostile := append([]byte{'x', 0x00}, bytesOf(0x61, 20000)...)
	if err := authIdentityPlantRowForTests(ctx, s, path, hostile); err != nil {
		t.Fatalf("plant hostile row: %v", err)
	}
	// The identity read must be the no-identity category, never projecting the
	// 20,002 hostile bytes into Go.
	if _, err := s.AdminIdentity(ctx); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("embedded-NUL identity = %v, want ErrNotFound (byte-bound guard)", err)
	}
}

// A username whose byte length is within the hard bound but whose code-point
// count exceeds 256 must also be rejected (byte-bound passes, rune-bound fails
// in Go). 300 ASCII 'a' bytes are 300 runes, over the 256 code-point limit.
func TestT008StorageV4TooManyCodePointsRejected(t *testing.T) {
	ctx := context.Background()
	s, path := openFreshAuthStore(t)
	tooMany := bytesOf('a', 300) // 300 bytes, 300 runes: bytes<=1024 but runes>256
	if err := authIdentityPlantRowForTests(ctx, s, path, tooMany); err != nil {
		t.Fatalf("plant row: %v", err)
	}
	if _, err := s.AdminIdentity(ctx); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("over-codepoint identity = %v, want ErrNotFound (rune bound)", err)
	}
}

// authIdentityPlantRowForTests inserts a complete valid verifier row with a
// caller-supplied raw username through the SAME private pool the production
// table lives on (no production seam is added). It is used ONLY to plant
// hostile or boundary rows the validated create would reject, so the read
// guard can be proven against them. The closure row is inserted so the record
// is a realistic consumed state; the read under test only consults
// admin_verifier.
func authIdentityPlantRowForTests(ctx context.Context, s *Store, path string, username []byte) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_verifier (id, format_version, argon2_version, time_cost, memory_kib, parallelism, salt, derived_key, username)
		 VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)`,
		authFormatVersion, authArgon2Version, authTimeCost, authMemoryKiB, authParallelism,
		bytesOf(0x11, authSaltBytes), bytesOf(0x22, authDerivedKeyByte), string(username)); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO bootstrap_state (id, consumed) VALUES (1, 1)`)
	return err
}
