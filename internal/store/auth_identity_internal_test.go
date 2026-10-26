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
