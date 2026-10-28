package store

import (
	"context"
	"database/sql"

	"github.com/suchimauz/raylane/internal/domain"
)

// This file is the idiomatic Go test-adapter surface: declarations compiled
// ONLY into test builds, visible to the external package store_test tests
// (and the in-package white-box tests) that need raw-pool inspection and
// mid-transaction fault injection. Production builds exclude it entirely, so
// the raw *sql.DB handle, the pragma probe and the write hook are NOT part of
// the product API surface. They exist solely to prove the accepted behaviour:
// connection invariants hold on every pooled connection, migrations and
// identity creation are atomic, and a mid-transaction cancel/fail leaves no
// partial publication. No production caller uses them (T008 composition
// boundary, architect decision §1 "Store API closure — settled minimal
// approach").

// SetHookOnlyForTests installs a mid-transaction interception hook used by
// tests to cancel or fail a write between revision insert and draft-head move.
// It is not part of the product behaviour; production code never calls it.
func (s *Store) SetHookOnlyForTests(hook func() error) { s.hook = hook }

// OpenPreservationForTests is a TEST-ONLY decryption oracle for the V4/T012
// managed-node preservation container. It opens the sealed_secrets blob under
// the node's preservation (ref, purpose) with the trusted test key and returns
// the EXACT original-components plaintext. Production builds exclude it; it is
// the only sanctioned way tests recover original bytes (the product itself
// never reads preservation plaintext back through the safe reader).
func OpenPreservationForTests(ctx context.Context, s *Store, keyPath, nodeID string) ([]byte, error) {
	ks, err := NewKeyStore(keyPath)
	if err != nil {
		return nil, err
	}
	sub, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer sub.Rollback()
	var ref, purpose string
	if err := sub.QueryRowContext(ctx,
		`SELECT ref, purpose FROM node_preservation WHERE node_id = ?`, nodeID).
		Scan(&ref, &purpose); err != nil {
		return nil, err
	}
	var blob []byte
	if err := sub.QueryRowContext(ctx,
		`SELECT blob FROM sealed_secrets WHERE ref = ? AND purpose = ?`, ref, purpose).
		Scan(&blob); err != nil {
		return nil, err
	}
	aead, err := ks.aead()
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	aad := secretAAD(secretFormatV1, ks.Version(), purpose, domain.SecretRef(ref))
	plain, err := aead.Open(nil, nil, blob, aad)
	if err != nil {
		return nil, ErrSecretAuth
	}
	cp := append([]byte(nil), plain...)
	return cp, nil
}

// DB exposes the pool for read-only inspection in tests. It is not part of
// the product API surface; callers must not issue schema changes through it.
func (s *Store) DB() *sql.DB { return s.db }

// DecodeProtocolStringForTests is a TEST-ONLY view of the store-private
// protocol retention guard in decodeProtocolString: it reports whether the
// envelope's own protocol token is a scalar (valid UTF-8, well-formed escapes,
// no unpaired surrogate) and returns the retained value. Production builds
// exclude it; the maintained scalar-integrity regression uses it to pin the
// guard itself, which the end-to-end store path cannot exercise in isolation
// (the unrelated prof.HasProtocol unknown-name gate masks guard removal).
func DecodeProtocolStringForTests(raw []byte) (string, bool) { return decodeProtocolString(raw) }

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
