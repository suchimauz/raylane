package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/suchimauz/raylane/internal/domain"
)

// Secret storage errors (T007). Messages are generic and secret-free by
// construction: they carry no plaintext, ciphertext, nonce, key material or
// unsafe input echoes. Callers match with errors.Is.
var (
	// ErrKeyUnavailable reports that the trusted key could not be opened or
	// validated: missing, malformed length, unsafe owner/permissions,
	// symlink or non-regular file, untrusted parent replacement. It fails
	// closed; there is never a plaintext fallback.
	ErrKeyUnavailable = errors.New("store: secret key unavailable")
	// ErrSealedSecretNotFound reports that no sealed value exists for a
	// reference under the requested purpose. Presence metadata (a secret_refs
	// placeholder row) is not proof that a value exists.
	ErrSealedSecretNotFound = errors.New("store: sealed secret not found")
	// ErrSecretAuth reports that authentication of a sealed record failed:
	// corruption, truncation, wrong key, unsupported envelope version, or a
	// purpose/record-identity binding mismatch. No plaintext is ever returned
	// and no partial value is usable.
	ErrSecretAuth = errors.New("store: secret authentication failed")
	// ErrSecretRefConflict reports that a value already exists for the
	// reference/purpose pair. Replacement is an explicit separate operation;
	// an implicit overwrite is refused.
	ErrSecretRefConflict = errors.New("store: secret reference conflict")
)

// secretFormatV1 is the only envelope format this package understands. The
// envelope is: AEAD(nonce-prefixed GCM ciphertext) over the plaintext, with an
// authenticated additional-data binding computed by secretAAD. A record whose
// format or key version differs fails closed (ErrSecretAuth); reading an old
// database after upgrade keeps working because rows carry their own versions.
const secretFormatV1 = 1

// SecretStore is the secret-store initialization boundary of an existing
// Store. Opening ordinary configuration storage (Open) never requires the
// master key and never fails because one is missing; secret operations become
// available only after this explicit initialization at the internal boundary,
// and their failure mode is fail-closed — never a plaintext fallback.
type SecretStore struct {
	store *Store
	keys  *KeyStore
}

// OpenSecretStore initializes the secret-store boundary for an opened Store
// with the master key from the service-configured trusted location. The path
// is operator configuration, never request-supplied. Missing, malformed or
// unsafe key material returns an error wrapping ErrKeyUnavailable; no key is
// ever created, regenerated or read from the database.
func OpenSecretStore(s *Store, keyPath string) (*SecretStore, error) {
	if s == nil {
		return nil, errors.New("store: secret store requires an opened store")
	}
	ks, err := NewKeyStore(keyPath)
	if err != nil {
		return nil, err
	}
	return &SecretStore{store: s, keys: ks}, nil
}

// OpenPreservation reads back the exact original-components plaintext of one
// node's preservation container. It resolves the node's (ref, purpose) from
// the owner/link metadata and authenticates the sealed blob with the trusted
// key, returning the exact bytes the operator submitted. This is the trusted
// management-side readback used to verify sealed-original preservation over a
// real process; the keyless safe reader never exposes it.
func (ss *SecretStore) OpenPreservation(ctx context.Context, nodeID string) ([]byte, error) {
	var ref, purpose string
	err := ss.store.db.QueryRowContext(ctx,
		`SELECT ref, purpose FROM node_preservation WHERE node_id = ?`, nodeID).
		Scan(&ref, &purpose)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSealedSecretNotFound
	}
	if err != nil {
		return nil, err
	}
	if ref == "" || purpose != nodeID+":"+SentinelPurpose {
		return nil, fmt.Errorf("%w: malformed preservation binding", ErrSecretAuth)
	}
	return ss.Open(ctx, domain.SecretRef(ref), purpose)
}

// Seal stores plaintext under ref for the given purpose as an authenticated
// immutable envelope and registers the reference in the existing secret_refs
// metadata table, all in one transaction: either both rows exist or neither
// does, and cancellation leaves no half-published record. Re-sealing the same
// (ref, purpose) pair is refused with ErrSecretRefConflict — rows are
// immutable, and a secret "replacement" means sealing a NEW ref that NEWER
// revisions point at; the material behind an older immutable revision's ref
// never changes.
//
// This is a trusted internal operation bound to purpose; there is no
// public/HTTP seal or read endpoint in this package.
func (ss *SecretStore) Seal(ctx context.Context, ref domain.SecretRef, purpose string, plaintext []byte) error {
	if ref == "" || purpose == "" {
		return errors.New("store: secret ref and purpose are required")
	}
	aad := secretAAD(secretFormatV1, ss.keys.Version(), purpose, ref)
	aead, err := ss.keys.aead()
	if err != nil {
		return ErrKeyUnavailable
	}
	// cipher.NewGCMWithRandomNonce prepends a fresh 96-bit random nonce on
	// every Seal, so sealing equal plaintext twice yields distinct
	// nonce+ciphertext pairs (verified in tests). Its documented per-key
	// ceiling is 2^32 messages per key generation.
	blob := aead.Seal(nil, nil, plaintext, aad)

	tx, err := ss.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO sealed_secrets (ref, purpose, format, key_version, blob) VALUES (?, ?, ?, ?, ?)`,
		string(ref), purpose, secretFormatV1, ss.keys.Version(), blob)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrSecretRefConflict
		}
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n != 1 {
		return ErrSecretRefConflict
	}
	// Keep the T006 reference-metadata table consistent: a sealed value is
	// always referenceable. INSERT OR IGNORE preserves an existing row.
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO secret_refs (ref) VALUES (?)`, string(ref)); err != nil {
		return err
	}
	if ss.store.hook != nil {
		// Same test-only mid-transaction boundary the T006 revision path uses:
		// failure or cancellation here must leave neither value row nor
		// reference row behind (proved in tests; production never sets it).
		if err := ss.store.hook(); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// HasValue reports whether a sealed VALUE exists for (ref, purpose). This is
// presence metadata from the encrypted store itself — deliberately distinct
// from mere existence of a secret_refs placeholder row, which proves only
// that a reference was mentioned. Presence never decrypts anything.
func (ss *SecretStore) HasValue(ctx context.Context, ref domain.SecretRef, purpose string) (bool, error) {
	var one int
	err := ss.store.db.QueryRowContext(ctx,
		`SELECT 1 FROM sealed_secrets WHERE ref = ? AND purpose = ?`, string(ref), purpose).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Open decrypts the value sealed under (ref, purpose) for trusted internal,
// purpose-bound use (the future engine/backup boundary). It is not a public
// secret-read API and never becomes one through this package. Authentication
// failures — corruption, truncation, wrong key, unsupported format/key
// version, or a record swapped across purpose/ref — return ErrSecretAuth and
// no usable bytes.
func (ss *SecretStore) Open(ctx context.Context, ref domain.SecretRef, purpose string) ([]byte, error) {
	var (
		format, keyVersion int
		blob               []byte
	)
	err := ss.store.db.QueryRowContext(ctx,
		`SELECT format, key_version, blob FROM sealed_secrets WHERE ref = ? AND purpose = ?`,
		string(ref), purpose).Scan(&format, &keyVersion, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSealedSecretNotFound
	}
	if err != nil {
		return nil, err
	}
	if format != secretFormatV1 || keyVersion != KeyVersion {
		// Unsupported versions fail closed; no partial or best-effort open.
		return nil, fmt.Errorf("%w: unsupported record version", ErrSecretAuth)
	}
	return ss.openBlob(ref, purpose, format, keyVersion, blob)
}

// openBlob authenticates one stored envelope. The AAD is recomputed from the
// CALLER'S purpose and ref together with the stored versions: a record copied
// under another ref or purpose, or a query made with the wrong purpose, binds
// to different AAD and fails authentication.
func (ss *SecretStore) openBlob(ref domain.SecretRef, purpose string, format, keyVersion int, blob []byte) ([]byte, error) {
	aead, err := ss.keys.aead()
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	aad := secretAAD(format, keyVersion, purpose, ref)
	plain, err := aead.Open(nil, nil, blob, aad)
	if err != nil {
		// Generic and secret-free: the driver/AEAD error is examined nowhere
		// and echoed to no one.
		return nil, ErrSecretAuth
	}
	return plain, nil
}

// NewSecretRef returns a fresh random SecretRef identifier (local identity per
// the data model; UUIDv4 via the existing stdlib helper — no new dependency).
func NewSecretRef() domain.SecretRef { return domain.SecretRef(newID()) }

// secretAAD builds the unambiguous, bounded authenticated binding for one
// record: format, key version, purpose and ref, each length-prefixed so no
// concatenation ambiguity can forge an equal binding. encoding/binary is the
// only serializer; no general serialization protocol is introduced.
func secretAAD(format, keyVersion int, purpose string, ref domain.SecretRef) []byte {
	var buf []byte
	put := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf = append(buf, l[:]...)
		buf = append(buf, b...)
	}
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], uint64(format))
	buf = append(buf, num[:]...)
	binary.BigEndian.PutUint64(num[:], uint64(keyVersion))
	buf = append(buf, num[:]...)
	put([]byte(purpose))
	put([]byte(ref))
	return buf
}

// isUniqueViolation classifies the driver's unique-constraint failure from
// its message text, examined locally and never returned verbatim (the same
// pattern entities.go uses in guardTranslate): the caller only ever receives
// the typed, secret-free ErrSecretRefConflict.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return containsAny(err.Error(), "UNIQUE", "unique")
}
