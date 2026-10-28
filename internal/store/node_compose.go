package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
	"github.com/suchimauz/raylane/internal/jsonscan"
)

// This file composes the trusted internal atomic managed-node CREATE and the
// cold keyless SAFE_READ on top of the accepted Store / SecretStore /
// capability-authority / nodes-validator seams. It is a nonapplying storage
// prerequisite of T012: no HTTP, no full CRUD, no UI, no engine/apply.
//
// Composition invariants:
//   - CreateNodeAtomic writes node + sealed secrets + owner/link rows +
//     validation snapshot + derived safe document in ONE SQLite transaction;
//     any error or cancellation rolls back every new row (existing rows stay).
//   - Secret values are sealed with a PRIVATE same-transaction helper that
//     reuses the Store and tx — never the standalone SecretStore.Seal (which
//     owns its own transaction and must not be nested).
//   - ReadNodeSafe runs in ONE consistent read snapshot, selects ONLY safe
//     derived content and row-EXISTENCE metadata (never a ciphertext blob,
//     never SecretStore.Open), derives CURRENT presence from owner+link+sealed
//     row existence, and re-applies the current authority's closed projection
//     checks to the persisted safe subset. It opens with NO SecretStore/key.

// SentinelPurpose is the exact reserved secret purpose refused for typed
// secret operations: it is reserved for the node's own preservation container
// and can never be claimed by a caller-supplied field.
const SentinelPurpose = "preservation"

// ReservedSecretSentinelValue is the exact reserved "leave this secret
// unchanged" sentinel. A `replace` whose VALUE equals it exactly is refused
// (the OpenAPI SecretUpdate schema rejects it with `not: {const: ...}`);
// matching is by exact equality only, so mask-like and other non-exact
// strings remain legitimate values. The sentinel is never stored and never
// echoed.
const ReservedSecretSentinelValue = "__RAYLANE_SECRET_UNCHANGED_V1__"

// ErrSafeRead is the single static, secret-free refusal category for a cold
// keyless safe-read that fails a binding check (authority digest mismatch,
// revision/metadata drift, malformed persisted verdict or derived content,
// malformed/mismatched owner/purpose). Callers match with errors.Is; the
// message is fixed and carries no driver text, value, ciphertext or name.
var ErrSafeRead = errors.New("store: node failed safe-read binding")

// ErrSecretOp is the static, secret-free refusal for an invalid typed secret
// operation (unknown op, duplicate field, undeclared/nonsecret membership,
// value-presence mismatch, bad size/UTF-8, or the reserved sentinel purpose).
var ErrSecretOp = errors.New("store: invalid secret operation")

// NodeAuthority owns an immutable copy of the trusted capability profile bytes
// and the parsed authority, plus the exact SHA-256 digest of those owned bytes.
// A reader validates the stored authority digest against its own before any
// safe content is exposed, so even a formatting-only change to the profile
// refuses safe reads until an explicit revalidation — never an implicit widened
// read. The bytes are copied at construction and never mutated.
type NodeAuthority struct {
	profile *capability.Profile
	digest  [32]byte
}

// OpenNodeAuthority parses an immutable copy of the trusted profile bytes and
// records the exact SHA-256 over those owned bytes. It never mutates the
// caller's slice and never consults global state.
func OpenNodeAuthority(profileBytes []byte) (*NodeAuthority, error) {
	cp := append([]byte(nil), profileBytes...)
	p, err := capability.Parse(cp)
	if err != nil {
		return nil, fmt.Errorf("store: node authority profile: %w", err)
	}
	return &NodeAuthority{profile: p, digest: sha256.Sum256(cp)}, nil
}

// Profile returns the immutable parsed authority (shared, never mutated).
func (a *NodeAuthority) Profile() *capability.Profile { return a.profile }

// Digest returns the exact 32-byte authority digest of the owned profile bytes.
func (a *NodeAuthority) Digest() [32]byte { return a.digest }

// secretFields returns the declared secret field names for a known protocol,
// derived from the authority's exact field vocabulary. The protocol grammar
// excludes the internal ':' separator, so the derived purpose stays
// unambiguous.
func secretFields(prof *capability.Profile, protocol string) []string {
	var out []string
	for _, name := range prof.FieldNames(protocol) {
		if f, ok := prof.Field(protocol, name); ok && f.Secret {
			out = append(out, name)
		}
	}
	return out
}

// NodeSecretUpdate is one typed secret operation for a managed-node create.
// Op is the closed set {unchanged, replace, clear}. On CREATE, unchanged and
// clear are no-ops (nothing to keep or clear); replace supplies a new value.
// HasValue/Value carry the value only for replace.
type NodeSecretUpdate struct {
	Field    string
	Op       string
	HasValue bool
	Value    string
}

// NodeCreateInput is the trusted internal create payload. The three *_Byte
// components are exact JSON values captured once at entry; LabelBytes is nil
// for an absent label (otherwise a JSON string). The caller supplies no node
// id, revision, profile, result, presence, ref, purpose or chain context — the
// server allocates all of those.
type NodeCreateInput struct {
	ProtocolBytes []byte
	FieldsBytes   []byte
	LabelBytes    []byte // nil = absent; otherwise must be a JSON string
	Secrets       []NodeSecretUpdate
}

// NodeOutcome is the result of an atomic create or a safe read. Validation is
// the FULL actual historical nodes.Result (status, applicability, closed
// issues, secret/unknown name lists, chain/structured checks). SecretPresence
// and Projection.Secrets are CURRENT same-read-snapshot facts derived from
// sealed-row ownership, never historical booleans promoted to truth. No raw
// protocol input, ref, purpose, private error, ciphertext or plaintext field
// is present in the result.
type NodeOutcome struct {
	NodeID   string
	Revision int64
	// Protocol is the protocol STRING exactly as the store decoded it for this
	// outcome: the creation input protocol on a write, and the persisted
	// derived-document protocol on a safe read (empty when the authority did
	// not declare it — the raw protocol never persists outside ciphertext).
	// Never an echo of arbitrary caller bytes on the read path.
	Protocol       string
	Validation     nodes.Result
	SecretPresence map[string]bool
	Projection     capability.ProjectedNode
}

// NodeReader performs cold keyless safe reads. It is constructed with only a
// Store and a NodeAuthority — no SecretStore, key path or key material — and it
// never opens the key or selects a ciphertext blob.
type NodeReader struct {
	store     *Store
	authority *NodeAuthority
}

// OpenNodeReader builds a safe-read reader. It requires no SecretStore and no
// key: safe reads derive current presence from row-EXISTENCE metadata and safe
// content from the persisted derived document, never from decrypted bytes.
func OpenNodeReader(s *Store, auth *NodeAuthority) (*NodeReader, error) {
	if s == nil || auth == nil {
		return nil, errors.New("store: node reader requires a store and an authority")
	}
	return &NodeReader{store: s, authority: auth}, nil
}

// ReadNodeSafe reads one managed node in a single consistent snapshot. It
// fails closed (ErrSafeRead) on any binding violation — authority digest
// mismatch, revision/metadata drift, malformed persisted verdict or derived
// content, malformed/mismatched owner/purpose — with no partial projection and
// no key fallback. It never selects ciphertext and never decrypts.
func (r *NodeReader) ReadNodeSafe(ctx context.Context, id string) (NodeOutcome, error) {
	return r.readNodeSafe(ctx, id)
}

// NodeWriter performs atomic managed-node creates. It embeds a NodeReader so
// both create and read share ONE ReadNodeSafe implementation.
type NodeWriter struct {
	*NodeReader
	ss *SecretStore
}

// OpenNodeWriter builds an atomic-create writer. It requires the SecretStore
// to be bound to the SAME Store and a non-nil authority, plus a real
// initialized key boundary (established by OpenSecretStore). It performs no
// key generation and no trust bypass.
func OpenNodeWriter(s *Store, ss *SecretStore, auth *NodeAuthority) (*NodeWriter, error) {
	if s == nil || ss == nil || auth == nil {
		return nil, errors.New("store: node writer requires a store, secret store and authority")
	}
	if ss.store != s {
		return nil, errors.New("store: node writer requires the secret store bound to the same store")
	}
	if _, err := ss.keys.aead(); err != nil {
		return nil, ErrKeyUnavailable
	}
	r, err := OpenNodeReader(s, auth)
	if err != nil {
		return nil, err
	}
	return &NodeWriter{NodeReader: r, ss: ss}, nil
}

// --- private same-transaction secret helpers (reuse Store + tx) -------------

// sealSecretTX seals one plaintext under (ref, purpose) inside an OUTER
// transaction, writing the sealed_secrets row and the secret_refs placeholder.
// It reuses the SAME Store and tx — never the standalone SecretStore.Seal,
// which owns its own transaction and must not be nested. On unique conflict it
// returns ErrSecretRefConflict.
func sealSecretTX(ctx context.Context, tx *sql.Tx, keys *KeyStore, ref domain.SecretRef, purpose string, plaintext []byte) error {
	if ref == "" || purpose == "" {
		return errors.New("store: secret ref and purpose are required")
	}
	aad := secretAAD(secretFormatV1, keys.Version(), purpose, ref)
	aead, err := keys.aead()
	if err != nil {
		return ErrKeyUnavailable
	}
	blob := aead.Seal(nil, nil, plaintext, aad)
	res, err := tx.ExecContext(ctx,
		`INSERT INTO sealed_secrets (ref, purpose, format, key_version, blob) VALUES (?, ?, ?, ?, ?)`,
		string(ref), purpose, secretFormatV1, keys.Version(), blob)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrSecretRefConflict
		}
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n != 1 {
		return ErrSecretRefConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO secret_refs (ref) VALUES (?)`, string(ref)); err != nil {
		return err
	}
	return nil
}

// hasSealedValueTX reports whether a sealed VALUE row exists for (ref, purpose)
// inside a transaction, using SELECT 1 (row existence only — never the blob).
func hasSealedValueTX(ctx context.Context, tx *sql.Tx, ref domain.SecretRef, purpose string) (bool, error) {
	var one int
	err := tx.QueryRowContext(ctx,
		`SELECT 1 FROM sealed_secrets WHERE ref = ? AND purpose = ?`, string(ref), purpose).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// --- create -----------------------------------------------------------------

// nodePurpose derives the internally unambiguous purpose for a node's
// per-field secret from its server-allocated UUID. The profile field grammar
// excludes the ':' separator, so this is unambiguous.
func nodeFieldPurpose(nodeID, field string) string { return nodeID + ":secret:" + field }

// CreateNodeAtomic creates one managed node atomically. See the file header
// for the full invariant set. It captures/copies the caller's components and
// secret records once at entry and never mutates them.
func (w *NodeWriter) CreateNodeAtomic(ctx context.Context, in NodeCreateInput) (NodeOutcome, error) {
	auth := w.authority
	prof := auth.Profile()

	// Capture/copy components ONCE at entry.
	protocolBytes := append([]byte(nil), in.ProtocolBytes...)
	fieldsBytes := append([]byte(nil), in.FieldsBytes...)
	var labelBytes []byte
	if in.LabelBytes != nil {
		labelBytes = append([]byte(nil), in.LabelBytes...)
	}
	secrets := make([]NodeSecretUpdate, len(in.Secrets))
	copy(secrets, in.Secrets)

	// Gate each component as exactly one complete JSON value via the existing
	// domain/jsonscan semantics. Malformed syntax or trailing content refuses
	// with domain.ErrMalformedJSON and writes nothing.
	for _, comp := range [][]byte{protocolBytes, fieldsBytes} {
		if len(comp) == 0 {
			return NodeOutcome{}, domain.ErrMalformedJSON
		}
		if _, err := domain.ParseDocument(comp); err != nil {
			return NodeOutcome{}, err
		}
	}
	// The protocol must be an EXPLICIT JSON string: a JSON null (decoded by the
	// generic unmarshal into the empty string) or any non-string is a static
	// zero-write component refusal, never coerced into an empty-string protocol
	// that would SAVE. A legal unknown / nonempty JSON STRING still flows to the
	// faithful validator (Invalid SAVE), never this shape gate.
	var protocolRaw json.RawMessage
	if err := json.Unmarshal(protocolBytes, &protocolRaw); err != nil ||
		len(bytes.TrimSpace(protocolRaw)) == 0 ||
		bytes.Equal(bytes.TrimSpace(protocolRaw), []byte("null")) {
		return NodeOutcome{}, errNodeComponent("protocol")
	}
	var protocolStr string
	if err := json.Unmarshal(protocolRaw, &protocolStr); err != nil {
		return NodeOutcome{}, errNodeComponent("protocol")
	}
	// The fields component must be exactly one complete JSON OBJECT, gated
	// STRUCTURALLY on the raw bytes (map[string]json.RawMessage, non-nil) with
	// NO float64 conversion: huge canonical numbers (1E400, very large integers,
	// tiny 1e-400, long fractions) must reach the actual validator, which owns
	// the faithful semantic verdict, instead of being refused here by a lossy
	// any/float64 decode. Null (decodes to a nil map), non-object, malformed,
	// and trailing content remain a static zero-write refusal.
	var fieldsObj map[string]json.RawMessage
	fieldsDec := json.NewDecoder(bytes.NewReader(fieldsBytes))
	if err := fieldsDec.Decode(&fieldsObj); err != nil || fieldsObj == nil {
		return NodeOutcome{}, errNodeComponent("fields")
	}
	var fieldsExtra any
	if err := fieldsDec.Decode(&fieldsExtra); err != io.EOF {
		// Trailing content after the object is not one complete JSON value.
		return NodeOutcome{}, errNodeComponent("fields")
	}

	// Label: absent stays absent; present must be a JSON string of 0..256
	// Unicode characters. The contract field is OPTIONAL with maxLength 256 and
	// NO minLength, so the empty string is accepted exactly; absence (nil) and
	// explicit null stay distinguishable — a present JSON null, a non-string,
	// or >256 runes are a static zero-write refusal. Decoding into a
	// json.RawMessage first keeps null from being silently coerced by a direct
	// string unmarshal.
	if labelBytes != nil {
		var labelRaw json.RawMessage
		if err := json.Unmarshal(labelBytes, &labelRaw); err != nil {
			return NodeOutcome{}, errNodeComponent("label")
		}
		// A present JSON null must stay a refusal: absence (nil labelBytes) and
		// explicit null stay distinguishable. Comparing the trimmed bytes keeps
		// null from being silently coerced by the string unmarshal below.
		if len(bytes.TrimSpace(labelRaw)) == 0 || bytes.Equal(bytes.TrimSpace(labelRaw), []byte("null")) {
			return NodeOutcome{}, errNodeComponent("label") // absent/null
		}
		var labelStr string
		if err := json.Unmarshal(labelRaw, &labelStr); err != nil {
			return NodeOutcome{}, errNodeComponent("label") // non-string
		}
		// Strict PRE-DECODE string-content validity, BEFORE the lossy Go decode.
		//
		// (1) Raw UTF-8 scalar validity on the wire bytes: Go's JSON decoder
		// lossily replaces invalid UTF-8 (including the CESU-8-style surrogate
		// encodings) with U+FFFD, so the decoded string alone can look valid.
		// Validating the inner bytes catches the original invalid sequences and
		// refuses them — a typed label is never silently coerced. A legal U+FFFD
		// literal and a valid surrogate PAIR (a real scalar such as U+10000) are
		// both ordinary valid-UTF-8 here and remain acceptable.
		inner := labelRaw
		if len(inner) >= 2 && inner[0] == '"' && inner[len(inner)-1] == '"' {
			inner = inner[1 : len(inner)-1]
		}
		if !utf8.Valid(inner) {
			return NodeOutcome{}, errNodeComponent("label")
		}
		// (2) Raw JSON STRING-ESCAPE scan on the same wire bytes. ASCII escape
		// sequences such as \ud800 are VALID UTF-8 bytes but encode an UNPAIRED
		// UTF-16 surrogate — not a valid Unicode scalar — and the Go decoder
		// would lossily map them to U+FFFD. This smallest store-private scan
		// (scoped ONLY to the typed label component; it does NOT expand jsonscan
		// or touch any other path) enforces surrogate pairing and well-formed
		// escapes before the lossy decode, and catches raw control bytes.
		if !validJSONStringContent(string(inner)) {
			return NodeOutcome{}, errNodeComponent("label")
		}
		if utf8.RuneCountInString(labelStr) > 256 {
			return NodeOutcome{}, errNodeComponent("label")
		}
	}

	// Validate typed secret operations BEFORE any write (refusal = zero rows).
	knownProtocol := prof.HasProtocol(protocolStr)
	var declaredSecrets map[string]bool
	if knownProtocol {
		declaredSecrets = declaredSecretFields(prof, protocolStr)
	}
	type resolvedOp struct {
		field string
		value string // plaintext for replace (never retained past seal)
		seal  bool
	}
	resolved := make([]resolvedOp, 0, len(secrets))
	seen := map[string]bool{}
	for _, su := range secrets {
		if seen[su.Field] {
			return NodeOutcome{}, fmt.Errorf("%w: duplicate field", ErrSecretOp)
		}
		seen[su.Field] = true
		// Membership: the protocol must resolve declared-secret membership and
		// the field must be an exact declared secret member.
		if !knownProtocol || !declaredSecrets[su.Field] {
			return NodeOutcome{}, fmt.Errorf("%w: field is not a declared secret", ErrSecretOp)
		}
		switch su.Op {
		case "unchanged", "clear":
			// On CREATE these are no-ops; they require no value.
			if su.HasValue || su.Value != "" {
				return NodeOutcome{}, fmt.Errorf("%w: value on a no-op", ErrSecretOp)
			}
		case "replace":
			if !su.HasValue || su.Value == "" {
				return NodeOutcome{}, fmt.Errorf("%w: replace requires a value", ErrSecretOp)
			}
			// The reserved "leave unchanged" sentinel is refused by EXACT VALUE
			// equality (the OpenAPI SecretUpdate schema rejects it with
			// `not: {const: ...}`), never by a substring/pattern match: mask-like
			// and other non-exact strings stay legitimate values. This guards the
			// VALUE, complementing the FIELD/purpose guard below.
			if su.Value == ReservedSecretSentinelValue {
				return NodeOutcome{}, fmt.Errorf("%w: reserved sentinel value", ErrSecretOp)
			}
			if !utf8.ValidString(su.Value) {
				return NodeOutcome{}, fmt.Errorf("%w: value is not valid UTF-8", ErrSecretOp)
			}
			n := utf8.RuneCountInString(su.Value)
			if n < 1 || n > 4096 {
				return NodeOutcome{}, fmt.Errorf("%w: value length out of range", ErrSecretOp)
			}
			// The reserved preservation sentinel purpose is not a declared secret
			// field, so membership gating already excludes it; this guards the
			// explicit sentinel spelling for defense in depth.
			if su.Field == SentinelPurpose {
				return NodeOutcome{}, fmt.Errorf("%w: reserved sentinel", ErrSecretOp)
			}
			resolved = append(resolved, resolvedOp{field: su.Field, value: su.Value, seal: true})
		default:
			return NodeOutcome{}, fmt.Errorf("%w: unknown op", ErrSecretOp)
		}
	}

	// Begin ONE transaction for the whole create.
	tx, err := w.store.db.BeginTx(ctx, nil)
	if err != nil {
		return NodeOutcome{}, err
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	nodeID := newID()
	digest := auth.Digest()

	// Seal the single original-components preservation container: the exact
	// captured protocol/fields (+ optional label) JSON components. Typed secret
	// replacement values are NEVER copied into preservation — they are sealed
	// separately, exactly once. The internally reserved preservation purpose
	// is not a profile field, so a caller cannot claim it.
	presRef := NewSecretRef()
	presPurpose := nodeID + ":" + SentinelPurpose
	presPlain := buildPreservationPlain(protocolBytes, fieldsBytes, labelBytes)
	if err := sealSecretTX(ctx, tx, w.ss.keys, presRef, presPurpose, presPlain); err != nil {
		return NodeOutcome{}, err
	}

	// Seal actual replace secret values; register owner/link rows; record refs
	// for the accepted node_secret_refs links.
	fieldRef := map[string]domain.SecretRef{}
	for _, op := range resolved {
		ref := NewSecretRef()
		purpose := nodeFieldPurpose(nodeID, op.field)
		if err := sealSecretTX(ctx, tx, w.ss.keys, ref, purpose, []byte(op.value)); err != nil {
			return NodeOutcome{}, err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node_secret_fields (node_id, field, ref, purpose) VALUES (?, ?, ?, ?)`,
			nodeID, op.field, string(ref), purpose); err != nil {
			return NodeOutcome{}, err
		}
		fieldRef[op.field] = ref
	}

	// Derive trusted CURRENT presence in the SAME transaction: every declared
	// secret field, present iff its exact owner+purpose sealed VALUE row exists
	// (never a placeholder or a client boolean). This covers declared secret
	// fields with no supplied plaintext field too.
	presence := map[string]bool{}
	for name := range declaredSecrets {
		p, err := hasSealedValueTX(ctx, tx, fieldRef[name], nodeFieldPurpose(nodeID, name))
		if err != nil {
			return NodeOutcome{}, err
		}
		presence[name] = p
	}

	// Run the ACTUAL validator over the original components (byte-assembled
	// {protocol, fields} only — NOT the original HTTP outer body), with no
	// inventory. No-ops (unchanged/clear on CREATE) contribute no plaintext, so
	// they never promote presence.
	envBytes := buildValidationEnvelope(protocolBytes, fieldsBytes)
	ar, err := nodes.ValidateDocument(prof, envBytes, presence)
	if err != nil && !errors.Is(err, nodes.ErrNotANodeEnvelope) {
		// domain.ErrMalformedJSON (and any other non-envelope adapter error) is a
		// syntax / nonwrite refusal: zero writes, the transaction rolls back.
		return NodeOutcome{}, err
	}
	// A syntactically-valid but non-canonical envelope (inner duplicate keys,
	// ambiguous buckets) is a SEMANTIC refusal, not a syntax error: the adapter
	// already produced its faithful Invalid / notApplicable AdapterResult with
	// the exact original bytes preserved. The draft is SAVEABLE — it persists as
	// an Invalid draft (exact bytes sealed; ambiguous derived maps stay empty so
	// nothing is laundered). errors.Is(err, nodes.ErrNotANodeEnvelope) is the
	// ONLY accepted adapter error here; nothing is revalidated, normalized, or
	// invented.

	// Generate derived safe content ONLY from unambiguous canonical decoded
	// buckets after actual validation (UseNumber, not float64). Unknown
	// protocol / malformed / duplicate / colliding envelopes produce empty
	// derived content rather than laundering ambiguity, but their exact
	// original bytes stay encrypted in the preservation container.
	derivedDoc := buildDerivedDoc(ar, prof, presence)

	// Persist the node row (ONE derived safe document in nodes.doc) + metadata
	// + closed validation snapshot + owner/link rows.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO nodes (id, revision, doc) VALUES (?, 1, ?)`, nodeID, derivedDoc); err != nil {
		return NodeOutcome{}, guardTranslate(err, true, true)
	}
	resultJSON, err := nodes.MarshalResultJSON(ar.Result)
	if err != nil {
		return NodeOutcome{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO node_validation (node_id, node_revision, authority_digest, result) VALUES (?, 1, ?, ?)`,
		nodeID, digest[:], string(resultJSON)); err != nil {
		return NodeOutcome{}, guardTranslate(err, true, false)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO node_preservation (node_id, ref, purpose) VALUES (?, ?, ?)`,
		nodeID, string(presRef), presPurpose); err != nil {
		return NodeOutcome{}, guardTranslate(err, true, false)
	}

	// Preservation ownership/link metadata is written for ALL new owned refs in
	// the same transaction (existing node_secret_refs semantics retained).
	ownedRefs := []domain.SecretRef{presRef}
	for _, op := range resolved {
		ownedRefs = append(ownedRefs, fieldRef[op.field])
	}
	for _, ref := range ownedRefs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node_secret_refs (node_id, secret_ref) VALUES (?, ?)`, nodeID, string(ref)); err != nil {
			return NodeOutcome{}, guardTranslate(err, true, false)
		}
	}

	// Test-only accepted hook: run AFTER all sealing/writes, BEFORE
	// publication/commit, to prove no partial publication on failure/cancel.
	if w.store.hook != nil {
		if err := w.store.hook(); err != nil {
			return NodeOutcome{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return NodeOutcome{}, err
	}
	committed = true

	// Re-apply the CURRENT authority's closed projection to the persisted safe
	// subset so the returned projection is a same-read-snapshot fact. For a
	// known protocol this is the actual projection; for an unknown protocol it
	// is an EMPTY projection (the raw protocol is never echoed).
	projection, err := safeProjection(prof, derivedDoc, presence)
	if err != nil {
		return NodeOutcome{}, err
	}
	// The creation outcome reports the INPUT protocol string (a plain decode
	// of the explicit scalar component the writer already gated); the READ
	// path derives it from the persisted derived document instead.
	outProtocol := string(protocolLiteral(protocolBytes))
	return NodeOutcome{
		NodeID:         nodeID,
		Revision:       1,
		Protocol:       outProtocol,
		Validation:     ar.Result,
		SecretPresence: copyBoolMap(presence),
		Projection:     projection,
	}, nil
}

// errNodeComponent returns a static, value-free refusal for an invalid typed
// outer component (protocol/fields/label shape).
// ErrNodeComponent is the ONE exported static sentinel for a malformed TYPED
// node component (a non-string protocol, a non-object fields envelope, a
// non-string/overlong label). It wraps the same fixed, component-name-only
// static error the store has always returned — no driver text, no input
// bytes, no value — so the trusted HTTP composition classifies a typed refusal
// with errors.Is INSTEAD of any string matching. Every other store failure
// keeps its own category and maps to a static 500 upstream.
var ErrNodeComponent = errors.New("store: node typed component refusal")

func errNodeComponent(which string) error {
	return fmt.Errorf("store: invalid node %s component: %w", which, ErrNodeComponent)
}

// buildPreservationPlain assembles the single original-components container:
// exact captured protocol/fields (+ optional label) JSON bytes. No typed secret
// replacement value is ever included. Absence versus explicit null stays
// distinguishable because the exact bytes are preserved.
func buildPreservationPlain(protocolBytes, fieldsBytes, labelBytes []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"protocol":`)
	buf.Write(protocolBytes)
	buf.WriteString(`,"fields":`)
	buf.Write(fieldsBytes)
	if labelBytes != nil {
		buf.WriteString(`,"label":`)
		buf.Write(labelBytes)
	}
	buf.WriteString(`}`)
	return buf.Bytes()
}

// buildValidationEnvelope byte-assembles ONLY {protocol, fields} for the
// validator — it is NOT the original HTTP outer body.
func buildValidationEnvelope(protocolBytes, fieldsBytes []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"protocol":`)
	buf.Write(protocolBytes)
	buf.WriteString(`,"fields":`)
	buf.Write(fieldsBytes)
	buf.WriteString(`}`)
	return buf.Bytes()
}

// declaredSecretFields returns the set of declared secret field names for a
// known protocol (the authority's exact membership, used for typed-op gating
// and presence coverage).
func declaredSecretFields(prof *capability.Profile, protocol string) map[string]bool {
	out := map[string]bool{}
	for _, name := range secretFields(prof, protocol) {
		out[name] = true
	}
	return out
}

// --- read -------------------------------------------------------------------

func (r *NodeReader) readNodeSafe(ctx context.Context, id string) (NodeOutcome, error) {
	auth := r.authority
	prof := auth.Profile()

	tx, err := r.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return NodeOutcome{}, err
	}
	defer tx.Rollback()

	// Node revision + derived safe document.
	var (
		revision int64
		docStr   string
	)
	err = tx.QueryRowContext(ctx, `SELECT revision, doc FROM nodes WHERE id = ?`, id).Scan(&revision, &docStr)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeOutcome{}, domain.ErrNotFound
	}
	if err != nil {
		return NodeOutcome{}, err
	}

	// Closed validation snapshot; revision must still match.
	var (
		nodeRevision int64
		digest       []byte
		resultJSON   string
	)
	err = tx.QueryRowContext(ctx,
		`SELECT node_revision, authority_digest, result FROM node_validation WHERE node_id = ?`, id).
		Scan(&nodeRevision, &digest, &resultJSON)
	if errors.Is(err, sql.ErrNoRows) {
		// A legacy (nonmanaged) node is never implicitly adopted or revalidated.
		return NodeOutcome{}, fmt.Errorf("%w: unmanaged node", ErrSafeRead)
	}
	if err != nil {
		return NodeOutcome{}, err
	}
	if nodeRevision != revision {
		return NodeOutcome{}, fmt.Errorf("%w: revision drift", ErrSafeRead)
	}
	authDigest := auth.Digest()
	if len(digest) != 32 || !bytes.Equal(digest, authDigest[:]) {
		return NodeOutcome{}, fmt.Errorf("%w: authority mismatch", ErrSafeRead)
	}
	res, err := nodes.DecodeResultStrict([]byte(resultJSON), prof)
	if err != nil {
		return NodeOutcome{}, fmt.Errorf("%w: %v", ErrSafeRead, err)
	}

	// Preservation ownership/link metadata must be structurally complete, but
	// the ciphertext/blob is NEVER selected.
	var presRef, presPurpose string
	err = tx.QueryRowContext(ctx, `SELECT ref, purpose FROM node_preservation WHERE node_id = ?`, id).
		Scan(&presRef, &presPurpose)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeOutcome{}, fmt.Errorf("%w: missing preservation binding", ErrSafeRead)
	}
	if err != nil {
		return NodeOutcome{}, err
	}
	if presRef == "" || presPurpose != id+":"+SentinelPurpose {
		return NodeOutcome{}, fmt.Errorf("%w: malformed preservation binding", ErrSafeRead)
	}

	// Decode the derived safe document (closed, versioned shape) and re-apply
	// the current authority's projection to the persisted safe subset.
	derived, protocol, err := decodeDerivedDoc([]byte(docStr))
	if err != nil {
		return NodeOutcome{}, fmt.Errorf("%w: %v", ErrSafeRead, err)
	}
	// The reader now holds the node protocol (from the closed derived document,
	// digest-bound to the same authority): enforce that persisted secret names
	// belong to THIS protocol, refusing a wrong-protocol secret claim.
	if err := nodes.EnforceSecretProtocol(prof, protocol, res.Secrets); err != nil {
		return NodeOutcome{}, fmt.Errorf("%w: %v", ErrSafeRead, err)
	}

	// CURRENT presence from owner + link + sealed row EXISTENCE (SELECT 1 /
	// EXISTS only — never the blob, never SecretStore.Open). A missing
	// field-owner row means an ABSENT field secret; a present owner with a
	// missing link or sealed row makes CURRENT presence false, without changing
	// the historical verdict.
	presence := map[string]bool{}
	for _, name := range secretFields(prof, protocol) {
		var ref, purpose string
		ferr := tx.QueryRowContext(ctx,
			`SELECT ref, purpose FROM node_secret_fields WHERE node_id = ? AND field = ?`, id, name).
			Scan(&ref, &purpose)
		if errors.Is(ferr, sql.ErrNoRows) {
			presence[name] = false
			continue
		}
		if ferr != nil {
			return NodeOutcome{}, ferr
		}
		if ref == "" || purpose == "" || purpose != nodeFieldPurpose(id, name) {
			return NodeOutcome{}, fmt.Errorf("%w: malformed secret binding", ErrSafeRead)
		}
		var linkOne int
		lerr := tx.QueryRowContext(ctx,
			`SELECT 1 FROM node_secret_refs WHERE node_id = ? AND secret_ref = ?`, id, ref).Scan(&linkOne)
		if lerr != nil && !errors.Is(lerr, sql.ErrNoRows) {
			return NodeOutcome{}, lerr
		}
		sealed, serr := hasSealedValueTX(ctx, tx, domain.SecretRef(ref), purpose)
		if serr != nil {
			return NodeOutcome{}, serr
		}
		presence[name] = errors.Is(lerr, sql.ErrNoRows) == false && sealed
	}

	projection, err := safeProjectionDecoded(prof, derived, protocol, presence)
	if err != nil {
		return NodeOutcome{}, err
	}
	return NodeOutcome{
		NodeID:         id,
		Revision:       revision,
		Protocol:       protocol,
		Validation:     res,
		SecretPresence: copyBoolMap(presence),
		Projection:     projection,
	}, nil
}

// safeProjection decodes the derived document and re-applies the current
// authority's closed projection to the persisted safe subset. An unknown
// protocol yields an EMPTY projection (never a projector error that loses a
// saved draft, and never a raw protocol echo); a known protocol reuses actual
// ProjectNodeFields with the derived active/inactive maps and current presence.
func safeProjection(prof *capability.Profile, docStr string, presence map[string]bool) (capability.ProjectedNode, error) {
	derived, protocol, err := decodeDerivedDoc([]byte(docStr))
	if err != nil {
		return capability.ProjectedNode{}, err
	}
	return safeProjectionDecoded(prof, derived, protocol, presence)
}

// safeProjectionDecoded is the projection core over an already-decoded derived
// document, shared by the writer's post-commit projection and the reader's
// cold safe read.
func safeProjectionDecoded(prof *capability.Profile, derived derivedDoc, protocol string, presence map[string]bool) (capability.ProjectedNode, error) {
	empty := capability.ProjectedNode{
		Active:   map[string]any{},
		Inactive: map[string]any{},
		Secrets:  map[string]bool{},
	}
	if !prof.HasProtocol(protocol) {
		return empty, nil
	}
	// Feed the projector the non-mutating union of active + inactive values with
	// the allowlisted inactive-set, so readable inactive members are placed in
	// Projection.Inactive (never promoted into Active, never dropped) while
	// secret/nested/unknown/quarantined inactive values NEVER leak. The derived
	// maps are treated as read-only and copied out by the projector.
	allow := map[string]bool{}
	for _, n := range prof.InactiveNames(protocol) {
		allow[n] = true
	}
	merged := make(map[string]any, len(derived.active)+len(derived.inactive))
	inactive := map[string]bool{}
	for k, v := range derived.active {
		merged[k] = v
	}
	for k, v := range derived.inactive {
		if !allow[k] {
			continue // not allowlisted to surface: secret/nested/unknown value stays sealed
		}
		merged[k] = v
		inactive[k] = true
	}
	proj, err := prof.ProjectNodeFields(protocol, merged, presence, inactive)
	if err != nil {
		return capability.ProjectedNode{}, err
	}
	// Projection.Secrets must agree with current presence for every declared
	// secret field, not just fields that happened to be in the submitted maps.
	if proj.Secrets == nil {
		proj.Secrets = map[string]bool{}
	}
	for _, name := range secretFields(prof, protocol) {
		proj.Secrets[name] = presence[name]
	}
	if proj.Active == nil {
		proj.Active = map[string]any{}
	}
	if proj.Inactive == nil {
		proj.Inactive = map[string]any{}
	}
	return proj, nil
}

// derivedDoc is the decoded, versioned safe internal document shape stored in
// nodes.doc: protocol-if-known plus the allowlisted active/inactive scalar
// maps. No raw unknown names, objects, secret values, original protocol or
// label strings appear outside the ciphertext.
type derivedDoc struct {
	protocol string
	active   map[string]any
	inactive map[string]any
}

// decodeDerivedDoc decodes the closed derived document with strict
// full-consumption and an exact key set {version, protocol, active, inactive}.
// Version must equal 1. Returns the protocol string (empty when the protocol
// was unknown at create time).
func decodeDerivedDoc(raw []byte) (derivedDoc, string, error) {
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return derivedDoc{}, "", errMalformedDerived()
	}
	if dec.More() {
		return derivedDoc{}, "", errMalformedDerived()
	}
	if len(top) != 4 {
		return derivedDoc{}, "", errMalformedDerived()
	}
	var version int64
	if err := json.Unmarshal(top["version"], &version); err != nil || version != 1 {
		return derivedDoc{}, "", errMalformedDerived()
	}
	var protocol string
	if err := json.Unmarshal(top["protocol"], &protocol); err != nil {
		return derivedDoc{}, "", errMalformedDerived()
	}
	active, err := decodeObjectMap(top["active"])
	if err != nil {
		return derivedDoc{}, "", err
	}
	inactive, err := decodeObjectMap(top["inactive"])
	if err != nil {
		return derivedDoc{}, "", err
	}
	return derivedDoc{protocol: protocol, active: active, inactive: inactive}, protocol, nil
}

// buildDerivedDoc derives the safe document for nodes.doc: ONLY the actual
// allowlisted safe known values (or fixed value-free metadata) ever persist in
// plaintext. It reuses the SAME closed authority projection the public read
// path applies (ProjectNodeFields) over the canonical decoded active/inactive
// buckets — unknown names, smuggled plaintext secret fields, and opaque-object
// private leaves are NEVER copied (secrets are presence-only, objects render
// name-only Unsupported, out-of-bounds values are withheld). The projector is
// fed the non-mutating union of active + inactive values with the allowlisted
// inactive-set, so readable inactive members land in Inactive (never promoted
// to Active, never dropped).
//
// The derived document stays the exact version-1 shape {version, protocol,
// active, inactive}. The protocol is derived ONLY from the independently
// decoded envelope when the authority actually declares it (prof.HasProtocol);
// otherwise it stays empty (the raw protocol never persists outside the
// ciphertext). An accepted envelope that fails the clean decode (unknown
// protocol / malformed / duplicate / colliding) yields EMPTY maps so ambiguity
// is never laundered into safe content, while its exact original bytes stay
// sealed in the preservation container.
func buildDerivedDoc(ar nodes.AdapterResult, prof *capability.Profile, presence map[string]bool) string {
	protocol := ""
	active := map[string]any{}
	inactive := map[string]any{}
	if ar.Validation == domain.ValidationValid || ar.Validation == domain.ValidationInvalid {
		if p, ok := decodeProtocolString(ar.Document.Raw); ok && prof.HasProtocol(p) {
			protocol = p
			decActive, decInactive, decUnknown, ok := canonicalDerivedBuckets(ar.Document.Raw)
			if ok {
				// Cross-bucket collision: a name present in MORE THAN ONE of the
				// active/inactive/unknown buckets is ambiguous — its value must
				// NEVER be laundered into derived plaintext. Every colliding name
				// is excluded from BOTH derived maps; UNRELATED safe known fields
				// are preserved.
				seen := map[string]int{}
				for name := range decActive {
					seen[name]++
				}
				for name := range decInactive {
					seen[name]++
				}
				for name := range decUnknown {
					seen[name]++
				}
				collide := map[string]bool{}
				for name, n := range seen {
					if n > 1 {
						collide[name] = true
					}
				}
				// Non-mutating union of the UNAMBIGUOUS active/inactive values, keyed
				// by bucket so placement is authority-driven (never promoted across
				// buckets).
				union := make(map[string]any, len(decActive)+len(decInactive))
				for name, val := range decActive {
					if collide[name] {
						continue
					}
					union[name] = val
				}
				inactiveSet := make(map[string]bool, len(decInactive))
				for name, val := range decInactive {
					if collide[name] {
						continue
					}
					union[name] = val
					inactiveSet[name] = true
				}
				proj, err := prof.ProjectNodeFields(protocol, union, presence, inactiveSet)
				if err == nil {
					active, inactive = proj.Active, proj.Inactive
					// An EXISTING ACTIVE known object renders as a FIXED name-only marker
					// ({}), never its private leaves and never promoted from inactive.
					// The marker keeps the historical fact that the object was present
					// without persisting any nested content in plaintext.
					for _, name := range proj.Unsupported {
						if _, wasActive := decActive[name]; wasActive && !collide[name] {
							active[name] = map[string]any{}
						}
					}
				}
				// On any projection refusal the safe derived maps stay empty: nothing
				// unsafe is ever persisted in plaintext.
			}
			// ok == false (duplicate canonical keys / ambiguous): derived maps stay
			// EMPTY so last-key-wins never launders ambiguity into safe content.
		}
	}
	doc := struct {
		Version  int            `json:"version"`
		Protocol string         `json:"protocol"`
		Active   map[string]any `json:"active"`
		Inactive map[string]any `json:"inactive"`
	}{Version: 1, Protocol: protocol, Active: active, Inactive: inactive}
	b, err := json.Marshal(doc)
	if err != nil {
		// json.Marshal on plain scalar maps cannot fail; guard anyway.
		return `{"version":1,"protocol":"","active":{},"inactive":{}}`
	}
	return string(b)
}

// validJSONStringContent reports whether s — the QUOTED-STripped inner content
// of a JSON string — is well-formed string content on the wire bytes. It is
// the store-private scalar-integrity scan scoped ONLY to the typed label
// component; it does NOT expand the dependency-neutral jsonscan package or
// affect any other path.
//
// It enforces:
//   - every `\` introduces a RECOGNIZED two-char escape (" \ / b f n r t) or a
//     well-formed \uXXXX escape (exactly four hex digits);
//   - every UTF-16 surrogate escape is PART of a valid high+low PAIR (an
//     unpaired or wrongly-ordered surrogate encodes an invalid scalar, which
//     the Go decoder would otherwise lossily map to U+FFFD and silently
//     accept as valid);
//   - no raw control byte (0x00..0x1F) appears unescaped.
//
// A legal literal/escaped U+FFFD (\ufffd), an ordinary \ud83d\ude00 pair,
// the escaped-backslash form \\ud800 (backslash + "uD800", NOT a surrogate
// escape), and ordinary BMP content are all valid and accepted.
func validJSONStringContent(s string) bool {
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		if c < 0x20 {
			return false // raw control byte must be escaped
		}
		if c == '\\' {
			i++
			if i >= n {
				return false // trailing backslash
			}
			e := s[i]
			switch e {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i++
			case 'u':
				if i+5 > n {
					return false // \\u needs exactly 4 hex digits after 'u'
				}
				v, hok := hexQuad(s[i+1 : i+5]) // s[i]=='u'; its 4 digits are s[i+1..i+4]
				if !hok {
					return false
				}
				if v >= 0xD800 && v <= 0xDBFF { // high surrogate: needs a low half
					// A following low escape \\uXXXX occupies s[i+5..i+10]; the last
					// index consumed is i+10, which must be within s (i+10 <= n-1).
					if i+10 >= n || s[i+5] != '\\' || s[i+6] != 'u' {
						return false // unpaired high surrogate
					}
					lv, lok := hexQuad(s[i+7 : i+11]) // low digits s[i+7..i+10]
					if !lok || lv < 0xDC00 || lv > 0xDFFF {
						return false // high not followed by a low surrogate
					}
					i += 10 // consume both \\uXXXX escapes (i was at 'u' of high)
					continue
				}
				if v >= 0xDC00 && v <= 0xDFFF {
					return false // low surrogate without a preceding high
				}
				i += 5 // consume \\uXXXX (i was at 'u'; +1 backslash +4 digits)
			default:
				return false // unrecognized escape
			}
			continue
		}
		i++
	}
	return true
}

// hexQuad parses exactly four hex digits into a value; hok=false on a non-hex
// digit. Each digit is folded into the low nibble of v (shift-then-or), so all
// four nibbles are preserved.
func hexQuad(q string) (v int, hok bool) {
	if len(q) != 4 {
		return 0, false
	}
	for i := 0; i < 4; i++ {
		d := q[i]
		var nib int
		switch {
		case d >= '0' && d <= '9':
			nib = int(d - '0')
		case d >= 'a' && d <= 'f':
			nib = int(d-'a') + 10
		case d >= 'A' && d <= 'F':
			nib = int(d-'A') + 10
		default:
			return 0, false
		}
		v = v<<4 | nib
	}
	return v, true
}

// stringScalarJSON reports whether a raw JSON string token (quoted) is
// scalar: valid UTF-8, well-formed escapes, no unpaired surrogate. It is the
// store-private wrapper around the jsonscan raw-string scalar capability,
// scoped to the protocol token. Returns false for non-string/non-quoted input.
func stringScalarJSON(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	if len(t) < 2 || t[0] != '"' || t[len(t)-1] != '"' {
		return false
	}
	return jsonscan.StringScalar(t) == nil
}

// decodeProtocolString extracts the protocol string from a canonical envelope
// when it is exactly present; returns ok=false otherwise (never an echo).
// protocolLiteral decodes the writer-gated protocol component (exactly one
// JSON string scalar, already validated upstream) into its string value.
// It never revalidates: an undecodable input yields the empty string.
func protocolLiteral(raw []byte) string {
	var p string
	if err := json.Unmarshal(raw, &p); err != nil {
		return ""
	}
	return p
}

func decodeProtocolString(raw []byte) (string, bool) {
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return "", false
	}
	pRaw, ok := top["protocol"]
	if !ok {
		return "", false
	}
	// The protocol is retained ONLY when its own raw token is scalar (valid
	// UTF-8, well-formed escapes, no unpaired surrogate): the protocol is
	// trusted metadata, and a non-scalar protocol must never be retained — but
	// a KNOWN protocol on an envelope whose FIELDS carry a non-scalar
	// value/key elsewhere is independently scalar-safe, so it stays.
	if !stringScalarJSON(pRaw) {
		return "", false
	}
	var p string
	if err := json.Unmarshal(pRaw, &p); err != nil || p == "" {
		return "", false
	}
	return p, true
}

// canonicalDerivedBuckets decodes the canonical active/inactive/unknown field
// maps for a known-protocol accepted envelope. It returns ok=false (so the
// caller persists EMPTY derived maps) whenever the fields envelope is not
// cleanly, unambiguously decodable: a duplicate canonical key at the fields
// level or inside the active/inactive/unknown objects (last-key-wins would
// launder ambiguity), a wrong bucket count, or a non-object bucket. The
// exact original bytes stay sealed in the preservation container either way.
func canonicalDerivedBuckets(raw []byte) (active, inactive, unknown map[string]any, ok bool) {
	empty := map[string]any{}
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return empty, empty, empty, false
	}
	fRaw, has := top["fields"]
	if !has {
		return empty, empty, empty, false
	}
	// A non-scalar string/key anywhere in the fields (invalid raw UTF-8, an
	// unpaired / wrongly-ordered surrogate escape, an ill-formed \uXXXX, or a
	// raw control byte) is a NON-CANONONICAL SEMANTIC envelope: the derived maps
	// must stay EMPTY so the lossy (U+FFFD) value is never laundered into safe
	// plaintext. The exact original bytes stay sealed.
	if err := jsonscan.StringScalar(fRaw); err != nil {
		return empty, empty, empty, false
	}
	// A duplicate canonical key at the FIELDS level (e.g. two "active"
	// buckets) is non-canonical: last-key-wins would launder ambiguity, so the
	// whole decode is rejected and the caller persists empty derived maps.
	if err := jsonscan.FullValue(fRaw); err != nil {
		return empty, empty, empty, false
	}
	var fields map[string]json.RawMessage
	fdec := json.NewDecoder(bytes.NewReader(fRaw))
	if err := fdec.Decode(&fields); err != nil || fields == nil {
		return empty, empty, empty, false
	}
	if fdec.More() {
		return empty, empty, empty, false // trailing content inside fields
	}
	if len(fields) != 3 {
		return empty, empty, empty, false
	}
	a, aok := decodeObjectLoose(fields["active"])
	i, iok := decodeObjectLoose(fields["inactive"])
	u, uok := decodeObjectLoose(fields["unknown"])
	if !aok || !iok || !uok {
		return empty, empty, empty, false
	}
	return a, i, u, true
}

// decodeObjectLoose decodes a JSON object member into a map (UseNumber);
// returns ok=false for absent/null/non-object members.
// decodeObjectLoose decodes a JSON object member into a map (UseNumber). It
// returns ok=false for absent/null/non-object members AND for an object that
// carries a DUPLICATE key anywhere inside it (a duplicate means last-key-wins
// would launder ambiguity, so the whole decode is rejected and the caller
// persists empty derived maps instead).
func decodeObjectLoose(raw json.RawMessage) (map[string]any, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	if err := jsonscan.FullValue(raw); err != nil {
		return nil, false // duplicate key (or unscalable content): never laundered
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	m := map[string]any{}
	if err := dec.Decode(&m); err != nil {
		return nil, false
	}
	if m == nil {
		return nil, false
	}
	return m, true
}

func decodeObjectMap(raw json.RawMessage) (map[string]any, error) {
	m, ok := decodeObjectLoose(raw)
	if !ok {
		return nil, errMalformedDerived()
	}
	return m, nil
}

func errMalformedDerived() error {
	return errors.New("store: malformed derived node document")
}

func copyBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
