// Package domain holds the control-plane configuration vocabulary: immutable
// revision snapshots, honest draft documents, secret references and the typed
// errors the store returns. It has no storage and no transport concerns; the
// store package persists exactly what this package describes.
//
// Normative basis: specs/001-selected-connections/data-model.md (ConfigRevision,
// ActiveState, Secret) and FR-009/FR-010 in spec.md.
package domain

import (
	"bytes"
	"encoding/json"
	"errors"
)

// ValidationStatus is the explicit three-way verdict attached to a stored
// revision, per the accepted contracts (ValidationReport / NOT_RUN semantics):
// absence of performed validation is its own honest state — it is neither an
// implied PASS nor a final FAIL.
type ValidationStatus int

const (
	// ValidationNotRun means validation was never performed. It must never be
	// treated as passing (NOT_RUN is not PASS).
	ValidationNotRun ValidationStatus = iota
	// ValidationValid means validation ran and the document passed.
	ValidationValid
	// ValidationInvalid means validation ran and produced findings; the draft
	// stays saveable but cannot pass apply-time checks (FR-009).
	ValidationInvalid
)

// String renders the status for structured, secret-free diagnostics.
func (v ValidationStatus) String() string {
	switch v {
	case ValidationValid:
		return "valid"
	case ValidationInvalid:
		return "invalid"
	default:
		return "not_run"
	}
}

// Document is a configuration document as saved by the operator.
//
// Raw keeps the exact submitted bytes so the store can persist them verbatim;
// Validation carries the explicit verdict state. A semantically invalid
// document is still a legitimate draft (FR-009): it is stored honestly, marked
// ValidationInvalid, and blocked from apply elsewhere. A document that was
// never validated stays ValidationNotRun — saving never performs validation
// and never upgrades the status. Malformed JSON is not a Document at all —
// ErrMalformedJSON is returned before any save so a broken payload can never
// replace a previously saved state. Nothing here silently corrects values.
type Document struct {
	// Raw is the exact JSON text of the document.
	Raw json.RawMessage
	// Validation is the explicit validation state; the zero value is
	// ValidationNotRun, deliberately not a pass.
	Validation ValidationStatus
	// Findings lists why the document is invalid (or warnings while valid).
	// Each finding is a redacted, structured message without secrets.
	Findings []string
}

// ParseDocument checks JSON syntax only and returns the document with
// ValidationNotRun. It deliberately performs no semantic validation: syntax is
// the hard save gate (FR-009), semantics stay honest draft data, and absence
// of validation stays visible. A syntax failure returns ErrMalformedJSON and
// nothing else.
func ParseDocument(raw []byte) (Document, error) {
	if !json.Valid(bytes.TrimSpace(raw)) {
		return Document{}, ErrMalformedJSON
	}
	return Document{Raw: json.RawMessage(append([]byte(nil), raw...)), Validation: ValidationNotRun}, nil
}

// SecretRef names a stored secret value. Configuration and domain objects
// carry references only; plaintext secret material never enters this package
// or the store schema. Encryption, key handling and redaction are owned by a
// later task (T007), not by T006.
type SecretRef string

// Revision is one immutable configuration snapshot. Once created the record
// is never modified: saving a new state inserts a new Revision and moves the
// draft reference; the active reference moves only under the future apply
// readiness protocol (T016), never as a side effect of saving. History is
// never rewritten or discarded (FR-010, data model ActiveState note).
type Revision struct {
	// ID is the revision identifier (UUID assigned by the store).
	ID string
	// Seq is a store-assigned global monotonically increasing sequence used
	// for ordering; it is distinct from per-entity optimistic revisions.
	Seq int64
	// ParentID is the revision this one was derived from ("" for the first).
	ParentID string
	// Doc is the snapshot content, stored exactly as saved, with its explicit
	// validation state.
	Doc Document
	// SecretRefs lists every secret reference the document depends on.
	SecretRefs []SecretRef
}

// ActiveState is the applied configuration reference plus the runtime
// generation it belongs to. Per the accepted data model it changes only after
// apply readiness; the apply journal and readiness controller are owned by a
// later task (T016), so T006 only persists and preserves this row — saving a
// draft never promotes active. Active membership of entities is defined by the
// active snapshot, not by a mutable entity flag.
type ActiveState struct {
	// RevisionID is the applied revision.
	RevisionID string
	// Generation increments on every successful apply.
	Generation int64
}

// Draft is the current draft head: the last saved revision plus its
// optimistic revision counter used by save guards.
type Draft struct {
	// RevisionID is the current draft revision.
	RevisionID string
	// Revision is the optimistic counter for draft-head operations.
	Revision int64
}

// Errors returned by the store as stable typed conditions. Callers match with
// errors.Is. Messages are safe: they carry identifiers and counters only,
// never configuration bodies, URLs, tokens or secret material.
var (
	// ErrNotFound reports that an entity or revision does not exist.
	ErrNotFound = errors.New("domain: not found")
	// ErrMalformedJSON reports syntactically invalid JSON; such a payload can
	// never replace a previously saved draft.
	ErrMalformedJSON = errors.New("domain: malformed json")
	// ErrInvalidDocument reports semantic invalidity that blocks apply but not
	// save (FR-009).
	ErrInvalidDocument = errors.New("domain: document is semantically invalid")
	// ErrStaleRevision reports that a client-supplied expected revision no
	// longer matches the stored one; the write was rejected and nothing changed.
	ErrStaleRevision = errors.New("domain: stale revision")
	// ErrConflict reports any other transactional conflict (duplicate key,
	// busy source, missing create target).
	ErrConflict = errors.New("domain: conflict")
	// ErrDependency reports that a deletion or change is blocked because the
	// current saved draft or the immutable active snapshot still references
	// the target (FR-010).
	ErrDependency = errors.New("domain: dependency reference exists")
)
