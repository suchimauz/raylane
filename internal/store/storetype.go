package store

// Store type and helpers shared by the operation files. The struct itself is
// declared in sqlite.go; this file carries the entity vocabulary.

import "github.com/suchimauz/raylane/internal/domain"

// Node is a managed node entity. Active membership is NOT a field here: it is
// decided by inclusion in the active revision snapshot (data-model rule), so
// this record only carries identity, its optimistic revision and the document.
type Node struct {
	// ID is the local identity (UUID assigned by CreateNode).
	ID string
	// Revision is the per-entity optimistic counter starting at 1.
	Revision int64
	// Doc is the entity document as stored (validated JSON text).
	Doc domain.Document
}

// Source is a subscription or ruleset source. Settings revision (Revision)
// guards admin edits and refresh requests; DraftVersion and ActiveVersion are
// content versions of the loaded set — a third, distinct counter family
// (data-model RuleSetSource row).
type Source struct {
	// ID is the local identity.
	ID string
	// Kind is "subscription" or "ruleset".
	Kind string
	// Revision is the settings revision (optimistic guard target).
	Revision int64
	// DraftVersion is the content version of the loaded-but-not-promoted set.
	DraftVersion int64
	// ActiveVersion is the content version currently in use by the source.
	ActiveVersion int64
	// Doc holds settings as stored (SecretRef values only, validated JSON).
	Doc domain.Document
}

// NewID returns a random UUIDv4 string (local identity per the data model).
func NewID() string { return newID() }
