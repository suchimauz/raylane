package store

// Entity operations: optimistic-revision guards, transactional uniqueness and
// dependency protection for nodes and sources (FR-010). All writes run in a
// single transaction; a rejection changes nothing at all.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/suchimauz/raylane/internal/domain"
)

// guardTranslate maps driver constraint failures onto the domain error types
// so callers never see raw SQLite text (and no value echoes leak). SQLite
// constraint violations arrive as modernc errors whose text must not be
// forwarded verbatim; every classified failure gets a typed domain error with
// a static message only.
func guardTranslate(err error, foreignKey, unique bool) error {
	if err == nil {
		return nil
	}
	msg := err.Error() // examined locally, never returned
	switch {
	case foreignKey && (containsAny(msg, "FOREIGN KEY", "foreign key") || msg == ""):
		// A deferred foreign key violation surfaced at COMMIT can carry an
		// empty driver message; classify it structurally, never pass it on.
		return fmt.Errorf("%w: reference violation", domain.ErrDependency)
	case unique && containsAny(msg, "UNIQUE", "unique"):
		return fmt.Errorf("%w: duplicate key", domain.ErrConflict)
	case containsAny(msg, "CHECK", "check"):
		return fmt.Errorf("%w: constraint violation", domain.ErrConflict)
	default:
		return err
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			continue
		}
		return true
	}
	return false
}

// CreateNode inserts a node with revision 1. Create carries no optimistic
// guard (no prior state to protect); protection is absence-of-target plus
// transactional key uniqueness: an existing id returns domain.ErrConflict and
// never overwrites (control-plane contract, Create row).
func (s *Store) CreateNode(ctx context.Context, id string, raw []byte) (Node, error) {
	doc, err := domain.ParseDocument(raw)
	if err != nil {
		return Node{}, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO nodes (id, revision, doc) VALUES (?,1,?)`, id, string(doc.Raw))
	if err != nil {
		return Node{}, guardTranslate(err, true, true)
	}
	if _, err := res.RowsAffected(); err != nil {
		return Node{}, err
	}
	return Node{ID: id, Revision: 1, Doc: doc}, nil
}

// GetNode loads one node entity.
func (s *Store) GetNode(ctx context.Context, id string) (Node, error) {
	var (
		n   Node
		doc string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, revision, doc FROM nodes WHERE id = ?`, id).Scan(&n.ID, &n.Revision, &doc)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, domain.ErrNotFound
	}
	if err != nil {
		return Node{}, err
	}
	n.Doc.Raw = []byte(doc)
	return n, nil
}

// UpdateNode replaces a node document under an optimistic guard: the caller's
// expectedRevision must match the stored one or nothing changes and
// domain.ErrStaleRevision is returned (409 class).
func (s *Store) UpdateNode(ctx context.Context, id string, expectedRevision int64, raw []byte) (Node, error) {
	doc, err := domain.ParseDocument(raw)
	if err != nil {
		return Node{}, err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE nodes SET doc = ?, revision = revision + 1 WHERE id = ? AND revision = ?`,
		string(doc.Raw), id, expectedRevision)
	if err != nil {
		return Node{}, guardTranslate(err, true, true)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Node{}, err
	}
	if n == 0 {
		if _, err := s.GetNode(ctx, id); err != nil {
			return Node{}, err
		}
		return Node{}, domain.ErrStaleRevision
	}
	return s.GetNode(ctx, id)
}

// DeleteNode removes an entity under the same optimistic guard. Deletion is
// rejected while any persisted revision references the node — via the active
// snapshot membership rows or via saved node SecretRef links: the FK makes the
// DELETE fail, the transaction rolls back completely and the caller receives
// domain.ErrDependency (FR-010).
func (s *Store) DeleteNode(ctx context.Context, id string, expectedRevision int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`DELETE FROM nodes WHERE id = ? AND revision = ?`, id, expectedRevision)
	if err != nil {
		return guardTranslate(err, true, false)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		if _, err := s.GetNode(ctx, id); err != nil {
			return err
		}
		return domain.ErrStaleRevision
	}
	// The deferred FKs are checked at COMMIT: while any revision membership or
	// node SecretRef row references this node, the commit fails as a foreign
	// key violation — the whole transaction rolls back (deferred rollback
	// triggers cancel the commit) and nothing changes (FR-010).
	if err := tx.Commit(); err != nil {
		return guardTranslate(err, true, false)
	}
	return nil
}

// CreateSource inserts a subscription/ruleset source at settings revision 1
// with zero content versions.
func (s *Store) CreateSource(ctx context.Context, id, kind string, raw []byte) (Source, error) {
	if kind != "subscription" && kind != "ruleset" {
		return Source{}, fmt.Errorf("%w: unknown source kind", domain.ErrConflict)
	}
	doc, err := domain.ParseDocument(raw)
	if err != nil {
		return Source{}, err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO sources (id, kind, revision, draft_version, active_version, doc) VALUES (?,?,1,0,0,?)`,
		id, kind, string(doc.Raw)); err != nil {
		return Source{}, guardTranslate(err, true, true)
	}
	return Source{ID: id, Kind: kind, Revision: 1, Doc: doc}, nil
}

// GetSource loads one source with its distinct revision/version counters.
func (s *Store) GetSource(ctx context.Context, id string) (Source, error) {
	var (
		src Source
		doc string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, kind, revision, draft_version, active_version, doc FROM sources WHERE id = ?`, id).
		Scan(&src.ID, &src.Kind, &src.Revision, &src.DraftVersion, &src.ActiveVersion, &doc)
	if errors.Is(err, sql.ErrNoRows) {
		return Source{}, domain.ErrNotFound
	}
	if err != nil {
		return Source{}, err
	}
	src.Doc.Raw = []byte(doc)
	return src, nil
}

// UpdateSettingsTx changes source settings under the client optimistic guard
// (expectedRevision, always the settings revision — never a content version).
// On success settings revision increments; content versions do not move.
func (s *Store) UpdateSettingsTx(ctx context.Context, id string, expectedRevision int64, raw []byte) (Source, error) {
	doc, err := domain.ParseDocument(raw)
	if err != nil {
		return Source{}, err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE sources SET doc = ?, revision = revision + 1 WHERE id = ? AND revision = ?`,
		string(doc.Raw), id, expectedRevision)
	if err != nil {
		return Source{}, guardTranslate(err, true, false)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Source{}, err
	}
	if n == 0 {
		if _, err := s.GetSource(ctx, id); err != nil {
			return Source{}, err
		}
		return Source{}, domain.ErrStaleRevision
	}
	return s.GetSource(ctx, id)
}
