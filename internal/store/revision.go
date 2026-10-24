package store

// Revision and draft/active persistence for the Store. See config.go for the
// Store type itself. This file defines the operations at the storage/envelope
// boundary only: saving a draft never touches active state (apply readiness is
// a later task, T016), and no code here implements the apply protocol.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/suchimauz/raylane/internal/domain"
)

// SaveDraft inserts a new immutable revision as the current draft. It performs
// the JSON syntax gate only: syntactically broken payloads are rejected with
// domain.ErrMalformedJSON and the previously saved draft stays exactly as it
// was (FR-009). Semantically invalid documents are stored honestly, keeping
// whatever explicit ValidationStatus the caller carries — including
// ValidationNotRun, which saving never upgrades to a verdict.
//
// expectedDraftRevision guards the draft head the same way entity revisions
// guard entities (optimistic concurrency): pass Draft.Revision from your last
// read; ErrStaleRevision means someone else saved in the meantime and this
// write changed nothing. Pass Draft.Revision+0 for the very first save as 0.
// Active state is not touched under any circumstance.
func (s *Store) SaveDraft(ctx context.Context, raw []byte, status domain.ValidationStatus, findings []string, refs []domain.SecretRef, expectedDraftRevision int64) (domain.Revision, error) {
	doc, err := domain.ParseDocument(raw)
	if err != nil {
		return domain.Revision{}, err
	}
	doc.Validation = status
	doc.Findings = findings
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Revision{}, err
	}
	defer tx.Rollback()

	// Serialize writers explicitly: with the deferred-fk immediate head lock,
	// a concurrent write gets SQLITE_BUSY instead of a deferred-commit
	// deadlock, and busy_timeout retries it. Deterministic first-writer-wins
	// is what the optimistic guard then reports to the loser.
	if _, err := tx.ExecContext(ctx, `UPDATE draft_head SET revision = revision WHERE id = 1`); err != nil {
		return domain.Revision{}, guardTranslate(err, false, false)
	}

	headID, headRev, err := draftHead(ctx, tx)
	if err != nil {
		return domain.Revision{}, err
	}
	if headRev != expectedDraftRevision {
		return domain.Revision{}, domain.ErrStaleRevision
	}

	rev, err := insertRevision(ctx, tx, doc, headID)
	if err != nil {
		return domain.Revision{}, err
	}
	for _, r := range refs {
		if r == "" {
			return domain.Revision{}, fmt.Errorf("%w: empty secret ref", domain.ErrConflict)
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO secret_refs (ref) VALUES (?)`, string(r)); err != nil {
			return domain.Revision{}, guardTranslate(err, true, true)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO revision_secrets (revision_id, secret_ref) VALUES (?,?)`, rev.ID, string(r)); err != nil {
			return domain.Revision{}, guardTranslate(err, true, true)
		}
	}
	rev.SecretRefs = append([]domain.SecretRef(nil), refs...)
	if s.hook != nil {
		if err := s.hook(); err != nil {
			return domain.Revision{}, err
		}
	}
	if headID == "" {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO draft_head (id, revision_id, revision) VALUES (1, ?, 1)`, rev.ID); err != nil {
			return domain.Revision{}, err
		}
	} else {
		res, err := tx.ExecContext(ctx,
			`UPDATE draft_head SET revision_id = ?, revision = revision + 1 WHERE id = 1 AND revision = ?`,
			rev.ID, expectedDraftRevision)
		if err != nil {
			return domain.Revision{}, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return domain.Revision{}, domain.ErrStaleRevision
		}
	}
	if err := tx.Commit(); err != nil {
		return domain.Revision{}, err
	}
	return rev, nil
}

// draftHead reads the draft head inside a transaction; ("", 0, nil) when none.
func draftHead(ctx context.Context, tx *sql.Tx) (string, int64, error) {
	var id string
	var rev int64
	err := tx.QueryRowContext(ctx,
		`SELECT revision_id, revision FROM draft_head WHERE id = 1`).Scan(&id, &rev)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	return id, rev, nil
}

// Draft returns the current draft pointer. ErrNotFound before the first save.
func (s *Store) Draft(ctx context.Context) (domain.Draft, error) {
	var d domain.Draft
	err := s.db.QueryRowContext(ctx,
		`SELECT revision_id, revision FROM draft_head WHERE id = 1`).Scan(&d.RevisionID, &d.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Draft{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Draft{}, err
	}
	return d, nil
}

// Active returns the current active pointer. ErrNotFound until an apply has
// happened; saving does not affect it.
func (s *Store) Active(ctx context.Context) (domain.ActiveState, error) {
	var a domain.ActiveState
	err := s.db.QueryRowContext(ctx,
		`SELECT revision_id, generation FROM active_state WHERE id = 1`).Scan(&a.RevisionID, &a.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ActiveState{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.ActiveState{}, err
	}
	return a, nil
}

// LoadRevision returns one immutable snapshot by id.
func (s *Store) LoadRevision(ctx context.Context, id string) (domain.Revision, error) {
	var (
		rev      domain.Revision
		doc      string
		status   int
		findings string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, seq, parent_id, doc, valid, findings FROM revisions WHERE id = ?`, id).
		Scan(&rev.ID, &rev.Seq, &rev.ParentID, &doc, &status, &findings)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Revision{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Revision{}, err
	}
	rev.Doc.Raw = json.RawMessage(doc)
	rev.Doc.Validation = domain.ValidationStatus(status)
	if findings != "" && findings != "[]" {
		if err := json.Unmarshal([]byte(findings), &rev.Doc.Findings); err != nil {
			return domain.Revision{}, err
		}
	}
	// Reference metadata (names only, values never stored — T007) belongs to
	// the revision itself: recover the exact rows saved with this revision.
	// Ordered by ref so the set reads back with a stable sequence.
	rows, err := s.db.QueryContext(ctx,
		`SELECT secret_ref FROM revision_secrets WHERE revision_id = ? ORDER BY secret_ref`, id)
	if err != nil {
		return domain.Revision{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return domain.Revision{}, err
		}
		rev.SecretRefs = append(rev.SecretRefs, domain.SecretRef(ref))
	}
	if err := rows.Err(); err != nil {
		return domain.Revision{}, err
	}
	return rev, nil
}

// LoadDraft loads the current draft snapshot.
func (s *Store) LoadDraft(ctx context.Context) (domain.Revision, error) {
	d, err := s.Draft(ctx)
	if err != nil {
		return domain.Revision{}, err
	}
	return s.LoadRevision(ctx, d.RevisionID)
}

// LoadActive loads the currently applied snapshot.
func (s *Store) LoadActive(ctx context.Context) (domain.Revision, error) {
	a, err := s.Active(ctx)
	if err != nil {
		return domain.Revision{}, err
	}
	return s.LoadRevision(ctx, a.RevisionID)
}

// RevisionCount returns the number of stored immutable revisions; used by
// tests to prove immutability and rollback (history rows are never rewritten
// or discarded).
func (s *Store) RevisionCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM revisions`).Scan(&n)
	return n, err
}
