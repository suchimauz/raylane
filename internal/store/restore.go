package store

// Transaction-internal helpers and the future atomic restore boundary. The
// restore code here deliberately defines ONLY the transaction skeleton T006
// must guarantee (restore creates a draft in the same transaction as its
// bookkeeping, never touches active); encrypted record remapping itself is
// T007/T021 work and is not implemented or claimed.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/suchimauz/raylane/internal/domain"
)

// insertRevision adds one immutable snapshot row and returns it. parentID is
// the previous draft revision ("" for the first).
func insertRevision(ctx context.Context, tx *sql.Tx, doc domain.Document, parentID string) (domain.Revision, error) {
	findings, err := json.Marshal(doc.Findings)
	if err != nil {
		return domain.Revision{}, err
	}
	if doc.Findings == nil {
		findings = []byte("[]")
	}
	revID := newID()
	var seq int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0)+1 FROM revisions`).Scan(&seq); err != nil {
		return domain.Revision{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO revisions (id, seq, parent_id, doc, valid, findings) VALUES (?,?,?,?,?,?)`,
		revID, seq, parentID, string(doc.Raw), int(doc.Validation), string(findings)); err != nil {
		return domain.Revision{}, err
	}
	out := domain.Revision{ID: revID, Seq: seq, ParentID: parentID}
	out.Doc.Raw = append([]byte(nil), doc.Raw...)
	out.Doc.Validation = doc.Validation
	out.Doc.Findings = append([]string(nil), doc.Findings...)
	return out, nil
}

// RestoreDraftTx atomically inserts a restored document as a brand-new draft
// revision and records the restore transaction marker. It never modifies
// active_state (restore lands in draft only, per FR-021/D-059). This is the
// minimal T006 boundary: a caller that later owns encrypted secret remapping
// (T007) runs it inside the same tx. A failed or cancelled call leaves no
// revision and no marker behind.
func (s *Store) RestoreDraftTx(ctx context.Context, raw []byte, status domain.ValidationStatus, findings []string) (domain.Revision, error) {
	doc, err := domain.ParseDocument(raw)
	if err != nil {
		return domain.Revision{}, err
	}
	doc.Validation = status
	doc.Findings = findings
	return s.restoreDraftDocTx(ctx, doc)
}

func (s *Store) restoreDraftDocTx(ctx context.Context, doc domain.Document) (domain.Revision, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Revision{}, err
	}
	defer tx.Rollback()

	headID, _, err := draftHead(ctx, tx)
	if err != nil {
		return domain.Revision{}, err
	}
	rev, err := insertRevision(ctx, tx, doc, headID)
	if err != nil {
		return domain.Revision{}, err
	}
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
		if _, err := tx.ExecContext(ctx,
			`UPDATE draft_head SET revision_id = ?, revision = revision + 1 WHERE id = 1`, rev.ID); err != nil {
			return domain.Revision{}, err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR REPLACE INTO restore_tx (id, state, revision_id) VALUES (1, 'committed', ?)`, rev.ID); err != nil {
		return domain.Revision{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.Revision{}, err
	}
	return rev, nil
}

// SetActiveFixture records an active-state row for tests only: T006 stores and
// preserves distinct draft/active state, while the real apply-readiness
// promotion belongs to T016. Every use of this helper marks a synthetic
// fixture, NOT proof of an apply protocol.
func (s *Store) SetActiveFixture(ctx context.Context, revisionID string, generation int64, nodeIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO active_state (id, revision_id, generation) VALUES (1, ?, ?)`, revisionID, generation); err != nil {
		return guardTranslate(err, true, true)
	}
	for _, n := range nodeIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO active_revision_nodes (revision_id, node_id) VALUES (?,?)`, revisionID, n); err != nil {
			return guardTranslate(err, true, true)
		}
	}
	return tx.Commit()
}

// DraftRevisionID returns the current draft revision id ("" before the first
// save) so callers can snapshot the saved state they depend on.
func (s *Store) DraftRevisionID(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT revision_id FROM draft_head WHERE id = 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// LinkDraftNodeTx records that a node belongs to a configuration revision —
// normally the current saved draft head. The FK makes the reference real: the
// node must exist, and while any draft/active revision references it, the node
// cannot be deleted (domain.ErrDependency with full rollback in DeleteNode).
func (s *Store) LinkDraftNodeTx(ctx context.Context, revisionID, nodeID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO active_revision_nodes (revision_id, node_id) VALUES (?,?)`, revisionID, nodeID); err != nil {
		return guardTranslate(err, true, true)
	}
	return tx.Commit()
}

// LinkNodeSecretTx records that a saved node references a SecretRef, creating
// the ref placeholder if needed. Only references exist here — never values.
func (s *Store) LinkNodeSecretTx(ctx context.Context, nodeID string, ref domain.SecretRef) error {
	if ref == "" {
		return fmt.Errorf("%w: empty secret ref", domain.ErrConflict)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO secret_refs (ref) VALUES (?)`, string(ref)); err != nil {
		return guardTranslate(err, true, true)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO node_secret_refs (node_id, secret_ref) VALUES (?,?)`, nodeID, string(ref)); err != nil {
		return guardTranslate(err, true, true)
	}
	return tx.Commit()
}
