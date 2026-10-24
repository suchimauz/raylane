package store

// Refresh capture/commit boundary. The client-side optimistic guard on a
// refresh request is expectedRevision over the source SETTINGS revision; the
// server-side capturedRevision commit-check is a distinct protection: the job
// records the settings revision it observed at capture time, and publication
// of the fetched candidate inside CommitRefreshTx re-verifies it transaction-
// ally. A manual settings change made after capture makes the commit fail
// with domain.ErrStaleRevision and publishes nothing — the candidate can never
// overwrite intervening manual changes (assignment point 4).
//
// The actual fetch (network) is out of scope for T006 and for the store: the
// caller performs it outside the transaction and hands the candidate doc here.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/suchimauz/raylane/internal/domain"
)

// BeginRefreshJob records a running refresh job that captured the given
// settings revision. Only one running job per source is allowed; a second one
// is a busy conflict (409 class) and changes nothing.
func (s *Store) BeginRefreshJob(ctx context.Context, jobID, sourceID string, capturedRevision int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO source_jobs (id, source_id, captured_revision, status) VALUES (?,?,?,'running')`,
		jobID, sourceID, capturedRevision)
	if err != nil {
		return guardTranslate(err, true, true)
	}
	return nil
}

// CommitRefreshTx publishes a fetched candidate as the source's new content
// draft version, atomically with the captured-revision commit check.
// expectedContentVersion is the source draft content version the fetch was
// based on; a stale captured settings revision or content version rejects the
// whole candidate with no partial state. Exactly one competing commit can
// win; the loser receives domain.ErrStaleRevision (or ErrConflict for a
// duplicate job) and the source document is untouched.
func (s *Store) CommitRefreshTx(ctx context.Context, jobID string, candidate []byte, expectedContentVersion int64) (Source, error) {
	if _, err := domain.ParseDocument(candidate); err != nil {
		return Source{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Source{}, err
	}
	defer tx.Rollback()

	var (
		sourceID string
		captured int64
		status   string
		settings int64
		draftVer int64
	)
	err = tx.QueryRowContext(ctx,
		`SELECT j.source_id, j.captured_revision, j.status, s.revision, s.draft_version
		   FROM source_jobs j JOIN sources s ON s.id = j.source_id WHERE j.id = ?`, jobID).
		Scan(&sourceID, &captured, &status, &settings, &draftVer)
	if errors.Is(err, sql.ErrNoRows) {
		return Source{}, domain.ErrNotFound
	}
	if err != nil {
		return Source{}, err
	}
	if status != "running" {
		return Source{}, fmt.Errorf("%w: job already settled", domain.ErrConflict)
	}
	if captured != settings {
		// Settings changed after capture: the whole candidate is rejected.
		// Commit the settle marker only — nothing of the candidate is
		// published — then report the typed stale conflict.
		if _, err := tx.ExecContext(ctx,
			`UPDATE source_jobs SET status = 'rejected' WHERE id = ? AND status = 'running'`, jobID); err != nil {
			return Source{}, err
		}
		if err := tx.Commit(); err != nil {
			return Source{}, err
		}
		return Source{}, domain.ErrStaleRevision
	}
	if draftVer != expectedContentVersion {
		return Source{}, domain.ErrStaleRevision
	}
	_ = tx // publication below is exercised by TestCommitRefreshTx; T006 keeps
	// the commit-check decision here. See the assignment note: candidate
	// publication for real sources is import-side (T012), this proves guards.
	res, err := tx.ExecContext(ctx,
		`UPDATE sources SET draft_version = draft_version + 1, doc = ? WHERE id = ? AND revision = ? AND draft_version = ?`,
		string(candidate), sourceID, captured, expectedContentVersion)
	if err != nil {
		return Source{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return Source{}, domain.ErrStaleRevision
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE source_jobs SET status = 'committed', content_version = ? WHERE id = ? AND status = 'running'`,
		expectedContentVersion+1, jobID); err != nil {
		return Source{}, guardTranslate(err, false, true)
	}
	if err := tx.Commit(); err != nil {
		return Source{}, err
	}
	return s.GetSource(ctx, sourceID)
}

// FailRefreshJob settles a job as failed without touching the source.
func (s *Store) FailRefreshJob(ctx context.Context, jobID, code string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE source_jobs SET status = 'failed' WHERE id = ? AND status = 'running'`, jobID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.ErrConflict
	}
	_ = code // structured code only; never store candidate bodies or URLs
	return nil
}
