package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/store"
)

func openStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "raylane.db")
	s, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestStoreOpens(t *testing.T) {
	ctx := context.Background()
	s, _ := openStore(t)
	if _, err := s.Draft(ctx); err == nil {
		t.Fatal("expected ErrNotFound before first save")
	}
	if _, err := s.SaveDraft(ctx, []byte(`{"a":1}`), 0, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadDraft(ctx); err != nil {
		t.Fatal(err)
	}
}

// --- immutable draft versus active; explicit validation semantics ----------

func TestSaveDraftImmutableNeverPromotesAndKeepsVerdicts(t *testing.T) {
	ctx := context.Background()
	s, _ := openStore(t)

	first, err := s.SaveDraft(ctx, []byte(`{"v":1}`), domain.ValidationValid, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.SaveDraft(ctx, []byte(`{"v":2}`), domain.ValidationInvalid, []string{"node.x: unknown field"}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if second.ParentID != first.ID || second.Seq <= first.Seq {
		t.Fatalf("second revision must chain to first: %+v %+v", first, second)
	}
	old, err := s.LoadRevision(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(old.Doc.Raw) != `{"v":1}` || old.Doc.Validation != domain.ValidationValid {
		t.Fatalf("immutable snapshot altered: %+v", old)
	}
	cur, err := s.LoadDraft(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Doc.Validation != domain.ValidationInvalid || len(cur.Doc.Findings) != 1 {
		t.Fatalf("invalid draft not stored honestly: %+v", cur)
	}
	// Saving never promotes anything to active; parse/save never implies PASS.
	if _, err := s.Active(ctx); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Active after saves = %v, want ErrNotFound (save must never promote)", err)
	}

	// Synthetic active fixture: NOT proof of apply; promotion protocol is T016.
	if err := s.SetActiveFixture(ctx, first.ID, 1, nil); err != nil {
		t.Fatal(err)
	}
	act, err := s.LoadActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if act.ID != first.ID {
		t.Fatal("active fixture must reference the first revision")
	}
	if _, err := s.SaveDraft(ctx, []byte(`{"v":3}`), domain.ValidationNotRun, nil, nil, 2); err != nil {
		t.Fatal(err)
	}
	act2, err := s.LoadActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if act2.ID != first.ID {
		t.Fatal("save must not move active")
	}
	// NOT_RUN is preserved distinctly across reload, never upgraded.
	draft3, err := s.LoadDraft(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if draft3.Doc.Validation != domain.ValidationNotRun {
		t.Fatalf("NOT_RUN must persist as its own verdict, got %v", draft3.Doc.Validation)
	}
}

// --- malformed JSON cannot replace prior state ------------------------------

func TestMalformedJSONKeepsPriorState(t *testing.T) {
	ctx := context.Background()
	s, _ := openStore(t)
	rev, err := s.SaveDraft(ctx, []byte(`{"good":true}`), domain.ValidationNotRun, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	n0, err := s.RevisionCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"broken":`, ``, `not json at all`} {
		_, err := s.SaveDraft(ctx, []byte(bad), domain.ValidationValid, nil, nil, 1)
		if !errors.Is(err, domain.ErrMalformedJSON) {
			t.Fatalf("SaveDraft(%q) err = %v, want ErrMalformedJSON", bad, err)
		}
		// Errors carry conditions only, never payload echoes.
		if bad != "" && strings.Contains(err.Error(), bad) {
			t.Fatalf("error leaked document bytes: %v", err)
		}
	}
	cur, err := s.LoadDraft(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cur.ID != rev.ID || string(cur.Doc.Raw) != `{"good":true}` {
		t.Fatalf("prior draft changed after malformed writes: %+v", cur)
	}
	n1, err := s.RevisionCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n1 != n0 {
		t.Fatalf("malformed writes added history rows: %d -> %d", n0, n1)
	}
}

// --- open, migrate, repeated migration, persisted revision reopen -----------

func TestFirstOpenMigrateReopenPersists(t *testing.T) {
	ctx := context.Background()
	s, path := openStore(t)

	if _, err := s.Draft(ctx); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("fresh Draft err = %v, want ErrNotFound", err)
	}
	if _, err := s.Active(ctx); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("fresh Active err = %v, want ErrNotFound", err)
	}
	rev, err := s.SaveDraft(ctx, []byte(`{"nodes":["a"]}`), domain.ValidationNotRun, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := store.Open(ctx, path) // repeated (idempotent) migration on reopen
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	loaded, err := s2.LoadDraft(ctx)
	if err != nil {
		t.Fatalf("LoadDraft after reopen: %v", err)
	}
	if loaded.ID != rev.ID || string(loaded.Doc.Raw) != `{"nodes":["a"]}` {
		t.Fatalf("draft after reopen = %+v", loaded)
	}
	if loaded.Doc.Validation != domain.ValidationNotRun {
		t.Fatalf("NOT_RUN must survive reopen, got %v", loaded.Doc.Validation)
	}
}

// --- optimistic concurrency: two clients, exactly one commit ----------------

func TestCompetingClientsExactlyOneCommitAndTypedConflict(t *testing.T) {
	ctx := context.Background()
	s, _ := openStore(t)
	if _, err := s.SaveDraft(ctx, []byte(`{"base":1}`), domain.ValidationNotRun, nil, nil, 0); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var ok, stale int
	// Both clients read draft revision 1; both submit against it.
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.SaveDraft(ctx, []byte(`{"client":`+strconv.Itoa(i)+`}`),
				domain.ValidationNotRun, nil, nil, 1)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, domain.ErrStaleRevision):
				// The loser must get the typed optimistic conflict, never a
				// raw busy error.
				stale++
			default:
				t.Errorf("unexpected error kind: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if ok != 1 || stale != 1 {
		t.Fatalf("ok=%d stale=%d, want exactly one commit and one typed ErrStaleRevision", ok, stale)
	}
	d, err := s.Draft(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.Revision != 2 {
		t.Fatalf("draft head moved twice: %+v", d)
	}
}

// --- cancellation / failure mid-transaction: no partial publication ---------

func TestTransactionRollbackLeavesNoPartialPublication(t *testing.T) {
	ctx := context.Background()
	s, _ := openStore(t)
	rev, err := s.SaveDraft(ctx, []byte(`{"good":1}`), domain.ValidationNotRun, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	d0, err := s.Draft(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n0, err := s.RevisionCount(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// (a) explicit failure after the revision row was inserted, before the
	// draft head moves.
	marker := errors.New("injected mid-transaction failure")
	s.SetHookOnlyForTests(func() error { return marker })
	if _, err := s.SaveDraft(ctx, []byte(`{"partial":true}`), domain.ValidationNotRun, nil, nil, d0.Revision); !errors.Is(err, marker) {
		t.Fatalf("hooked save err = %v, want injected failure", err)
	}
	s.SetHookOnlyForTests(nil)

	// (b) context cancellation at the same interception point.
	cancelCtx, cancel := context.WithCancel(ctx)
	s.SetHookOnlyForTests(func() error { cancel(); return context.Canceled })
	if _, err := s.SaveDraft(cancelCtx, []byte(`{"partial":true}`), domain.ValidationNotRun, nil, nil, d0.Revision); err == nil {
		t.Fatal("cancelled save must fail")
	}
	s.SetHookOnlyForTests(nil)

	d1, err := s.Draft(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d1.RevisionID != rev.ID || d1.Revision != d0.Revision {
		t.Fatalf("draft head moved on rolled-back writes: %+v", d1)
	}
	n1, err := s.RevisionCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n1 != n0 {
		t.Fatalf("rolled-back writes left history rows: %d -> %d", n0, n1)
	}
	cur, err := s.LoadDraft(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(cur.Doc.Raw) != `{"good":1}` {
		t.Fatalf("prior draft altered by rolled-back writes: %s", cur.Doc.Raw)
	}
}

// --- entity optimistic guards and transactional uniqueness ------------------

func TestEntityOptimisticGuardsAndUniqueness(t *testing.T) {
	ctx := context.Background()
	s, _ := openStore(t)

	node, err := s.CreateNode(ctx, "node-1", []byte(`{"address":"a"}`))
	if err != nil || node.Revision != 1 {
		t.Fatalf("CreateNode: %+v %v", node, err)
	}
	// Create on an existing id must conflict, never overwrite.
	if _, err := s.CreateNode(ctx, "node-1", []byte(`{"address":"b"}`)); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate CreateNode err = %v, want ErrConflict", err)
	}
	kept, err := s.GetNode(ctx, "node-1")
	if err != nil || string(kept.Doc.Raw) != `{"address":"a"}` {
		t.Fatalf("duplicate create overwrote the entity: %+v %v", kept, err)
	}
	// Stale optimistic revision changes nothing and reports the typed error.
	if _, err := s.UpdateNode(ctx, "node-1", 99, []byte(`{"address":"z"}`)); !errors.Is(err, domain.ErrStaleRevision) {
		t.Fatalf("stale UpdateNode err = %v, want ErrStaleRevision", err)
	}
	upd, err := s.UpdateNode(ctx, "node-1", 1, []byte(`{"address":"c"}`))
	if err != nil || upd.Revision != 2 || string(upd.Doc.Raw) != `{"address":"c"}` {
		t.Fatalf("UpdateNode: %+v %v", upd, err)
	}
	if err := s.DeleteNode(ctx, "node-1", 1); !errors.Is(err, domain.ErrStaleRevision) {
		t.Fatalf("stale DeleteNode err = %v, want ErrStaleRevision", err)
	}
	if err := s.DeleteNode(ctx, "node-1", 2); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if _, err := s.GetNode(ctx, "node-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("node survived delete: %v", err)
	}
}

// --- dependency protection: referenced nodes cannot be deleted ---------------

func TestDeleteNodeProtectedByActiveAndSecretReferences(t *testing.T) {
	ctx := context.Background()
	s, _ := openStore(t)

	rev, err := s.SaveDraft(ctx, []byte(`{"draft":1}`), domain.ValidationNotRun, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	node, err := s.CreateNode(ctx, "node-proto", []byte(`{"protocol":"vless"}`))
	if err != nil {
		t.Fatal(err)
	}

	// Active-snapshot membership (synthetic fixture; promotion itself is T016).
	if err := s.SetActiveFixture(ctx, rev.ID, 1, []string{node.ID}); err != nil {
		t.Fatal(err)
	}
	blocked := s.DeleteNode(ctx, node.ID, node.Revision)
	if !errors.Is(blocked, domain.ErrDependency) {
		t.Fatalf("delete of active-referenced node err = %v, want ErrDependency", blocked)
	}
	still, err := s.GetNode(ctx, node.ID)
	if err != nil || still.Revision != node.Revision {
		t.Fatalf("rejected delete must leave the node untouched: %+v %v", still, err)
	}

	// A saved node SecretRef reference likewise blocks removal: the deferred
	// RESTRICT FK makes the deleting commit fail, the transaction rolls back
	// and the node survives untouched.
	if err := s.LinkNodeSecretTx(ctx, node.ID, domain.SecretRef("sec-ref-1")); err != nil {
		t.Fatal(err)
	}
	blocked = s.DeleteNode(ctx, node.ID, node.Revision)
	if !errors.Is(blocked, domain.ErrDependency) {
		t.Fatalf("delete with secret link err = %v, want ErrDependency", blocked)
	}
	survivor, err := s.GetNode(ctx, node.ID)
	if err != nil || survivor.Revision != node.Revision {
		t.Fatalf("rolled-back delete damaged the node: %+v %v", survivor, err)
	}
	// Error text must stay structural: identifiers and counters only, never
	// stored document bytes or driver constraint payloads.
	if strings.Contains(blocked.Error(), "protocol") || strings.Contains(blocked.Error(), "FOREIGN KEY") {
		t.Fatalf("error leaks payload or driver text: %v", blocked)
	}
}

// --- source settings revision vs content versions, captured-revision commit --

func TestSourceSettingsVsContentVersionsAndCapturedRevision(t *testing.T) {
	ctx := context.Background()
	s, _ := openStore(t)
	src, err := s.CreateSource(ctx, "src-1", "subscription", []byte(`{"url":"x"}`))
	if err != nil || src.Revision != 1 || src.DraftVersion != 0 || src.ActiveVersion != 0 {
		t.Fatalf("CreateSource: %+v %v", src, err)
	}
	if _, err := s.CreateSource(ctx, "src-1", "ruleset", []byte(`{}`)); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate source id err = %v, want ErrConflict", err)
	}

	// Manual settings edit bumps ONLY the settings revision.
	upd, err := s.UpdateSettingsTx(ctx, "src-1", 1, []byte(`{"url":"y"}`))
	if err != nil || upd.Revision != 2 || upd.DraftVersion != 0 || upd.ActiveVersion != 0 {
		t.Fatalf("UpdateSettingsTx must move settings revision only: %+v %v", upd, err)
	}
	if _, err := s.UpdateSettingsTx(ctx, "src-1", 1, []byte(`{"url":"z"}`)); !errors.Is(err, domain.ErrStaleRevision) {
		t.Fatalf("stale settings guard err = %v, want ErrStaleRevision", err)
	}

	// Two refresh jobs: only one may run per source (busy conflict).
	if err := s.BeginRefreshJob(ctx, "job-1", "src-1", 2); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginRefreshJob(ctx, "job-2", "src-1", 2); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second running job err = %v, want ErrConflict busy", err)
	}

	// Intervening manual settings change after capture ⇒ commit-check rejects
	// the whole candidate; nothing is published.
	if _, err := s.UpdateSettingsTx(ctx, "src-1", 2, []byte(`{"url":"manual"}`)); err != nil {
		t.Fatal(err)
	}
	before, err := s.GetSource(ctx, "src-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitRefreshTx(ctx, "job-1", []byte(`{"url":"fetched"}`), 0); !errors.Is(err, domain.ErrStaleRevision) {
		t.Fatalf("stale capturedRevision commit err = %v, want ErrStaleRevision", err)
	}
	after, err := s.GetSource(ctx, "src-1")
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != before.Revision || after.DraftVersion != before.DraftVersion || string(after.Doc.Raw) != string(before.Doc.Raw) {
		t.Fatalf("rejected refresh published something: %+v vs %+v", after, before)
	}

	// A correctly captured refresh commits and bumps ONLY the content draft
	// version, never the settings revision. job-1 is already settled as
	// 'rejected' by the commit check itself — no manual settle needed.
	cur, err := s.GetSource(ctx, "src-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BeginRefreshJob(ctx, "job-3", "src-1", cur.Revision); err != nil {
		t.Fatal(err)
	}
	pub, err := s.CommitRefreshTx(ctx, "job-3", []byte(`{"url":"fetched"}`), cur.DraftVersion)
	if err != nil {
		t.Fatalf("valid refresh commit: %v", err)
	}
	if pub.Revision != cur.Revision || pub.DraftVersion != cur.DraftVersion+1 || pub.ActiveVersion != cur.ActiveVersion {
		t.Fatalf("refresh must bump content draft version only: %+v vs %+v", pub, cur)
	}
	if string(pub.Doc.Raw) != `{"url":"fetched"}` {
		t.Fatalf("candidate not published: %s", pub.Doc.Raw)
	}
	// Settled job cannot re-publish.
	if _, err := s.CommitRefreshTx(ctx, "job-3", []byte(`{"url":"again"}`), pub.DraftVersion); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("re-commit of settled job err = %v, want ErrConflict", err)
	}
}

// --- revision secret-reference metadata readback (names only, T007 owns values) --

func TestRevisionSecretRefsReadback(t *testing.T) {
	ctx := context.Background()
	s, path := openStore(t)

	refs := []domain.SecretRef{"secret://test/z", "secret://test/a"}
	first, err := s.SaveDraft(ctx, []byte(`{"v":1}`), domain.ValidationValid, []string{"w1"}, refs, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Immediate LoadRevision recovers the exact set, stably ordered.
	loaded, err := s.LoadRevision(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.SecretRefs) != 2 || loaded.SecretRefs[0] != "secret://test/a" || loaded.SecretRefs[1] != "secret://test/z" {
		t.Fatalf("LoadRevision SecretRefs = %v, want [a z]", loaded.SecretRefs)
	}
	// Identity, document, status and findings are unchanged by the read.
	if loaded.ID != first.ID || loaded.Seq != first.Seq || loaded.ParentID != first.ParentID {
		t.Fatalf("identity changed on readback: %+v", loaded)
	}
	if string(loaded.Doc.Raw) != `{"v":1}` || loaded.Doc.Validation != domain.ValidationValid || len(loaded.Doc.Findings) != 1 {
		t.Fatalf("document envelope altered on readback: %+v", loaded)
	}
	// LoadDraft delegates to the same shared read.
	draft, err := s.LoadDraft(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(draft.SecretRefs) != 2 || draft.SecretRefs[0] != "secret://test/a" {
		t.Fatalf("LoadDraft SecretRefs = %v", draft.SecretRefs)
	}
	// Synthetic active fixture (not proof of T016 apply) reads the same refs.
	if err := s.SetActiveFixture(ctx, first.ID, 1, nil); err != nil {
		t.Fatal(err)
	}
	act, err := s.LoadActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(act.SecretRefs) != 2 || act.SecretRefs[1] != "secret://test/z" {
		t.Fatalf("LoadActive SecretRefs = %v", act.SecretRefs)
	}

	// A later revision carries a DIFFERENT set without disturbing the older
	// immutable one; an empty set stays empty.
	second, err := s.SaveDraft(ctx, []byte(`{"v":2}`), domain.ValidationNotRun, nil, []domain.SecretRef{"secret://test/b"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	third, err := s.SaveDraft(ctx, []byte(`{"v":3}`), domain.ValidationNotRun, nil, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(third.SecretRefs) != 0 {
		t.Fatalf("empty set must stay empty: %v", third.SecretRefs)
	}
	old, err := s.LoadRevision(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(old.SecretRefs) != 2 || old.SecretRefs[0] != "secret://test/a" || old.SecretRefs[1] != "secret://test/z" {
		t.Fatalf("older revision refs mutated by later saves: %v", old.SecretRefs)
	}
	mid, err := s.LoadRevision(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(mid.SecretRefs) != 1 || mid.SecretRefs[0] != "secret://test/b" {
		t.Fatalf("second revision refs = %v", mid.SecretRefs)
	}
	empty, err := s.LoadRevision(ctx, third.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.SecretRefs) != 0 {
		t.Fatalf("empty set read back as %v", empty.SecretRefs)
	}

	// Close and reopen: refs persist in the store, not in process memory.
	s.Close()
	s2, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	reopened, err := s2.LoadRevision(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.SecretRefs) != 2 || reopened.SecretRefs[0] != "secret://test/a" || reopened.SecretRefs[1] != "secret://test/z" {
		t.Fatalf("after reopen refs = %v", reopened.SecretRefs)
	}
}

// --- connection invariants on every pooled connection -----------------------

func TestConnectionInvariantsOnEveryPooledConnection(t *testing.T) {
	ctx := context.Background()
	s, _ := openStore(t)
	// Force several distinct pool connections through real work, then probe
	// invariants repeatedly: foreign_keys and WAL must hold on more than the
	// first connection the pool opened.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := s.CreateNode(ctx, "inv-"+strconv.Itoa(i), []byte(`{"i":`+strconv.Itoa(i)+`}`)); err != nil {
				t.Errorf("CreateNode: %v", err)
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < 8; i++ {
		fk, wal, err := store.ConnectionInvariants(s.DB())
		if err != nil {
			t.Fatal(err)
		}
		if !fk || !wal {
			t.Fatalf("probe %d: foreign_keys=%v wal=%v, both must hold on every pooled connection", i, fk, wal)
		}
	}
}

// --- restore boundary: atomic draft creation, active untouched ---------------

func TestRestoreDraftTxNeverTouchesActive(t *testing.T) {
	ctx := context.Background()
	s, _ := openStore(t)
	activeRev, err := s.SaveDraft(ctx, []byte(`{"applied":1}`), domain.ValidationValid, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetActiveFixture(ctx, activeRev.ID, 1, nil); err != nil {
		t.Fatal(err)
	}
	d0, err := s.Draft(ctx)
	if err != nil {
		t.Fatal(err)
	}

	restored, err := s.RestoreDraftTx(ctx, []byte(`{"restored":true}`), domain.ValidationNotRun, nil)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := s.Draft(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d1.RevisionID != restored.ID || d1.Revision <= d0.Revision {
		t.Fatalf("restore must land in draft atomically: %+v", d1)
	}
	act, err := s.LoadActive(ctx)
	if err != nil || act.ID != activeRev.ID {
		t.Fatalf("restore must never touch active: %+v %v", act, err)
	}

	// A rolled-back restore leaves no revision and no head movement.
	marker := errors.New("injected restore failure")
	s.SetHookOnlyForTests(func() error { return marker })
	if _, err := s.RestoreDraftTx(ctx, []byte(`{"partial":true}`), domain.ValidationNotRun, nil); !errors.Is(err, marker) {
		t.Fatalf("hooked restore err = %v, want injected failure", err)
	}
	s.SetHookOnlyForTests(nil)
	d2, err := s.Draft(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d2.RevisionID != restored.ID || d2.Revision != d1.Revision {
		t.Fatalf("rolled-back restore moved the draft head: %+v", d2)
	}
}
