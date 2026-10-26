package authhttp

import (
	"errors"
	"testing"
	"time"
)

// Deterministic private-clock coverage for the session manager's remaining
// mandatory timing/capacity cases (T008). These inject a controllable clock
// at construction (newSessionManagerAt) — no real waiting, no new public hook,
// no fake activity endpoint. They complement the existing HTTP-level idle
// boundary test (TestT008SessionIdleExpiryUsesServerClock).

// TestSessionAbsoluteLifetimeBoundary exercises the absolute branch of
// expiredLocked directly: a session whose lastSeen is kept within the idle
// window but whose createdAt passes sessionAbsoluteSeconds (43200s) is dead.
// (Because reads never extend idle, a live-at-absolute session requires its
// lastSeen to be recent; the absolute ceiling is the backstop that still
// bounds such a session.) We construct the session state deterministically.
func TestSessionAbsoluteLifetimeBoundary(t *testing.T) {
	start := time.Unix(1700000000, 0)
	m := newSessionManagerAt(func() time.Time { return start })
	createdAt := start
	// lastSeen kept just inside the idle window relative to the test 'now'.
	now := start.Add(sessionAbsoluteSeconds * time.Second)
	lastSeen := now.Add(-(sessionIdleSeconds * time.Second) + time.Millisecond)
	s := session{digest: [32]byte{1}, createdAt: createdAt, lastSeen: lastSeen}
	if m.expiredLocked(s, now.Add(-time.Millisecond)) {
		t.Fatal("session should be alive one tick before the absolute ceiling")
	}
	if !m.expiredLocked(s, now) {
		t.Fatal("session must be dead at the absolute ceiling even with recent lastSeen")
	}
}

// TestSessionReadsDoNotExtendIdle: Lookup (reads/polling) never updates
// lastSeen, so a session that is continuously read still dies at
// lastSeen + sessionIdleSeconds. This is the non-activity invariant.
func TestSessionReadsDoNotExtendIdle(t *testing.T) {
	start := time.Unix(1700000000, 0)
	now := start
	m := newSessionManagerAt(func() time.Time { return now })
	tok, err := m.Create()
	if err != nil {
		t.Fatal(err)
	}
	// Poll repeatedly across the whole idle window: reads must not slide it.
	for elapsed := time.Duration(0); elapsed < sessionIdleSeconds*time.Second; elapsed += 100 * time.Second {
		now = start.Add(elapsed)
		if !m.Lookup(tok) {
			t.Fatalf("read at %+v wrongly expired the session (reads must not extend idle)", elapsed)
		}
	}
	// One tick before idle boundary: alive.
	now = start.Add(sessionIdleSeconds*time.Second - time.Millisecond)
	if !m.Lookup(tok) {
		t.Fatal("session expired before the idle boundary")
	}
	// At the idle boundary (measured from lastSeen=creation, since reads never
	// moved it): dead.
	now = start.Add(sessionIdleSeconds * time.Second)
	if m.Lookup(tok) {
		t.Fatal("session survived the idle boundary despite only reads")
	}
}

// TestSessionCapacityRejectsNewAtMax: at exactly maxSessions (1024) Create
// returns errTooManySessions and creates nothing (reject-new, no eviction);
// the existing sessions remain valid.
func TestSessionCapacityRejectsNewAtMax(t *testing.T) {
	now := time.Unix(1700000000, 0)
	m := newSessionManagerAt(func() time.Time { return now })
	var tokens []string
	for i := 0; i < maxSessions; i++ {
		tok, err := m.Create()
		if err != nil {
			t.Fatalf("create %d below capacity: %v", i, err)
		}
		tokens = append(tokens, tok)
	}
	if m.Len() != maxSessions {
		t.Fatalf("expected %d sessions, got %d", maxSessions, m.Len())
	}
	// At capacity: the next Create is rejected and adds nothing.
	if _, err := m.Create(); !errors.Is(err, errTooManySessions) {
		t.Fatalf("expected errTooManySessions at capacity, got %v", err)
	}
	if m.Len() != maxSessions {
		t.Fatalf("capacity rejection must not evict or add; len=%d", m.Len())
	}
	// Existing sessions are unaffected.
	for _, tok := range tokens {
		if !m.Lookup(tok) {
			t.Fatal("existing session invalidated by capacity rejection")
		}
	}
}

// TestSessionExpiredSessionNotResurrected: once a session is expired and
// removed by Lookup, advancing time backwards (or re-presenting the token)
// must not resurrect it.
func TestSessionExpiredSessionNotResurrected(t *testing.T) {
	start := time.Unix(1700000000, 0)
	now := start
	m := newSessionManagerAt(func() time.Time { return now })
	tok, err := m.Create()
	if err != nil {
		t.Fatal(err)
	}
	// Advance past idle so the session expires and is removed.
	now = start.Add(sessionIdleSeconds*time.Second + time.Second)
	if m.Lookup(tok) {
		t.Fatal("session should be expired at idle+1s")
	}
	if m.Len() != 0 {
		t.Fatal("expired session must be removed")
	}
	// Wind the clock back: the token must NOT come back to life.
	now = start
	if m.Lookup(tok) {
		t.Fatal("expired session resurrected after winding the clock back")
	}
	if m.Len() != 0 {
		t.Fatal("resurrected session present after clock rewind")
	}
}
