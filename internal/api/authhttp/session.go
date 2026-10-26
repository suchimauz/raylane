package authhttp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// errTooManySessions is the internal reject-new signal at capacity. It is
// never returned to a remote caller as a distinguishing detail beyond the
// generic limiter response.
var errTooManySessions = errors.New("authhttp: session capacity reached")

// session is one live admin session. Only the SHA-256 digest of the token is
// retained; the raw token is returned to the client exactly once (in the
// Set-Cookie header) and never stored.
type session struct {
	digest    [sha256.Size]byte
	createdAt time.Time
	lastSeen  time.Time
}

// sessionManager owns the live sessions for one runtime process. Sessions are
// RAM-only and do not survive a restart (re-login is required). The zero value
// is NOT usable; use newSessionManager.
type sessionManager struct {
	mu       sync.Mutex
	sessions map[[sha256.Size]byte]session
	now      func() time.Time // wall clock, replaceable only in tests
}

func newSessionManager() *sessionManager {
	return newSessionManagerAt(time.Now)
}

// newSessionManagerAt builds a manager reading the supplied clock. Production
// uses the wall clock; tests inject a deterministic clock at construction.
func newSessionManagerAt(now func() time.Time) *sessionManager {
	return &sessionManager{
		sessions: map[[sha256.Size]byte]session{},
		now:      now,
	}
}

// newToken returns a fresh opaque 32-byte CSPRNG token encoded base64url with
// no padding, and its SHA-256 digest.
func newToken() (raw string, digest [sha256.Size]byte, err error) {
	var buf [sessionTokenBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", digest, err
	}
	digest = sha256.Sum256(buf[:])
	return base64.RawURLEncoding.EncodeToString(buf[:]), digest, nil
}

// Create establishes a NEW session and returns its raw token (base64url, no
// padding). Login always calls Create, so every login mints a fresh session.
// At capacity (maxSessions) it returns errTooManySessions and creates nothing
// (reject-new, no eviction).
func (m *sessionManager) Create() (string, error) {
	raw, digest, err := newToken()
	if err != nil {
		return "", err
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(now)
	if len(m.sessions) >= maxSessions {
		return "", errTooManySessions
	}
	m.sessions[digest] = session{digest: digest, createdAt: now, lastSeen: now}
	return raw, nil
}

// Lookup validates a presented raw token: the token's digest must map to a
// live session that has not expired by idle or absolute lifetime. On success
// it returns true; it does NOT extend the idle timer (reads/polling must not
// extend idle). Expired sessions are removed.
func (m *sessionManager) Lookup(raw string) bool {
	digest, ok := digestOf(raw)
	if !ok {
		return false
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[digest]
	if !ok {
		return false
	}
	if m.expiredLocked(s, now) {
		delete(m.sessions, digest)
		return false
	}
	return true
}

// Revoke removes the session for a presented raw token (logout). It is
// idempotent: revoking an unknown or already-removed token is a no-op.
func (m *sessionManager) Revoke(raw string) {
	digest, ok := digestOf(raw)
	if !ok {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, digest)
}

// expiredLocked reports whether s has passed its idle or absolute lifetime at
// now. Idle is measured from lastSeen; absolute from createdAt. Reads never
// update lastSeen, so idle expiry is unaffected by polling.
func (m *sessionManager) expiredLocked(s session, now time.Time) bool {
	if now.Sub(s.createdAt) >= sessionAbsoluteSeconds*time.Second {
		return true
	}
	if now.Sub(s.lastSeen) >= sessionIdleSeconds*time.Second {
		return true
	}
	return false
}

// expireLocked removes every expired session (housekeeping at Create).
func (m *sessionManager) expireLocked(now time.Time) {
	for d, s := range m.sessions {
		if m.expiredLocked(s, now) {
			delete(m.sessions, d)
		}
	}
}

// Len returns the live session count (test/diagnostic only).
func (m *sessionManager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// digestOf decodes a base64url-no-padding token and returns its SHA-256
// digest. A malformed token yields ok=false.
func digestOf(raw string) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	buf, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(buf) != sessionTokenBytes {
		return digest, false
	}
	return sha256.Sum256(buf), true
}
