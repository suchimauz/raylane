// auth: protected session manager (T008 private unwired primitive).
// RAM-only, hash-only session bookkeeping per the accepted R2/R3/R4
// contract and its ADDENDUM/ERRATA/CORRECTION/OWNER/mask-precedence
// supplements. Not wired to HTTP, cookies or any composition.

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

// errSessionConfig is the typed configuration failure of
// newSessionManager: a non-positive maxSessions is refused and no manager
// is built. Static message; never echoes the rejected value.
type errSessionConfig struct{}

func (errSessionConfig) Error() string {
	return "auth: session configuration invalid"
}

// errSessionCapacity is the typed failure of createSession when the manager
// already holds maxSessions live sessions: NEW sessions are rejected and
// live sessions are NEVER evicted.
type errSessionCapacity struct{}

func (errSessionCapacity) Error() string {
	return "auth: session capacity reached"
}

// errSessionRandom is the DEFENSIVE failure branch of createSession when
// crypto/rand does not fill the material buffer. Accepted qualification:
// Go's crypto/rand.Read fills or terminates the process irrecoverably, so
// this branch is fail-closed source structure only — it creates nothing and
// carries NO runtime-fault-coverage claim (S-13 prime, source inspection
// only). Static message; never echoes material.
type errSessionRandom struct{}

func (errSessionRandom) Error() string {
	return "auth: session material unavailable"
}

// errSessionUnknown is the typed failure of approveSession for a raw value
// that identifies NO stored session entry at all (no entry exists).
type errSessionUnknown struct{}

func (errSessionUnknown) Error() string {
	return "auth: session unknown"
}

// errSessionExpired is the typed failure of approveSession for a stored
// session whose idle or absolute deadline has passed (equality counts as
// expired). An expired session is NEVER resurrected: approve changes
// nothing on this path.
type errSessionExpired struct{}

func (errSessionExpired) Error() string {
	return "auth: session expired"
}

const (
	// sessionRawBytes is the accepted raw material size drawn from
	// crypto/rand before base64url-no-padding encoding (C3 candidate
	// representation; the raw string is returned once and never stored).
	sessionRawBytes = 32
	// sessionIdleSeconds is the accepted fixed idle timeout in seconds.
	// Both timeouts are accepted constants, NOT constructor parameters.
	sessionIdleSeconds = 900
	// sessionAbsoluteSeconds is the accepted fixed absolute timeout in
	// seconds.
	sessionAbsoluteSeconds = 43200
)

// sessionRecord stores only the digest-keyed deadlines; the raw session
// token is never retained. Stored in a map keyed by sha256(raw).
type sessionRecord struct {
	idleDeadline     time.Time
	absoluteDeadline time.Time
}

// sessionManager is RAM-only: a new process starts empty, which invalidates
// every previously issued token by construction (no restart path exists).
// No function-typed fields, no background sweeper, no internal clock.
type sessionManager struct {
	mu          sync.Mutex
	maxSessions int
	records     map[[sha256.Size]byte]sessionRecord
}

// sessionSatAdd returns start plus dSeconds seconds, clamped at the maximum
// representable instant instead of wrapping into the past (R-K7).
func sessionSatAdd(start time.Time, dSeconds int64) time.Time {
	const maxUnix = int64(1)<<62 - 1
	startUnix := start.Unix()
	if dSeconds > 0 && startUnix > maxUnix-dSeconds {
		return time.Unix(maxUnix, 1e9-1)
	}
	return start.Add(time.Duration(dSeconds) * time.Second)
}

// sessionSecondsBetween returns b minus a in whole seconds using checked
// subtraction, saturating at maxUnix seconds when the true difference
// cannot be represented. Used for min/max deadline arithmetic without
// constructing out-of-range time values.
func sessionSecondsBetween(a, b time.Time) int64 {
	const maxUnix = int64(1)<<62 - 1
	diff := b.Unix() - a.Unix()
	if a.Unix() > 0 && b.Unix() < 0 && diff > 0 {
		return -maxUnix
	}
	if a.Unix() < 0 && b.Unix() > 0 && diff < 0 {
		return maxUnix
	}
	return diff
}

// newSessionManager builds the manager with an explicit positive
// maxSessions (an entry COUNT; its byte-budget proof is open gate G-3).
// idleTimeout and absoluteTimeout are fixed accepted constants and are NOT
// parameters, so no manager can be built with an already-expired or
// unbounded window. A non-positive capacity returns (nil, errSessionConfig)
// and no manager is built.
func newSessionManager(maxSessions int) (*sessionManager, error) {
	if maxSessions <= 0 {
		return nil, errSessionConfig{}
	}
	return &sessionManager{
		maxSessions: maxSessions,
		records:     make(map[[sha256.Size]byte]sessionRecord, maxSessions),
	}, nil
}

// createSession issues a NEW session and returns its opaque raw token. The
// token material is sessionRawBytes bytes from crypto/rand encoded
// base64url-no-padding; only the SHA-256 digest of the raw token is stored.
// On crypto/rand failure NOTHING is created and errSessionRandom is
// returned (defensive branch; see errSessionRandom). At capacity, a NEW
// session is rejected with errSessionCapacity and no live session is
// evicted. Deadlines: idle = min(now+900s, absolute), absolute =
// satAdd(now, 43200s).
func (m *sessionManager) createSession(now time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.records) >= m.maxSessions {
		return "", errSessionCapacity{}
	}
	var buf [sessionRawBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Defensive fail-closed branch: creates nothing. The runtime
		// entropy-failure path is NOT_RUN and never claimed (R-K6).
		return "", errSessionRandom{}
	}
	raw := base64.RawURLEncoding.EncodeToString(buf[:])
	key := sha256.Sum256([]byte(raw))
	absolute := sessionSatAdd(now, sessionAbsoluteSeconds)
	idle := sessionSatAdd(now, sessionIdleSeconds)
	if sessionSecondsBetween(idle, absolute) < 0 {
		idle = absolute
	}
	m.records[key] = sessionRecord{idleDeadline: idle, absoluteDeadline: absolute}
	return raw, nil
}

// approveSession records ONE approved activity for the session identified
// by raw, moving the idle deadline forward but NEVER past the absolute
// deadline: newIdle = max(currentIdle, min(now+900s, absolute)), so a clock
// that moved backwards cannot extend anything. It never creates a session
// and never extends the absolute deadline.
//
// EXPLICIT REFUSAL SEMANTICS: unknown raw (no entry) → errSessionUnknown,
// nothing created; a known session past its idle or absolute deadline
// (equality counts as expired) → errSessionExpired with NO state change —
// no idle extension, no re-creation, no resurrection.
func (m *sessionManager) approveSession(raw string, now time.Time) error {
	key := sha256.Sum256([]byte(raw))
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, exists := m.records[key]
	if !exists {
		return errSessionUnknown{}
	}
	if !now.Before(rec.idleDeadline) || !now.Before(rec.absoluteDeadline) {
		return errSessionExpired{}
	}
	candidate := sessionSatAdd(now, sessionIdleSeconds)
	if sessionSecondsBetween(candidate, rec.absoluteDeadline) < 0 {
		candidate = rec.absoluteDeadline
	}
	if sessionSecondsBetween(rec.idleDeadline, candidate) > 0 {
		rec.idleDeadline = candidate
	}
	m.records[key] = rec
	return nil
}

// validateSession returns true only if raw identifies a stored session
// that is neither idle-expired nor absolute-expired (equality at either
// deadline counts as expired). It NEVER extends any deadline: reads, polls
// and validation do not count as activity. Expired entries are not
// resurrected and are observed as invalid at every later now.
func (m *sessionManager) validateSession(raw string, now time.Time) bool {
	key := sha256.Sum256([]byte(raw))
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, exists := m.records[key]
	if !exists {
		return false
	}
	return now.Before(rec.idleDeadline) && now.Before(rec.absoluteDeadline)
}

// revokeSession removes the session identified by raw (logout). It is
// idempotent: revoking an unknown, expired-but-stored or already-revoked
// session removes any stored entry and returns nil.
func (m *sessionManager) revokeSession(raw string) error {
	key := sha256.Sum256([]byte(raw))
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, key)
	return nil
}
