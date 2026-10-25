// auth: protected bootstrap token manager (T008 private unwired primitive).
// Hash-only single-token manager per the accepted R2/R3/R4 contract and its
// ADDENDUM/ERRATA/CORRECTION/OWNER/mask-precedence supplements.

package auth

import (
	"crypto/sha256"
	"sync"
	"time"
)

// errBootstrapTokenConfig is the typed configuration failure of
// newBootstrapTokenManager: a non-positive ttl is refused and there is NO
// default. Static message; never echoes the rejected value.
type errBootstrapTokenConfig struct{}

func (errBootstrapTokenConfig) Error() string {
	return "auth: bootstrap token configuration invalid"
}

// errBootstrapTokenLength is the typed failure of register/consume when the
// presented raw token is outside the accepted 1..256 byte bound. At
// registration the bound is checked BEFORE any hashing; at consume it is
// checked after the no-live-token check and before any digest comparison.
// Static message; never echoes the input.
type errBootstrapTokenLength struct{}

func (errBootstrapTokenLength) Error() string {
	return "auth: bootstrap token length invalid"
}

// errBootstrapTokenCapacity is the typed failure of registerBootstrapToken
// when a live token already exists: registration is install-only and NEVER
// replaces or overwrites the live token.
type errBootstrapTokenCapacity struct{}

func (errBootstrapTokenCapacity) Error() string {
	return "auth: bootstrap token already active"
}

// errBootstrapTokenUnknown is the typed failure of consumeBootstrapToken
// when no live token exists to consume.
type errBootstrapTokenUnknown struct{}

func (errBootstrapTokenUnknown) Error() string {
	return "auth: bootstrap token unknown"
}

// errBootstrapTokenMismatch is the typed failure of consumeBootstrapToken
// when the presented raw token's digest does not match the stored digest.
// Static message; the stored digest is never echoed.
type errBootstrapTokenMismatch struct{}

func (errBootstrapTokenMismatch) Error() string {
	return "auth: bootstrap token invalid"
}

// errBootstrapTokenExpired is the typed failure of consumeBootstrapToken
// when the live token's deadline has passed. Deadline equality (now ==
// expiry) counts as expired; a token cannot be resurrected. The expiry
// check runs AFTER the digest comparison so a wrong presentation never
// learns which deadline the stored token carried.
type errBootstrapTokenExpired struct{}

func (errBootstrapTokenExpired) Error() string {
	return "auth: bootstrap token expired"
}

// errBootstrapTokenClosed is the typed failure once the manager has been
// closed by a successful consume: the close is terminal, permanent, and
// no path reopens the manager.
type errBootstrapTokenClosed struct{}

func (errBootstrapTokenClosed) Error() string {
	return "auth: bootstrap token closed"
}

// bootstrapTokenMaxBytes is the accepted input bound checked BEFORE any
// hashing (R-T2).
const bootstrapTokenMaxBytes = 256

// bootstrapTokenManager holds AT MOST ONE live bootstrap token, hash-only.
// Memory is O(1) by construction: no tombstones, no eviction, no capacity
// parameter. All state transitions are atomic under mu; there are no
// function-typed seams.
type bootstrapTokenManager struct {
	mu       sync.Mutex
	ttl      time.Duration
	digest   [sha256.Size]byte
	expiry   time.Time
	haveLive bool
	closed   bool
}

// saturatingAdd returns start+d clamped to the maximum representable
// instant instead of wrapping into the past. startUnix is the cached
// Unix-seconds base used for the checked overflow arithmetic (a value,
// never a global clock).
func saturatingAdd(start time.Time, startUnix int64, d time.Duration) time.Time {
	const maxUnix = int64(1)<<62 - 1
	dSec := int64(d / time.Second)
	dRem := int64(d % time.Second)
	if dSec > 0 && startUnix > maxUnix-dSec {
		return time.Unix(maxUnix, 1e9-1)
	}
	sum := startUnix + dSec
	nanos := int64(start.Nanosecond()) + dRem
	if nanos >= int64(time.Second) {
		nanos -= int64(time.Second)
		if sum >= maxUnix {
			return time.Unix(maxUnix, 1e9-1)
		}
		sum++
	}
	if sum > maxUnix {
		return time.Unix(maxUnix, 1e9-1)
	}
	return time.Unix(sum, nanos)
}

// newBootstrapTokenManager creates the single-token manager with ttl
// supplied ONLY here: a zero or negative ttl is a typed configuration
// failure with no default, and no manager is built in that case.
func newBootstrapTokenManager(ttl time.Duration) (*bootstrapTokenManager, error) {
	if ttl <= 0 {
		return nil, errBootstrapTokenConfig{}
	}
	return &bootstrapTokenManager{ttl: ttl}, nil
}

// registerBootstrapToken installs raw as the single live bootstrap token.
// It installs ONLY WHEN NO LIVE TOKEN EXISTS: it never replaces and never
// overwrites an existing live token. TRUSTED CALLER PRECONDITION: the
// caller must already have obtained raw over the accepted protected local
// channel; this function does NOT prove that precondition and is NOT an
// issuer. Returns errBootstrapTokenLength if len(raw) is outside 1..256
// (checked before hashing), errBootstrapTokenClosed if the manager was
// closed by a successful consume, and errBootstrapTokenCapacity if a live
// token already exists.
func registerBootstrapToken(m *bootstrapTokenManager, raw []byte, now time.Time) error {
	if len(raw) < 1 || len(raw) > bootstrapTokenMaxBytes {
		return errBootstrapTokenLength{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errBootstrapTokenClosed{}
	}
	if m.haveLive {
		return errBootstrapTokenCapacity{}
	}
	// R-T1: only the digest is retained; raw is never stored, logged or
	// echoed. Expiry uses saturating add so a huge ttl clamps at the
	// maximum representable instant instead of wrapping into the past.
	m.digest = sha256.Sum256(raw)
	m.expiry = saturatingAdd(now, now.Unix(), m.ttl)
	m.haveLive = true
	return nil
}

// consumeBootstrapToken atomically consumes the live token: it verifies the
// presented raw against the stored digest AND the expiry, then closes the
// manager permanently. One-use: a second consume always fails with
// errBootstrapTokenClosed. Accepted failure precedence (single lock
// critical section): closed, then unknown (no live token), then length,
// then digest mismatch, then expiry (equality counts as expired).
func consumeBootstrapToken(m *bootstrapTokenManager, raw []byte, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errBootstrapTokenClosed{}
	}
	if !m.haveLive {
		return errBootstrapTokenUnknown{}
	}
	if len(raw) < 1 || len(raw) > bootstrapTokenMaxBytes {
		return errBootstrapTokenLength{}
	}
	if sha256.Sum256(raw) != m.digest {
		return errBootstrapTokenMismatch{}
	}
	if !now.Before(m.expiry) {
		return errBootstrapTokenExpired{}
	}
	// Successful consume: terminal close, no tombstone, no reopen.
	m.digest = [sha256.Size]byte{}
	m.expiry = time.Time{}
	m.haveLive = false
	m.closed = true
	return nil
}
