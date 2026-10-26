package authhttp

import (
	"net"
	"sync"
	"time"
)

// loginLimiter is the anonymous login rate limiter: per actual socket peer IP
// a token bucket of burst 5 refilling 1 per 60 s, capped at 1024 peers
// (reject-new, no eviction), plus a GLOBAL cap of 2 concurrent Argon2
// verifications (fail-fast, no queue). X-Forwarded-For is ignored entirely;
// the peer IP comes from the accepting connection.
type loginLimiter struct {
	mu     sync.Mutex
	peers  map[string]*peerBucket
	now    func() time.Time
	argon2 chan struct{} // global in-flight Argon2 semaphore, capacity 2
}

// peerBucket is one peer's token bucket.
type peerBucket struct {
	tokens float64
	last   time.Time
}

func newLoginLimiter() *loginLimiter {
	return newLoginLimiterAt(time.Now)
}

// newLoginLimiterAt builds a limiter reading the supplied clock. Production
// uses the wall clock through newLoginLimiter; tests inject a deterministic
// clock at construction (there is no exported setter — the clock cannot be
// swapped on a live object from outside the package).
func newLoginLimiterAt(now func() time.Time) *loginLimiter {
	return &loginLimiter{
		peers:  map[string]*peerBucket{},
		now:    now,
		argon2: make(chan struct{}, limitGlobalArgon2),
	}
}

// activeForTest reports how many Argon2 release handles are held right now.
// Test-only observation of the ceiling; production never calls it.
func (l *loginLimiter) activeForTest() int {
	return len(l.argon2)
}

// TryAdmitKDF acquires one global Argon2 slot WITHOUT any per-IP bucket
// accounting. The local bootstrap path uses it so its expensive KDF work
// shares the SAME global max-2 admission as login: saturated means fail-fast
// (no queue, no per-IP bucket consumed, no Retry-After hint — the bucket is
// not the blocker). The caller MUST call ReleaseKDF exactly once.
func (l *loginLimiter) TryAdmitKDF() bool {
	select {
	case l.argon2 <- struct{}{}:
		return true
	default:
		return false
	}
}

// ReleaseKDF returns one global Argon2 slot taken by TryAdmitKDF.
func (l *loginLimiter) ReleaseKDF() { <-l.argon2 }

// peerIP extracts the actual socket peer IP from the request's RemoteAddr and
// NORMALIZES it so equivalent IPv4 and IPv4-in-IPv6-mapped forms share ONE
// limiter bucket ("127.0.0.1" and "::ffff:127.0.0.1" are the same host). It
// NEVER consults X-Forwarded-For or any forwarded header.
func peerIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		// To4 collapses a mapped IPv6 form (::ffff:a.b.c.d) to the 4-byte IPv4
		// form, so both spellings of the same peer hash to one bucket. A real
		// IPv6 address is returned in its canonical 16-byte form.
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return host
}

// Allow reports whether one anonymous login attempt from peer is permitted
// under the per-IP bucket AND acquires a global Argon2 slot. When Argon2 is
// saturated it fails fast (no queue). The caller MUST call the returned
// release function exactly once when the Argon2 work completes.
//
// A saturated global gate reports retryAfter = -1: the delay is NOT
// computable for this peer (the bucket is not the blocker), so the caller
// must OMIT Retry-After rather than fabricate one. A bucket refusal always
// reports a positive integer second count.
func (l *loginLimiter) Allow(peer string) (permitted bool, retryAfter int, release func()) {
	release = func() {} // default no-op

	// Per-IP token bucket.
	now := l.now()
	l.mu.Lock()
	b, ok := l.peers[peer]
	if !ok {
		if len(l.peers) >= limitMaxPeers {
			l.mu.Unlock()
			// Table full: reject-new. Report a bounded retry hint (one refill
			// interval) since no peer-specific bucket exists.
			return false, limitRefillSeconds, release
		}
		b = &peerBucket{tokens: limitBurst, last: now}
		l.peers[peer] = b
	}
	// Refill continuously: tokens accrue at 1 per refill interval, capped at
	// burst, measured from the last allowance time.
	elapsed := now.Sub(b.last)
	if elapsed > 0 {
		b.tokens += elapsed.Seconds() / limitRefillSeconds
		if b.tokens > limitBurst {
			b.tokens = limitBurst
		}
		b.last = now
	}
	if b.tokens < 1 {
		// Depleted: integer seconds until the next whole token accrues. The
		// deficit is strictly positive here (tokens < 1), so the ceiling is
		// always >= 1 — a rate-limited answer NEVER fabricates "0".
		deficit := (1 - b.tokens) * limitRefillSeconds
		remaining := int(deficit) + 1 // ceiling of a strictly positive value
		l.mu.Unlock()
		return false, remaining, release
	}
	b.tokens--
	l.mu.Unlock()

	// Global Argon2 semaphore: fail-fast, no queue. The shared helper is the
	// SAME admission the local bootstrap path uses, so login and bootstrap
	// verifications draw from one global max-2 pool.
	if l.TryAdmitKDF() {
		return true, 0, func() { l.ReleaseKDF() }
	}
	// Saturated: the per-IP token was already consumed (the attempt is a real,
	// bounded login try). retryAfter = -1 signals NOT-COMPUTABLE: the caller
	// omits the header instead of inventing a countdown.
	return false, -1, release
}
