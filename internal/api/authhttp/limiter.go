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
// RetryAfter is the integer seconds until the bucket next refills a token
// (0 when a token is available now but Argon2 is saturated; the per-IP bucket
// is not the blocker then).
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
		// Depleted: integer seconds until the next whole token accrues.
		deficit := (1 - b.tokens) * limitRefillSeconds
		remaining := int(deficit + 0.9999) // round up to a positive integer
		if remaining < 1 {
			remaining = 1
		}
		l.mu.Unlock()
		return false, remaining, release
	}
	b.tokens--
	l.mu.Unlock()

	// Global Argon2 semaphore: fail-fast, no queue.
	select {
	case l.argon2 <- struct{}{}:
		release = func() { <-l.argon2 }
		return true, 0, release
	default:
		// Saturated: the per-IP token was already consumed (the attempt is a
		// real, bounded login try), and there is no per-IP retry hint because
		// the bucket is not the blocker. Return permitted=false with a zero
		// Retry-After (omitted when not computable).
		return false, 0, release
	}
}
