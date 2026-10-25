// auth: protected admission limiter (T008 private unwired primitive).
// Per-peer token buckets plus a global verification-slot cap with
// owner-bound single-use permits, per the accepted R2/R3/R4 contract and
// its ADDENDUM/ERRATA/CORRECTION/OWNER/mask-precedence supplements. Not
// wired to HTTP; it makes no claim about real peer addresses (gate G-8).

package auth

import (
	"crypto/sha256"
	"sync"
	"time"
)

// errAdmissionConfig is the typed configuration failure of
// newAdmissionLimiter: a non-positive burst, refillEvery, maxPeers or
// maxActive, a refillEvery whose seconds-to-duration conversion would
// overflow time.Duration, or a maxPeers above the private structural
// ceiling. No default is applied. Static message; never echoes values.
type errAdmissionConfig struct{}

func (errAdmissionConfig) Error() string {
	return "auth: admission configuration invalid"
}

// errAdmissionPeerKey is the typed failure of allowPeer for the empty
// peer key, so a missing key can never share a bucket. Static message; the
// key is never echoed.
type errAdmissionPeerKey struct{}

func (errAdmissionPeerKey) Error() string {
	return "auth: admission peer key invalid"
}

// errAdmissionPeerLimit is the typed failure of allowPeer when the peer's
// bucket is empty after saturating refill.
type errAdmissionPeerLimit struct{}

func (errAdmissionPeerLimit) Error() string {
	return "auth: admission peer limit reached"
}

// errAdmissionPeerCapacity is the typed failure of allowPeer when a NEW
// peer key arrives while the limiter already holds maxPeers distinct
// keys: existing buckets are never evicted.
type errAdmissionPeerCapacity struct{}

func (errAdmissionPeerCapacity) Error() string {
	return "auth: admission peer capacity reached"
}

// errAdmissionGlobalSaturated is the typed failure of beginVerification
// when all maxActive verification slots are outstanding. Fail-fast: no
// queue, no waiting goroutine.
type errAdmissionGlobalSaturated struct{}

func (errAdmissionGlobalSaturated) Error() string {
	return "auth: admission globally saturated"
}

// errAdmissionPermitReleased is the typed failure of a second release of
// the same permit. It never decrements any counter.
type errAdmissionPermitReleased struct{}

func (errAdmissionPermitReleased) Error() string {
	return "auth: admission permit already released"
}

// errAdmissionPermitNil is the typed failure of releasing a nil permit or
// a permit that was never acquired by any limiter (it carries no owner).
// It never decrements any counter.
type errAdmissionPermitNil struct{}

func (errAdmissionPermitNil) Error() string {
	return "auth: admission permit invalid"
}

// errAdmissionPermitForeign is the typed failure of releasing a permit
// issued by a DIFFERENT limiter. NOTHING changes: not the foreign
// limiter's counter, not this limiter's counter, not the permit's state,
// so the rightful owner can still release the permit exactly once.
type errAdmissionPermitForeign struct{}

func (errAdmissionPermitForeign) Error() string {
	return "auth: admission permit belongs elsewhere"
}

// admissionPrivateMaxPeersCeiling is a NEW PRIVATE structural bound of this
// contract (not a product limit; the policy value 1024 remains a C2
// candidate): maxPeers above it is refused as errAdmissionConfig.
const admissionPrivateMaxPeersCeiling = 65536

// admissionPeerBucket is one peer's token bucket. lastRefill is the last
// observed now value for this bucket; tokens never exceed burst and refill
// arithmetic is saturating, so a large clock jump cannot mint unbounded
// tokens.
type admissionPeerBucket struct {
	tokens     int
	lastRefill time.Time
}

// admissionOwnerID is the Chief-authorized PRIVATE identity wrapper of an
// admission limiter. Shape: pointer to the owning limiter PLUS a private
// comparable value field naming that same limiter; the struct is a
// non-error type with ZERO methods, so it adds nothing to the accepted
// error catalogue (20 new error types / 22 Error methods unchanged).
// IMPORTANT LIMITS OF THIS IDENTITY: it is NOT an independent cryptographic
// secret, and it is NOT a second independent identity channel. It is
// redundant by construction — derived once from the very pointer it
// accompanies — and adds NO independent unpredictability or strength
// beyond that pointer. Its accepted guarantee (P1) is: distinct LIVE
// nonzero-sized limiter allocations never share an identity, and an
// identity is stable for the limiter's lifetime; references from permits
// and identity values retain the owner reachable. NO claim is made about
// eternal address non-reuse after garbage collection, and no GC/runtime
// behaviour is observed or asserted here.
type admissionOwnerID struct {
	limiter *admissionLimiter
}

// admissionLimiter buckets caller-derived opaque peer keys and caps global
// concurrent verifications. maxPeers bounds the COUNT of distinct keys,
// not a byte budget (the byte-budget question is open gate G-3/G-8).
type admissionLimiter struct {
	mu        sync.Mutex
	burst     int
	maxPeers  int
	maxActive int
	interval  time.Duration
	buckets   map[[sha256.Size]byte]*admissionPeerBucket
	active    int
	// ownerID is this limiter's identity, assigned exactly once from the
	// freshly allocated limiter right after allocation. ownerID is NOT an
	// independent cryptographic secret, and ownerID is NOT a second
	// independent identity channel: redundant by construction, no added
	// strength (see admissionOwnerID for the full accepted limits).
	ownerID admissionOwnerID
}

// admissionPermit is an opaque, single-use ownership token for ONE
// acquired global verification slot. It is unexported, has no exported
// fields, can only be created by beginVerification, and carries the
// accepted owner binding: a pointer to the owning limiter PLUS a copy of
// that limiter's private admissionOwnerID value, both stamped only by
// beginVerification. Neither component is a cryptographic secret and the
// pair is not a second independent identity channel (see admissionOwnerID);
// the binding cannot be constructed from outside the package, and there is
// no package-level identity state (globals are forbidden by the accepted
// contract).
type admissionPermit struct {
	owner *admissionLimiter
	// ownerID is the permit's copy of the issuing limiter's private
	// identity value. ownerID is NOT an independent cryptographic secret
	// and NOT a second independent identity channel; redundant with owner
	// by construction (see admissionOwnerID).
	ownerID  admissionOwnerID
	released bool
}

// admissionDurationSeconds converts a positive seconds count to a
// time.Duration saturatingly: reports ok==false when the product would
// overflow, so newAdmissionLimiter can refuse rather than wrap into a tiny
// or negative interval.
func admissionDurationSeconds(seconds int) (time.Duration, bool) {
	const maxSeconds = int64(^uint64(0)>>1) / int64(time.Second)
	if int64(seconds) > maxSeconds {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

// newAdmissionLimiter builds the limiter. UNITS (exact): burst is a count
// of tokens; refillEvery is a COUNT OF SECONDS (not nanoseconds, not a
// time.Duration) — 60 means one token per 60 seconds; maxPeers is a count
// of distinct peer keys; maxActive is a count of concurrently active
// verifications. All four are EXPLICIT parameters with NO default; the
// historically proposed values remain C2 candidates and are NOT adopted.
// Validation: burst > 0, refillEvery > 0, maxPeers > 0 within the private
// ceiling, maxActive > 0, and the saturating duration conversion must
// pass; otherwise (nil, errAdmissionConfig).
func newAdmissionLimiter(burst, refillEvery, maxPeers, maxActive int) (*admissionLimiter, error) {
	if burst <= 0 || refillEvery <= 0 || maxPeers <= 0 || maxActive <= 0 {
		return nil, errAdmissionConfig{}
	}
	if maxPeers > admissionPrivateMaxPeersCeiling {
		return nil, errAdmissionConfig{}
	}
	interval, ok := admissionDurationSeconds(refillEvery)
	if !ok {
		return nil, errAdmissionConfig{}
	}
	l := &admissionLimiter{
		burst:     burst,
		maxPeers:  maxPeers,
		maxActive: maxActive,
		interval:  interval,
		buckets:   make(map[[sha256.Size]byte]*admissionPeerBucket),
	}
	// Assign the identity ONCE, from this freshly allocated limiter. The
	// wrapper is redundant by construction: NOT an independent
	// cryptographic secret, NOT a second independent identity channel.
	l.ownerID = admissionOwnerID{limiter: l}
	return l, nil
}

// allowPeer consumes one unit from the bucket of peerKey. peerKey is an
// OPAQUE, CALLER-DERIVED string: this primitive cannot determine the real
// peer address and cannot reject X-Forwarded-For (obligations of the
// future HTTP adapter, gate G-8). An empty peerKey is refused with
// errAdmissionPeerKey; an empty bucket after saturating refill yields
// errAdmissionPeerLimit; a NEW key at the peer ceiling yields
// errAdmissionPeerCapacity and existing buckets are never evicted.
func (l *admissionLimiter) allowPeer(peerKey string, now time.Time) error {
	if peerKey == "" {
		return errAdmissionPeerKey{}
	}
	key := sha256.Sum256([]byte(peerKey))
	l.mu.Lock()
	defer l.mu.Unlock()
	b, exists := l.buckets[key]
	if !exists {
		if len(l.buckets) >= l.maxPeers {
			return errAdmissionPeerCapacity{}
		}
		// A fresh bucket starts full at burst and consumes one unit now.
		l.buckets[key] = &admissionPeerBucket{tokens: l.burst - 1, lastRefill: now}
		return nil
	}
	// Saturating refill: whole intervals elapsed, tokens clamped to burst.
	if now.After(b.lastRefill) {
		elapsed := now.Sub(b.lastRefill)
		full := int64(elapsed / l.interval)
		if full > 0 {
			if full >= int64(l.burst)-int64(b.tokens) {
				b.tokens = l.burst
			} else {
				b.tokens += int(full)
			}
			advanced := time.Duration(full) * l.interval
			if b.lastRefill.Add(advanced).After(now) {
				b.lastRefill = now
			} else {
				b.lastRefill = b.lastRefill.Add(advanced)
			}
		}
	}
	if b.tokens <= 0 {
		return errAdmissionPeerLimit{}
	}
	b.tokens--
	return nil
}

// beginVerification acquires one of the maxActive global verification
// slots. On success it returns a NON-NIL owner-bound permit and a nil
// error; on refusal it returns a NIL permit and errAdmissionGlobalSaturated
// (fail-fast, no queue). The permit owns exactly one active slot and is
// bound to THIS limiter by the accepted owner shape: the limiter pointer
// plus the limiter's private ownerID value, copied from the owner at issue
// time. Neither component is a cryptographic secret; the pair is the
// accepted pointer-plus-private-ID shape, forgeable only from inside the
// package.
func (l *admissionLimiter) beginVerification() (*admissionPermit, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= l.maxActive {
		return nil, errAdmissionGlobalSaturated{}
	}
	l.active++
	return &admissionPermit{owner: l, ownerID: l.ownerID}, nil
}

// release ends the slot owned by p. OWNER CHECK (exact, before any
// mutation): p must be non-nil (checked BEFORE any lock or dereference);
// then, under THIS limiter's own lock, p must carry THIS limiter's
// identity — p.owner must equal l AND p.ownerID must equal l.ownerID —
// compared BEFORE ANY mutation. A foreign permit returns
// errAdmissionPermitForeign and NOTHING changes — not this limiter's
// counter, not the foreign limiter's counter, not the permit's state — so
// the rightful owner can still release it exactly once. A nil permit
// returns errAdmissionPermitNil. A second release of the same live permit
// returns errAdmissionPermitReleased. Only the single successful release
// sets released and decrements the active counter, which therefore equals
// the number of outstanding correctly-owned permits at all times.
func (l *admissionLimiter) release(p *admissionPermit) error {
	if p == nil {
		return errAdmissionPermitNil{}
	}
	// Permits are created ONLY by beginVerification, which stamps the
	// owner pointer and a copy of the owner's ownerID. The releasing
	// limiter's own lock guards the counter being decremented, and both
	// identity comparisons happen before any mutation.
	l.mu.Lock()
	defer l.mu.Unlock()
	if p.owner != l || p.ownerID != l.ownerID {
		return errAdmissionPermitForeign{}
	}
	if p.released {
		return errAdmissionPermitReleased{}
	}
	p.released = true
	l.active--
	return nil
}
