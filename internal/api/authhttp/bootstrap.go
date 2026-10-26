package authhttp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// errNoLiveToken is the internal signal that no live bootstrap token exists.
// Token redemption failures (expired/consumed/unknown/mismatched) all map to
// the SAME generic public response, never an expiry/existence oracle.
var errNoLiveToken = errors.New("authhttp: no live bootstrap token")

// bootstrapIssuer issues and redeems the local one-time bootstrap token. At
// most ONE token is live at a time; a token is invalid after process restart
// (the issuer is RAM-only). The raw token is returned to the caller exactly
// once at issuance and is never stored — only its SHA-256 digest and expiry.
type bootstrapIssuer struct {
	mu      sync.Mutex
	digest  [sha256.Size]byte
	expires time.Time
	now     func() time.Time
}

func newBootstrapIssuer() *bootstrapIssuer {
	return newBootstrapIssuerAt(time.Now)
}

// newBootstrapIssuerAt builds an issuer reading the supplied clock.
// Production uses the wall clock; tests inject a deterministic clock at
// construction.
func newBootstrapIssuerAt(now func() time.Time) *bootstrapIssuer {
	return &bootstrapIssuer{now: now}
}

// Issue creates a fresh 32-byte CSPRNG token (base64url, no padding), invalid
// any prior token (at most one live token), and returns the raw token plus
// its TTL. The raw token appears only here, in the protected issuance
// response.
func (i *bootstrapIssuer) Issue() (raw string, ttl time.Duration, err error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", 0, err
	}
	digest := sha256.Sum256(buf[:])
	now := i.now()
	i.mu.Lock()
	defer i.mu.Unlock()
	i.digest = digest
	i.expires = now.Add(bootstrapTokenTTL)
	return base64.RawURLEncoding.EncodeToString(buf[:]), bootstrapTokenTTL, nil
}

// Redeem validates a presented raw token against the single live token: the
// digest must match and the token must not be expired. On success the token
// is consumed (no second redemption) and it returns true. Every failure —
// expired, consumed, unknown, mismatched — returns false (the SAME generic
// category at the caller).
func (i *bootstrapIssuer) Redeem(raw string) bool {
	digest, ok := digestOf(raw)
	if !ok {
		return false
	}
	now := i.now()
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.expires.IsZero() {
		return false // nothing issued
	}
	if !now.Before(i.expires) {
		return false // expired: TTL is 300 s from issuance, so the token is
		// INVALID at the exact expiry instant (now >= expires), not only after.
	}
	if digest != i.digest {
		return false // mismatched
	}
	// Consume: exactly one winner; clear the live token.
	i.digest = [sha256.Size]byte{}
	i.expires = time.Time{}
	return true
}

// HasLive reports whether a live (issued, unexpired) token exists. It is used
// to enforce at-most-one-live-token on the issuance path without consuming.
func (i *bootstrapIssuer) HasLive() bool {
	now := i.now()
	i.mu.Lock()
	defer i.mu.Unlock()
	return !i.expires.IsZero() && now.Before(i.expires)
}
