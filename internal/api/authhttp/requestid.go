package authhttp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

// maxRequestIDLen bounds a client-supplied X-Request-Id. The contract fixes
// 1..128 characters with the pattern ^[A-Za-z0-9._:-]+$ (openapi XRequestId);
// anything empty, longer, or containing a character outside that pattern is
// not conforming client identity and a fresh server identifier is generated
// instead. The value is never a secret and never carries user data.
const maxRequestIDLen = 128

// requestIDKey scopes the per-request identifier in the request context.
type requestIDKey struct{}

// requestIDFrom returns the identifier the requestIdentity middleware
// resolved for this request (generated when absent, validated when
// supplied). Handlers emit exactly this value in X-Request-Id and in every
// error body, so the header and the body always agree.
func requestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok && v != "" {
		return v
	}
	return generateRequestID()
}

// requestIdentity is the outermost middleware on every listener. It resolves
// the request identifier (fresh per request), stores it in the context, sets
// the X-Request-Id response header, and applies the universal non-cacheable
// and content-nosniff posture to every response, before any handler runs.
// It is the ONLY middleware in this package allowed to observe an inbound
// X-Request-Id; every other handler takes the request identity from the
// context.
func requestIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := validRequestID(r.Header.Get("X-Request-Id"))
		if id == "" {
			id = generateRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// validRequestID reports a conforming client-supplied identifier (pattern
// [A-Za-z0-9._:-]+, 1..128 characters) or returns "" to signal "generate a
// fresh one".
func validRequestID(s string) string {
	if s == "" || len(s) > maxRequestIDLen {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if !requestIDByte(s[i]) {
			return ""
		}
	}
	return s
}

func requestIDByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '.', b == '_', b == ':', b == '-':
		return true
	}
	return false
}

// generateRequestID returns a fresh opaque identifier: 12 CSPRNG bytes in
// base64url without padding, prefixed "req-" (16 characters total, inside the
// 128-character bound and inside the header pattern). It is derived from the
// CSPRNG only — never from request data or time.
func generateRequestID() string {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// A CSPRNG failure must not produce an empty or non-conforming id.
		// Retry once; a second failure yields a fixed conforming fallback so
		// the invariant (non-empty, matching pattern) holds on every response.
		if _, err2 := rand.Read(buf[:]); err2 != nil {
			return "req-unavailable"
		}
	}
	return "req-" + base64.RawURLEncoding.EncodeToString(buf[:])
}

// notFoundHandler is the generic 403 for unregistered paths on every
// listener. The LAN has NO bootstrap route and no existence oracle: an
// unknown path and the absent /bootstrap path answer the SAME generic 403, so
// a caller cannot distinguish "route does not exist" from "bootstrap is
// closed". (Settled V4 contract: LAN bootstrap/unknown protected paths are a
// generic 403, not a 404.)
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, http.StatusForbidden, codeForbidden, msgForbidden, requestIDFrom(r.Context()))
}
