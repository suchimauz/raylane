package authhttp

import "net/http"

// originAllowed reports whether an unsafe-method request carries EXACTLY ONE
// Origin header that equals the configured trusted management origin. Missing,
// empty, "null", MULTIPLE (a trusted value plus a smuggled foreign value) or
// any foreign origin is rejected. Header.Get returns only the first of several
// same-named headers, so a trusted-first/foreign-second pair must be counted,
// not just read. The trusted origin is the configured value — never derived
// from Host, X-Forwarded-Host, X-Forwarded-Proto or Referer.
func originAllowed(r *http.Request, trustedOrigin string) bool {
	values := r.Header.Values("Origin")
	if len(values) != 1 {
		return false
	}
	origin := values[0]
	if origin == "" || origin == "null" {
		return false
	}
	return origin == trustedOrigin
}

// requireOrigin is CSRF middleware for unsafe methods (POST/PUT/PATCH/DELETE).
// It checks Origin BEFORE any session validation. Safe methods (GET/HEAD/...)
// pass through. A rejected request gets 403 csrf_rejected with a generic body
// that never echoes the received origin.
func requireOrigin(trustedOrigin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			next.ServeHTTP(w, r)
			return
		}
		if !originAllowed(r, trustedOrigin) {
			writeProblem(w, http.StatusForbidden, codeForbidden, msgForbidden, requestIDFrom(r.Context()))
			return
		}
		next.ServeHTTP(w, r)
	})
}
