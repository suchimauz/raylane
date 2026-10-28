package authhttp

import (
	"encoding/json"
	"net/http"
)

// problem is the generic error body returned to remote callers. It carries a
// machine code, a generic human message and the per-request identifier. It
// NEVER echoes credentials, tokens, origins or any secret/existence detail.
// requestId is REQUIRED by the accepted ErrorResponse contract
// (additionalProperties false, required [code, message, requestId]).
type problem struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId"`
}

// writeProblem writes a JSON problem body with the given status. The message
// is always the caller-supplied generic text; requestID is the per-request
// identifier resolved by the requestIdentity middleware, so every response
// body and its X-Request-Id header agree.
func writeProblem(w http.ResponseWriter, status int, code, message, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Encoding cannot fail for this fixed shape; the error is ignored.
	_ = json.NewEncoder(w).Encode(problem{Code: code, Message: message, RequestID: requestID})
}

// Public error codes and the single generic message per category. The message
// is identical across the login-mismatch, limiter, CSRF and bootstrap
// categories so that no category discloses existence or cause beyond its code.
const (
	codeInvalidCredentials = "invalid_credentials"
	codeRateLimited        = "rate_limited"
	codeBadRequest         = "invalid_request"
	codeForbidden          = "forbidden"
	codeNotFound           = "not_found"
	codePayloadTooLarge    = "payload_too_large"
	codeUnprocessable      = "semantic_validation_failed"
	codeConflict           = "conflict"
	codeServiceUnavailable = "service_unavailable"
	codeInternalError      = "internal_error"

	msgInvalidCredentials = "invalid credentials"
	msgRateLimited        = "too many attempts"
	msgBadRequest         = "invalid request"
	msgForbidden          = "forbidden"
	msgNotFound           = "not found"
	msgPayloadTooLarge    = "request body too large"
	msgUnprocessable      = "semantic validation failed"
	msgConflict           = "conflict"
	msgServiceUnavailable = "service unavailable"
	msgInternalError      = "internal error"
)
