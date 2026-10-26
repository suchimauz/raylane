// Package api hosts the API-side boundaries that are testable without a
// server: the allowlisted read/diagnostic projection described by D1. It is
// deliberately NOT HTTP wiring — no handlers, routes or sockets live here.
//
// The capability authority itself (profile model, parser, projection and
// diagnostics) lives in internal/capability. This package keeps thin
// compatibility aliases and delegating wrappers so existing consumers and
// tests continue to work against ONE parser — there is deliberately no second
// copy of the model or the parse logic.
package api

import (
	"github.com/suchimauz/raylane/internal/capability"
)

// Compatibility aliases: the authority types are re-exported so callers that
// imported api.Profile / api.ProjectedNode / api.DiagnosticCode keep working.
type (
	// Profile is the validated classification authority (alias for
	// capability.Profile).
	Profile = capability.Profile
	// ProjectedNode is the safe public projection (alias).
	ProjectedNode = capability.ProjectedNode
	// Diagnostic is one projected diagnostic entry (alias).
	Diagnostic = capability.Diagnostic
	// DiagnosticCode is the closed vocabulary of diagnostic facts (alias).
	DiagnosticCode = capability.DiagnosticCode
)

// Re-exported closed-vocabulary diagnostic codes (aliases, same values).
const (
	DiagConfigParseFailed = capability.DiagConfigParseFailed
	DiagApplyPending      = capability.DiagApplyPending
	DiagSecretMissing     = capability.DiagSecretMissing
)

// Re-exported typed errors. errors.Is works against both the api alias and the
// capability sentinel because they are the SAME error values.
var (
	ErrProfileRejected = capability.ErrProfileRejected
	ErrProtocolUnknown = capability.ErrProtocolUnknown
)

// SecretUnchangedSentinel is the exact reserved string refused on a
// SecretUpdate replace operation (contracts/openapi.yaml SecretUpdate). Only
// an exact match is refused; mask-lookalikes are legitimate secret values.
const SecretUnchangedSentinel = "__RAYLANE_SECRET_UNCHANGED_V1__"

// SecretUpdateIsReservedSentinel identifies whether a candidate SecretUpdate
// replace value is the reserved sentinel. Exact match only.
func SecretUpdateIsReservedSentinel(candidate string) bool {
	return candidate == SecretUnchangedSentinel
}

// ParseCapabilityProfile validates the authored capability-profile bytes and
// indexes them for projection. It delegates to the single authority in
// internal/capability; there is no separate api-side parser.
func ParseCapabilityProfile(raw []byte) (*Profile, error) {
	return capability.Parse(raw)
}

// ProjectNodeFields is the allowlisted read projection. It delegates to the
// authority's method on the shared Profile value.
func ProjectNodeFields(p *Profile, protocol string, fields map[string]any, presence map[string]bool, inactive map[string]bool) (ProjectedNode, error) {
	if p == nil {
		return ProjectedNode{}, ErrProfileRejected
	}
	return p.ProjectNodeFields(protocol, fields, presence, inactive)
}

// BuildDiagnostic projects the supplied closed-vocabulary codes under the
// caller-fixed protocol. It delegates to the authority.
func BuildDiagnostic(p *Profile, protocol string, codes []DiagnosticCode) map[string]Diagnostic {
	if p == nil {
		return map[string]Diagnostic{}
	}
	return p.BuildDiagnostic(protocol, codes)
}
