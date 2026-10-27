package nodes

import "github.com/suchimauz/raylane/internal/capability"

// This file holds the FR-002 structural REALITY/transport compatibility rule
// (D-009..D-012/D-016). It runs as an explicit post-pass inside Validate after
// the per-field shape checks, because it depends on the EFFECTIVE ACTIVE values
// of BOTH the transport and security selectors. It reuses the closed IssueCode
// vocabulary (no new codes) and reports only the declared field path
// "transport" — never a submitted value.
//
// Structural fact (pinned Xray conf-transport.go, T001 checks 27..28): the
// REALITY security builder supports only tcp/splithttp/grpc transports, so the
// canonical transport choices mkcp, ws and httpupgrade are structurally
// incompatible with security=reality. This pure rule rejects exactly those
// three ACTIVE pairs. It does NOT validate TLS/REALITY content, keys, flow,
// handshake, or engine readiness, and it does not remove any transport choice,
// downgrade security, or rewrite/drop/default/promote any value.

// transportSelector reads one selector's ACTIVE value against its ACTUAL
// declared metadata and reports whether it is USABLE for the cross-rule. A
// selector is usable only when it is independently DECLARED known NON-SECRET
// supported-not-false type ENUM, and its ACTIVE value is an actual string that
// is a member of the field's real AllowedValues.
//
// A field that is undeclared, secret, unsupported, or of the wrong declared
// type is NOT a usable enum selector: the ordinary per-field validator reports
// the field's own finding (unknownField / secretPlaintextSubmitted /
// unsupportedField / typeMismatch) and this cross-rule stays silent — it never
// manufactures a demand from a selector that failed its own declaration, and an
// ineligible declaration cannot infer authority even when absent. A value
// outside the declared AllowedValues subset already produced enumViolation and
// is likewise unusable here (membership is defined by the actual metadata, not
// a token list). Absent/inactive-only selectors are never promoted.
//
// Returns (value, usable): value is the active string ("" when absent or
// non-string); usable reports the eligibility + membership gate above.
func transportSelector(declared map[string]capability.Field, active map[string]any, name string) (string, bool) {
	f, isDecl := declared[name]
	if !isDecl {
		return "", false // not declared: protocol unaffected by this cross-rule
	}
	// Eligibility BEFORE the value branch: only an ELIGIBLE enum declaration may
	// act as a selector at all (mirrors dnsEligible/chainEligible/authEligible).
	if f.Type != "enum" || !transportEligible(f) {
		return "", false // secret/unsupported/wrong-type declaration is inert
	}
	raw, present := active[name]
	if !present {
		return "", false // absent: no inactive promotion, no fallback/default
	}
	s, isStr := raw.(string)
	if !isStr {
		return "", false // active null/non-string: typeMismatch already emitted
	}
	for _, a := range f.AllowedValues {
		if s == a {
			return s, true
		}
	}
	return s, false // out-of-subset value: enumViolation already emitted
}

// transportEligible reports whether a declared field may act as a
// transport/security selector: known (non-secret), supported-not-false, type
// enum. Mirrors dnsEligible/chainEligible/authEligible — the declaration guard
// prevents inventing an authority the profile does not actually declare.
func transportEligible(f capability.Field) bool {
	if f.Classification != "known" {
		return false // secret-classified fields are never transport/security selectors
	}
	if f.HasSupported && !f.Supported {
		return false // unsupported declarations are inert
	}
	return f.Type == "enum"
}

// checkTransportRules applies the FR-002 structural REALITY/transport
// compatibility rule. It consumes ONLY the two effective ACTIVE selector values
// (each independently eligible and a member of its own ACTUAL AllowedValues);
// it never mutates the maps, never reads a secret value, and never echoes a
// byte.
//
// When BOTH selectors are usable and security is "reality" while transport is
// one of the structurally refused canonical choices {mkcp, ws, httpupgrade},
// exactly ONE static value-free IssueDependencyIncompatible is added on the
// declared path "transport". The existing invalid/applicable logic owns status
// (an issue makes the node Invalid and not-applicable). No literal protocol
// blanket, no default, no fallback, no inactive promotion: an ineligible,
// absent, or out-of-subset selector keeps the rule silent, and the ordinary
// generic issues (required/type/enum/unsupported/plaintext/collision) remain
// ordinary without an invented conditional duplicate.
func checkTransportRules(res *Result, declared map[string]capability.Field, active map[string]any) {
	transport, transportOK := transportSelector(declared, active, "transport")
	security, securityOK := transportSelector(declared, active, "security")
	if !transportOK || !securityOK {
		return // both selectors must be independently usable; else stay silent
	}
	if security != "reality" {
		return // TLS and any non-reality security impose no structural transport bar
	}
	switch transport {
	case "mkcp", "ws", "httpupgrade":
		// Structurally incompatible ACTIVE REALITY pair (D-009..D-012). One
		// static value-free issue on the declared transport path; raw is
		// preserved and the node is an invalid, retainable draft.
		addIssue(res, IssueDependencyIncompatible, "transport")
	}
}
