package nodes

import "github.com/suchimauz/raylane/internal/capability"

// This file holds the FR-003 structured-object readiness rule (D-014/D-015/
// D-016/D-050). It runs as an explicit post-pass inside Validate, after the
// per-field generic shape checks, because it depends on the EFFECTIVE ACTIVE
// values of the structured-object targets (xhttpExtra/finalMask) and, for the
// xhttp mode decision, the ACTIVE transport selector.
//
// Purpose (FR-003): a real JSON object value for xhttpExtra/finalMask is a
// valid SHAPE (see the "object" case in valueOK), but an ACTIVE opaque object
// whose real engine-compatibility checker does not exist must NEVER become
// apply-ready. This rule reports that honestly through Result.StructuredCheck:
//   - No ACTIVE eligible target            -> StructuredCheckNotRequired (no gate).
//   - ACTIVE eligible target, shape valid  -> StructuredCheckNotRun (structurally
//     Valid but NOT applicable; Ready is reserved for a future real checker).
//   - eligible xhttpExtra + usable transport offering xhttp but active transport
//     is a real member of its own AllowedValues that is NOT "xhttp" -> exactly
//     ONE static dependencyIncompatible@xhttpExtra + StructuredCheckFailed.
//
// It reuses the closed IssueCode vocabulary (no new codes), reports only
// DECLARED field paths (never a submitted value), never mutates the maps, and
// never reads a secret. It is protocol-scoped by the ACTUAL input protocol and
// exact declared field: vless.xhttpExtra, vless.finalMask, wireguard.finalMask.
// These product readiness/mode rules must NOT leak into socks5/http/custom
// protocol declarations that happen to reuse the field names.
//
// This is pure domain validation, NOT actual saving or an editor/engine
// implementation: readiness here is not engine/handshake/network/crypto proof.

// structuredTarget reports whether one declared field is an ELIGIBLE structured
// target for this rule: independently DECLARED known NON-SECRET supported-not-
// false, type OBJECT, and ACTIVE-present. The ACTUAL protocol + exact declared
// field guard is applied by the caller (checkStructuredRules) before this is
// consulted, so the readiness/mode rules never leak into other protocols.
//
// Returns (field, present, eligible): present reports an ACTIVE key; eligible
// reports the declaration gate above. An ineligible declaration (secret /
// supported=false / wrong type) leaves ordinary generic diagnostics and yields
// StructuredCheckNotRequired — this rule never manufactures a demand from a
// declaration that failed its own gate. Inactive/absent is never promoted.
func structuredTarget(declared map[string]capability.Field, active map[string]any, name string) (capability.Field, bool, bool) {
	f, isDecl := declared[name]
	if !isDecl {
		return capability.Field{}, false, false // not declared: no readiness target
	}
	if !structuredEligible(f) {
		return f, false, false // secret/unsupported/wrong-type declaration is inert
	}
	_, present := active[name]
	return f, present, true
}

// structuredEligible reports whether a declared field may act as a structured
// readiness target: known (non-secret), supported-not-false, type object.
// Mirrors transportEligible/dnsEligible/chainEligible/authEligible — the
// declaration guard prevents inventing an authority the profile does not
// actually declare.
func structuredEligible(f capability.Field) bool {
	if f.Classification != "known" {
		return false // secret-classified fields are never structured targets
	}
	if f.HasSupported && !f.Supported {
		return false // unsupported declarations are inert
	}
	return f.Type == "object"
}

// checkStructuredRules applies the FR-003 structured-object readiness rule.
// It consumes ONLY the effective ACTIVE values (each independently eligible and
// shape-valid) and the ACTIVE transport selector for the xhttp mode decision;
// it never mutates the maps, never reads a secret value, and never echoes a
// byte. protocol is the ACTUAL input protocol (hard scope guard).
//
// Aggregate (F): StructuredCheckFailed dominates StructuredCheckNotRun when
// both an eligible target has a bad shape/decided conflict and another is an
// active opaque object. Any NotRun/Failed only reduces APPLICABILITY (below);
// it NEVER resets Status to Valid when issues exist, and NEVER overwrites a
// prior ChainCheck outcome (the two aggregates are independent).
func checkStructuredRules(res *Result, protocol string, declared map[string]capability.Field, active map[string]any) {
	res.StructuredCheck = StructuredCheckNotRequired

	// Hard protocol scope: only these ACTUAL (protocol, field) pairs are
	// structured readiness targets. A socks5/http/custom protocol that declares
	// a same-named field is NOT a target (D-050 scope).
	vlessXHTTPExtra, hasVlessXHTTPExtra := false, false
	vlessFinalMask, hasVlessFinalMask := false, false
	wgFinalMask, hasWGFinalMask := false, false
	switch protocol {
	case "vless":
		_, vlessXHTTPExtra, hasVlessXHTTPExtra = structuredTarget(declared, active, "xhttpExtra")
		_, vlessFinalMask, hasVlessFinalMask = structuredTarget(declared, active, "finalMask")
	case "wireguard":
		_, wgFinalMask, hasWGFinalMask = structuredTarget(declared, active, "finalMask")
	}

	// xhttp mode decision (D-050): an eligible ACTIVE valid-shape vless.xhttpExtra
	// requires the ACTUAL ACTIVE transport selector to be a real member of its
	// OWN declared AllowedValues. If the real authority offers xhttp and the
	// active usable transport is NOT "xhttp", that is ONE static
	// dependencyIncompatible@xhttpExtra (Failed). A transport whose
	// AllowedValues excludes xhttp, an absent/inactive/bad selector, or an
	// out-of-enum selector does NOT manufacture an unavailable-mode demand.
	xhttpConflict := false
	if vlessXHTTPExtra && hasVlessXHTTPExtra && activeObjectShapeOK(declared, active, "xhttpExtra") {
		if transportOffersXHTTPButActiveIsNot(declared, active) {
			xhttpConflict = true
			addIssue(res, IssueDependencyIncompatible, "xhttpExtra")
		}
	}

	// Readiness aggregate over the eligible ACTIVE shape-valid targets. Each
	// such opaque object lacks a real engine-compat checker -> NotRun. FinalMask
	// (vless/wireguard) never fabricates a mode pairing and never emits an issue.
	anyNotRun := false
	if vlessXHTTPExtra && hasVlessXHTTPExtra && activeObjectShapeOK(declared, active, "xhttpExtra") && !xhttpConflict {
		anyNotRun = true // eligible active valid-shape opaque object, no real checker
	}
	if vlessFinalMask && hasVlessFinalMask && activeObjectShapeOK(declared, active, "finalMask") {
		anyNotRun = true
	}
	if wgFinalMask && hasWGFinalMask && activeObjectShapeOK(declared, active, "finalMask") {
		anyNotRun = true
	}

	switch {
	case xhttpConflict:
		// A decided structured conflict dominates NotRun (F).
		res.StructuredCheck = StructuredCheckFailed
	case anyNotRun:
		res.StructuredCheck = StructuredCheckNotRun
	default:
		res.StructuredCheck = StructuredCheckNotRequired
	}

	// Applicability: NotRun/Failed reduce Applicable but NEVER change Status and
	// NEVER overwrite a prior ChainCheck outcome. Status/invalid is owned by the
	// issue count (an issue makes Status Invalid + not applicable in the main
	// Validate tail); a NotRun with zero issues leaves Status Valid but not
	// applicable.
	if res.StructuredCheck == StructuredCheckFailed || res.StructuredCheck == StructuredCheckNotRun {
		res.Applicable = false
	}
}

// activeObjectShapeOK reports whether an eligible ACTIVE target's value passed
// its own generic object shape check (a real non-nil map). The generic type
// check already ran in the per-field loop; a wrong-typed value already produced
// its typeMismatch and is not shape-valid, so this rule adds nothing for it
// (generic-first, no duplicate). Read directly — the value is opaque content,
// never inspected leaf-by-leaf.
func activeObjectShapeOK(declared map[string]capability.Field, active map[string]any, name string) bool {
	raw, present := active[name]
	if !present {
		return false
	}
	m, ok := raw.(map[string]any)
	return ok && m != nil
}

// transportOffersXHTTPButActiveIsNot implements the xhttp mode decision. It
// returns true only when BOTH hold:
//  1. the transport field is a USABLE enum selector (independently declared
//     known/non-secret/supported, ACTIVE present, value a real string member of
//     its OWN declared AllowedValues), AND
//  2. that declared AllowedValues actually contains "xhttp" (the real authority
//     offers xhttp), AND
//  3. the active usable transport value is NOT "xhttp".
//
// If the real AllowedValues excludes xhttp, the mode is unavailable and this
// rule does NOT demand it (no manufactured demand for an unavailable mode). An
// absent/inactive/bad/out-of-enum selector keeps the rule silent.
func transportOffersXHTTPButActiveIsNot(declared map[string]capability.Field, active map[string]any) bool {
	f, isDecl := declared["transport"]
	if !isDecl {
		return false
	}
	if f.Type != "enum" || !structuredEnumEligible(f) {
		return false
	}
	raw, present := active["transport"]
	if !present {
		return false
	}
	s, isStr := raw.(string)
	if !isStr {
		return false
	}
	member := false
	offersXHTTP := false
	for _, a := range f.AllowedValues {
		if a == s {
			member = true
		}
		if a == "xhttp" {
			offersXHTTP = true
		}
	}
	if !member {
		return false // out-of-enum value already produced enumViolation; not usable
	}
	return offersXHTTP && s != "xhttp"
}

// structuredEnumEligible is the enum-selector declaration guard for the xhttp
// mode decision: known (non-secret), supported-not-false, type enum.
func structuredEnumEligible(f capability.Field) bool {
	if f.Classification != "known" {
		return false
	}
	if f.HasSupported && !f.Supported {
		return false
	}
	return f.Type == "enum"
}
