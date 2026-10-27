package nodes

import (
	"github.com/suchimauz/raylane/internal/capability"
)

// This file holds the FR-007 credential-intent / trusted-sealed-presence rule
// (D-016/D-043). It runs as an explicit post-pass inside Validate after the
// per-field shape checks, because it depends on the EFFECTIVE ACTIVE authMode
// selector and the TRUSTED sealed-presence booleans (supplied by the store
// boundary, never the submitter). It reuses the closed IssueCode vocabulary (no
// new codes) and reports only the fixed declared path "authMode" — never a
// secret value, a presence value, or any submitted bytes.
//
// Central guarantee: explicit no-auth (none) and user/password (userpass)
// intent is checked for deterministic presence compatibility; legacy PARTIAL
// credentials (exactly one of username/password stored, selector absent) are an
// INVALID but RETAINABLE draft — never silently downgraded to no-auth. Presence
// here is trusted sealed state ONLY; the pure rule certifies presence
// compatibility, never byte validity, content, engine readiness, or successful
// authentication.

// authModeState reads the ACTIVE authMode value against its ACTUAL declared
// metadata and reports the effective selector state. The selector is usable
// only when it is declared AND known/non-secret AND supported-not-false AND
// type enum AND the active value is a string member of its real AllowedValues.
//
// An ineligible (undeclared/secret/unsupported/wrong-type) selector is INERT:
// it never runs the auth-intent demands, INCLUDING when absent — no fallback
// bypasses eligibility. A value outside the declared subset already produced
// enumViolation per-field and is not a usable mode here.
//
// Returns (mode, state): mode is the active value ("" when absent); state is
// one of authSelInert / authSelNone / authSelUserpass / authSelActive (an
// active but unusable value — per-field finding already emitted).
type authSelectorState int

const (
	// authSelInert: no authMode declared at all — the protocol is unaffected by
	// FR-007 (e.g. vless/wireguard as a source).
	authSelInert authSelectorState = iota
	// authSelInertIneligible: an authMode IS declared but is not an eligible enum
	// (secret / unsupported / wrong declared type). It is INERT: no auth demands
	// and no absent-resolution, even when absent — no fallback bypasses
	// eligibility.
	authSelInertIneligible
	// authSelAbsentEligible: an ELIGIBLE enum authMode is declared but is truly
	// ABSENT from the active bucket (compatibility resolution applies, unless
	// present only inactive).
	authSelAbsentEligible
	// authSelActiveUnusable: an ACTIVE value exists but is not a usable member
	// (wrong type / out of subset). Its own per-field finding already fired.
	authSelActiveUnusable
	// authSelNone: explicit ACTIVE "none".
	authSelNone
	// authSelUserpass: explicit ACTIVE "userpass".
	authSelUserpass
)

func authModeState(declared map[string]capability.Field, active map[string]any) (string, authSelectorState) {
	f, isDecl := declared["authMode"]
	if !isDecl {
		return "", authSelInert // not declared: protocol unaffected by FR-007
	}
	// Eligibility BEFORE the absent branch: only an ELIGIBLE enum declaration
	// may act as a selector at all (mirrors dnsModeState/chainModeState). A
	// secret/unsupported/wrong-type declaration is inert even when absent: no
	// fallback bypasses eligibility, and an ineligible absent selector must NOT
	// trigger compatibility resolution.
	if f.Type != "enum" || !authEligible(f, "enum") {
		return "", authSelInertIneligible
	}
	raw, present := active["authMode"]
	if !present {
		return "", authSelAbsentEligible // eligible selector ABSENT -> resolve below
	}
	s, isStr := raw.(string)
	if !isStr {
		return "", authSelActiveUnusable // active null/non-string: typeMismatch already emitted
	}
	for _, a := range f.AllowedValues {
		if s == a {
			if s == "none" {
				return s, authSelNone
			}
			return s, authSelUserpass // the only other in-subset member is "userpass"
		}
	}
	return s, authSelActiveUnusable // out-of-subset value: enumViolation already emitted
}

// authEligible reports whether a declared field may act as the authMode
// selector: known (non-secret), supported-not-false, and of the expected type.
// Mirrors dnsEligible/chainEligible — the declaration guard prevents inventing
// an authority the profile does not actually declare.
func authEligible(f capability.Field, wantType string) bool {
	if f.Classification != "known" {
		return false // secret-classified fields are never the auth selector
	}
	if f.HasSupported && !f.Supported {
		return false // unsupported declarations are inert
	}
	return f.Type == wantType
}

// authEligibleCredential reports whether a declared field counts as a
// credential companion: a SECRET STRING that is supported-not-false. Only such
// fields are legitimate username/password companions; a wrong-type / known /
// unsupported / undeclared field is never an invented credential target, and an
// arbitrary SecretPresence key or plaintext/quarantine name never counts.
func authEligibleCredential(f capability.Field) bool {
	if f.Classification != "secret" {
		return false
	}
	if f.HasSupported && !f.Supported {
		return false
	}
	return f.Type == "string"
}

// authCredentialPresence returns, for every ELIGIBLE credential companion
// (sorted for determinism), whether it has trusted sealed presence. Companions
// are looked up by declaration, never by submitted map keys or arbitrary
// presence names.
func authCredentialPresence(declared map[string]capability.Field, presence map[string]bool) []bool {
	var out []bool
	for _, n := range sortedKeysOf(declared) {
		if authEligibleCredential(declared[n]) {
			out = append(out, presence[n])
		}
	}
	return out
}

// checkAuthRules applies the FR-007 presence-compatibility rule. It consumes
// ONLY the eligible ACTIVE selector and the trusted sealed-presence booleans;
// it never mutates the maps, never reads a secret value, and never echoes a
// byte. declared/active/inactive are the caller's views; presence is trusted.
//
// Deterministic outcomes (existing closed codes, fixed "authMode" path):
//
//   - Explicit ACTIVE "none": coherent with ANY sealed presence — credentials
//     remain sealed/linked/inactive, no clear, GC, promotion, or downgrade.
//   - Explicit ACTIVE "userpass": every eligible credential companion must have
//     trusted true presence; otherwise dependencyMissing on authMode.
//   - Selector present ONLY INACTIVE: preserved, NOT legacy absence — no
//     credential activation, fallback, or demand is run from it.
//   - Selector TRULY ABSENT (neither active nor inactive): compatibility
//     resolution over the eligible credential companions by trusted presence —
//     none present => coherent none; all present => coherent userpass; exactly
//     one present => dependencyMissing on authMode (invalid, retainable draft,
//     never silently no-auth). The inferred effective mode must belong to the
//     selector's ACTUAL enum subset, else dependencyIncompatible on authMode.
//   - Ineligible selector (undeclared/secret/unsupported/wrong-type): inert —
//     no auth demands and no invented credential targets.
func checkAuthRules(res *Result, declared map[string]capability.Field, active, inactive map[string]any, presence map[string]bool) {
	// authMode selector state from the ACTIVE bucket only (an inactive-only
	// selector is preserved, never an activation source).
	_, state := authModeState(declared, active)

	// Credential companions: only declared ELIGIBLE (secret string, supported)
	// fields count, by trusted sealed presence — never submitted keys, plaintext
	// or quarantine names.
	creds := authCredentialPresence(declared, presence)

	_, selInactive := inactive["authMode"]

	switch state {
	case authSelNone:
		// Explicit no-auth: ANY sealed presence is coherent. Credentials are
		// untouched — no clear, no GC, no promotion, no downgrade, no value use.
		return
	case authSelUserpass:
		// Explicit user/password: every eligible credential must be sealed.
		for _, p := range creds {
			if !p {
				addIssue(res, IssueDependencyMissing, "authMode")
				return
			}
		}
		// Zero eligible companions: an auth-only profile invents no demand and no
		// unsupported issue — the mode is simply coherent with nothing to require.
		return
	case authSelActiveUnusable:
		// An active value that failed its own declaration (wrong type / out of
		// subset) already produced its per-field finding; no auth demand runs.
		return
	case authSelInert, authSelInertIneligible:
		// No authMode declared (inert), or an ineligible declaration (secret /
		// unsupported / wrong type): no auth demands and no absent-resolution.
		// An ineligible selector is inert EVEN when absent — no fallback bypasses
		// eligibility, and no companion is invented as a credential target.
		return
	case authSelAbsentEligible:
		// An ELIGIBLE selector is truly ABSENT from the active bucket. A selector
		// present ONLY INACTIVE is NOT legacy absence: preserve it and run no
		// auth-intent demands from it (no activation, fallback, or demand).
		if selInactive {
			return
		}
		// TRULY ABSENT (neither bucket, not quarantined): compatibility
		// resolution over the eligible credential companions by trusted presence.
		resolveAbsentAuthMode(res, declared, creds)
	}
}

// resolveAbsentAuthMode applies the truly-absent compatibility resolution. With
// zero eligible companions there is nothing to resolve (no demand, no invented
// target). Otherwise count the trusted-presence split: none present => coherent
// none; all present => coherent userpass; exactly one present (a legacy PARTIAL
// credential pair) => dependencyMissing on authMode — an invalid, retainable
// draft, never silently downgraded to no-auth. The inferred effective mode must
// itself be a member of the selector's ACTUAL enum subset, else
// dependencyIncompatible on authMode (never invent a disallowed mode).
func resolveAbsentAuthMode(res *Result, declared map[string]capability.Field, creds []bool) {
	if len(creds) == 0 {
		return // no eligible companions => no auth demands
	}
	present := 0
	for _, p := range creds {
		if p {
			present++
		}
	}
	var inferred string
	switch {
	case present == 0:
		inferred = "none"
	case present == len(creds):
		inferred = "userpass"
	default:
		// Legacy partial pair: invalid, retainable, never silent no-auth.
		addIssue(res, IssueDependencyMissing, "authMode")
		return
	}
	// The inferred effective mode must belong to the selector's ACTUAL enum
	// subset; an excluded inferred mode is refused, never silently invented.
	f := declared["authMode"]
	for _, a := range f.AllowedValues {
		if a == inferred {
			return // coherent compatibility, no issue
		}
	}
	addIssue(res, IssueDependencyIncompatible, "authMode")
}
