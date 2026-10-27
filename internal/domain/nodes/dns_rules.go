package nodes

import "github.com/suchimauz/raylane/internal/capability"

// This file holds the FR-004 value-conditional DNS/Happy-Eyeballs cross-field
// rules (D-019/D-020/D-046). They run as an explicit post-pass inside Validate
// after per-field shape checks, because they depend on the EFFECTIVE active
// dnsMode and the active-valid/active-invalid/inactive split of the resolver
// fields. They reuse the closed IssueCode vocabulary (no new codes) and report
// only declared field paths — never a submitted value.

// dnsFieldView is the small view of one DNS-related field the rules need.
type dnsFieldView struct {
	declared bool
	eligible bool // declared + known + supported + expected scalar type
	// activeValid: present in active AND passed shape grammar this run.
	activeValid bool
	// activePresent: present in active (shape may or may not have passed).
	activePresent bool
	// inactivePresent: present in the inactive bucket (preserved).
	inactivePresent bool
}

// anyDNSFieldDeclared reports whether the profile declares ANY of the
// participating DNS/HE fields. A profile with none of them is exempt from the
// cross-field rules entirely (the ordinary unknown-field path handles any
// submitted keys).
func anyDNSFieldDeclared(declared map[string]capability.Field) bool {
	for _, n := range []string{"dnsMode", "dnsServer", "dnsServerUrl", "happyEyeballs", "dnsStrategy"} {
		if _, ok := declared[n]; ok {
			return true
		}
	}
	return false
}

// dnsModeState reads the active dnsMode value against its ACTUAL declared
// metadata. It returns the effective mode and whether the selector is USABLE
// (eligible enum whose value is a member of the field's real AllowedValues).
//
// A field is a usable enum selector only when it is eligible (declared+known+
// supported) AND declared with type "enum". A boolean/string/secret/unsupported
// declaration is NOT an enum selector: the ordinary per-field validator reports
// the field's own finding (typeMismatch/secretPlaintextSubmitted/
// unsupportedField) and the mode-dependent resolver rules stay silent — they
// never manufacture a demand from a value that failed its own declaration.
//
// When the selector is absent, the effective default "auto" applies (no value
// is inserted; absent stays raw-distinct from an explicit "auto"). When the
// selector is present but unusable (wrong declared type, ineligible, or a value
// outside the declared AllowedValues subset), usable is false and the resolver
// rules skip; membership is defined by the actual metadata, not a token list.
func dnsModeState(declared map[string]capability.Field, active map[string]any) (mode string, usable bool) {
	f, isDecl := declared["dnsMode"]
	if !isDecl {
		return "auto", false // no selector declared: no mode-dependent rules
	}
	raw, present := active["dnsMode"]
	if !present {
		return "auto", true // absent -> effective auto default (not inserted)
	}
	// A non-enum declaration is not a selector; the ordinary validator already
	// reported the value's own type finding. Do not act as an enum selector.
	if f.Type != "enum" || !dnsEligible(f, "enum") {
		return "", false
	}
	s, isStr := raw.(string)
	if !isStr {
		return "", false // non-string active value: typeMismatch already emitted
	}
	// Membership by the field's ACTUAL AllowedValues (same authority valueOK
	// uses); a value outside the declared subset is unusable for the resolver
	// rules and already produced enumViolation per-field.
	for _, a := range f.AllowedValues {
		if s == a {
			return s, true
		}
	}
	return "", false
}

// checkDNSRules applies the value-conditional DNS/HE rules for one protocol.
// It adds deterministic, value-free issues to res. active/inactive are the
// caller's maps (never mutated). mode/modeUsable come from dnsModeState: mode
// is the effective active selector value ("auto" when absent) and modeUsable
// is whether that selector is an ELIGIBLE enum whose value is a member of the
// field's ACTUAL AllowedValues. When modeUsable is false the mode-dependent
// resolver rules are skipped — a selector that failed its own declaration
// (wrong declared type, ineligible, or out-of-subset value) must not cascade a
// resolver demand. The independent HE rule is NOT gated on modeUsable.
func checkDNSRules(res *Result, declared map[string]capability.Field, active, inactive map[string]any, mode string, modeUsable bool) {
	// These rules apply only when at least one DNS/HE field is declared for
	// this protocol. WireGuard (and any profile lacking ALL of them) is not
	// subjected to invented DNS issues. The independent HE rule does not need
	// dnsMode or a resolver companion declared; it only needs the HE and
	// strategy fields themselves, gated by their own eligibility below.
	if !anyDNSFieldDeclared(declared) {
		return
	}
	server := dnsView(res, declared, active, inactive, "dnsServer", "string", dnsServerOK)
	serverURL := dnsView(res, declared, active, inactive, "dnsServerUrl", "string", dnsServerUrlOK)
	heTrue, heEligible := dnsHEView(declared, active)
	strategyManual, strategyEligible := dnsStrategyView(declared, active)

	// Rule 1 (D-046 independent HE): an ACTIVE true happyEyeballs is
	// incompatible with an ACTIVE manual dnsStrategy (non-auto). BOTH fields
	// must be eligible (declared+known+supported+expected type); an unrelated
	// missing companion or an unusable mode selector never disables or invents
	// this rule. An inactive true HE does not disable an active manual strategy.
	if heEligible && strategyEligible && heTrue && strategyManual {
		addIssue(res, IssueDependencyIncompatible, "dnsStrategy")
	}

	// Mode-dependent resolver rules: skipped entirely when the selector is not
	// usable (wrong declared type, ineligible, or out-of-subset value). Such a
	// selector already produced its own ordinary per-field finding and must not
	// manufacture a resolver demand. Absent selector => effective auto (handled
	// by dnsModeState); a no-dnsMode profile yields modeUsable=false and skips
	// only these resolver rules, never the HE rule above.
	if !modeUsable {
		return
	}

	// Resolver requirements per effective mode. A companion requirement fires
	// ONLY when that companion is ELIGIBLE (declared+known+supported+expected
	// type). An absent/ineligible companion is never invented as a dependency
	// target. The active-companion incompatibility likewise fires only for an
	// ELIGIBLE active companion; an ineligible active key already produced its
	// own ordinary (unknown/support/type) finding.
	switch mode {
	case "auto":
		// Rule 7 (auto): no resolver required; an ACTIVE ELIGIBLE resolver is
		// incompatible. An ineligible active key is handled by the ordinary
		// validator; an explicitly INACTIVE resolver is allowed/retained.
		if server.eligible && server.activePresent {
			addIssue(res, IssueDependencyIncompatible, "dnsServer")
		}
		if serverURL.eligible && serverURL.activePresent {
			addIssue(res, IssueDependencyIncompatible, "dnsServerUrl")
		}
	case "tcp", "udp":
		// Rule 6: active tcp/udp requires an ACTIVE VALID dnsServer, but ONLY
		// when dnsServer is an eligible companion declaration. When eligible,
		// missing/inactive-only/invalid-active never satisfies; "present but
		// invalid" already emitted its shape finding, so only absent/inactive
		// adds dependencyMissing. An ACTIVE ELIGIBLE dnsServerUrl is
		// incompatible; an inactive or ineligible one is retained.
		if server.eligible {
			if !server.activeValid && !server.activePresent {
				addIssue(res, IssueDependencyMissing, "dnsServer")
			}
		}
		if serverURL.eligible && serverURL.activePresent {
			addIssue(res, IssueDependencyIncompatible, "dnsServerUrl")
		}
	case "doh":
		// Rule 7: active doh requires an ACTIVE VALID dnsServerUrl, but ONLY
		// when dnsServerUrl is an eligible companion declaration. An ACTIVE
		// ELIGIBLE dnsServer is incompatible; an inactive or ineligible one is
		// retained.
		if serverURL.eligible {
			if !serverURL.activeValid && !serverURL.activePresent {
				addIssue(res, IssueDependencyMissing, "dnsServerUrl")
			}
		}
		if server.eligible && server.activePresent {
			addIssue(res, IssueDependencyIncompatible, "dnsServer")
		}
	}
}

// dnsView builds the resolver field view. A field is ELIGIBLE only when it is
// declared AND known AND supported AND of the expected scalar type. The
// cross-field rules may consume/report ONLY eligible fields: an undeclared,
// unsupported, secret-classified, or wrong-declaration-type field is never an
// invented dependency target, and its submitted active key is already handled
// by the ordinary validator (unknown/support/type findings). shapeOK is the
// precise grammar predicate; a field is activeValid only when present in
// active AND passing grammar. An ACTIVE resolver that is eligible but fails
// precise grammar emits a single value-free pattern issue here. Inactive
// presence is recorded for retention but never promoted.
func dnsView(res *Result, declared map[string]capability.Field, active, inactive map[string]any, name string, wantType string, shapeOK func(string) bool) dnsFieldView {
	f, isDecl := declared[name]
	if !isDecl {
		return dnsFieldView{} // not declared: never a rule target
	}
	v := dnsFieldView{declared: true, eligible: dnsEligible(f, wantType)}
	if val, ok := active[name]; ok {
		v.activePresent = true
		// Only an ELIGIBLE active field participates in grammar/dependency
		// semantics. An ineligible active key (unsupported/secret/wrong type)
		// produced its own ordinary finding already; do not inspect or
		// double-report it here.
		if v.eligible {
			if s, isStr := val.(string); isStr {
				if shapeOK(s) {
					v.activeValid = true
				} else {
					addIssue(res, IssuePatternViolation, name)
				}
			}
		}
	}
	if _, ok := inactive[name]; ok {
		v.inactivePresent = true
	}
	return v
}

// dnsEligible reports whether a declared field may participate in the DNS
// cross-field rules: known (not secret), supported, and of the expected
// scalar type. This is the declaration guard — it prevents inventing
// dependency targets the authority does not actually declare as usable.
func dnsEligible(f capability.Field, wantType string) bool {
	if f.Classification != "known" {
		return false // secret-classified fields are never DNS rule controls
	}
	if f.HasSupported && !f.Supported {
		return false // unsupported fields are not eligible requirement targets
	}
	return f.Type == wantType
}

// dnsHEView / dnsStrategyView report eligibility-gated active views. An
// ineligible (undeclared/unsupported/secret/wrong-type) HE or strategy field
// never triggers the independent-HE incompatibility.

// dnsHEView reports whether an ELIGIBLE declared happyEyeballs boolean is
// active-and-true. An ineligible field (undeclared/unsupported/secret/wrong
// declared type) never triggers the independent-HE rule. A non-bool active
// value already produced its own per-field type finding; it is not "true".
func dnsHEView(declared map[string]capability.Field, active map[string]any) (activeTrue, eligible bool) {
	f, ok := declared["happyEyeballs"]
	if !ok || !dnsEligible(f, "boolean") {
		return false, false
	}
	if val, present := active["happyEyeballs"]; present {
		if b, isBool := val.(bool); isBool {
			return b, true
		}
	}
	return false, true
}

// dnsStrategyView reports whether an ELIGIBLE declared dnsStrategy enum is
// ACTIVE with a manual (non-auto) value. An ineligible field never triggers
// the rule. An invalid strategy token already produced enumViolation per-field
// and is not treated as a manual strategy here (no misleading cascade).
func dnsStrategyView(declared map[string]capability.Field, active map[string]any) (activeManual, eligible bool) {
	f, ok := declared["dnsStrategy"]
	if !ok || !dnsEligible(f, "enum") {
		return false, false
	}
	if val, present := active["dnsStrategy"]; present {
		if s, isStr := val.(string); isStr && s != "" && s != "auto" {
			// "Manual" means a NON-auto value that is a MEMBER of the field's
			// ACTUAL AllowedValues (the same authority valueOK uses). A token
			// outside the declared subset already produced enumViolation per-field
			// and is not treated as a manual strategy here (no cascade).
			for _, a := range f.AllowedValues {
				if s == a {
					return true, true
				}
			}
		}
	}
	return false, true
}
