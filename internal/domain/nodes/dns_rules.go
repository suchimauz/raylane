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

// dnsModeState reads the active dnsMode value. modeOK is true only when the
// value is a valid enum string (auto/tcp/udp/doh). When dnsMode is absent, or
// declared-but-absent (effective default auto), it returns (nil, true) so the
// rules use the auto default. An invalid selector returns (val, false) and the
// rules skip the cross-field cascade.
func dnsModeState(declared map[string]capability.Field, active map[string]any) (val any, ok bool) {
	f, isDecl := declared["dnsMode"]
	if !isDecl {
		return nil, true // no DNS declarations: rules not applied anyway
	}
	_ = f
	raw, present := active["dnsMode"]
	if !present {
		return nil, true // absent -> effective auto default
	}
	s, isStr := raw.(string)
	if !isStr {
		return raw, false // wrong type: typeMismatch already emitted per-field
	}
	switch s {
	case "auto", "tcp", "udp", "doh":
		return raw, true
	}
	return raw, false // invalid enum: enumViolation already emitted per-field
}

// checkDNSRules applies the value-conditional DNS/HE rules for one protocol.
// It adds deterministic, value-free issues to res. active/inactive are the
// caller's maps (never mutated). modeVal is the raw active dnsMode value and
// modeOK whether it was a valid enum string (pre-checked by the per-field
// pass); when the selector is invalid we skip the cross-field cascade to avoid
// misleading duplicate findings for a bad selector.
func checkDNSRules(res *Result, declared map[string]capability.Field, active, inactive map[string]any, modeVal any, modeOK bool) {
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

	// Resolve the EFFECTIVE active mode: absent (or not a declared field)
	// means the authored default "auto". An invalid selector produced its own
	// enum/type issue in the per-field pass; do not cascade further.
	mode := "auto"
	if modeOK {
		if s, ok := modeVal.(string); ok && s != "" {
			mode = s
		}
	} else if modeVal != nil {
		// Invalid selector already reported; skip cross-field rules.
		return
	}

	// Rule 1 (D-046 independent HE): an ACTIVE true happyEyeballs is
	// incompatible with an ACTIVE manual dnsStrategy (non-auto). BOTH fields
	// must be eligible (declared+known+supported+expected type); an unrelated
	// missing companion never disables or invents this rule. An inactive true
	// HE does not disable an active manual strategy.
	if heEligible && strategyEligible && heTrue && strategyManual {
		addIssue(res, IssueDependencyIncompatible, "dnsStrategy")
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
			switch s {
			case "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only":
				return true, true
			}
		}
	}
	return false, true
}
