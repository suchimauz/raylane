package nodes

import "github.com/suchimauz/raylane/internal/capability"

// This file holds the FR-004 value-conditional DNS/Happy-Eyeballs cross-field
// rules (D-019/D-020/D-046). They run as an explicit post-pass inside Validate
// after per-field shape checks, because they depend on the EFFECTIVE active
// dnsMode and the active-valid/active-invalid/inactive split of the resolver
// fields. They reuse the closed IssueCode vocabulary (no new codes) and report
// only declared field paths — never a submitted value.

// dnsField is the small view of one DNS-related field the rules need.
type dnsFieldView struct {
	declared bool
	// activeValid: present in active AND passed shape grammar this run.
	activeValid bool
	// activePresent: present in active (shape may or may not have passed).
	activePresent bool
	// inactivePresent: present in the inactive bucket (preserved).
	inactivePresent bool
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
	// These rules apply only when the DNS fields are declared for this
	// protocol. WireGuard (and any profile lacking the declarations) is not
	// subjected to invented DNS issues.
	if _, ok := declared["dnsMode"]; !ok {
		return
	}
	server := dnsView(res, declared, active, inactive, "dnsServer", dnsServerOK)
	serverURL := dnsView(res, declared, active, inactive, "dnsServerUrl", dnsServerUrlOK)
	he := dnsBoolView(active, "happyEyeballs")
	strategy := dnsStrategyView(active)

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
	// incompatible with an ACTIVE manual dnsStrategy (non-auto). An INACTIVE
	// true HE does not disable an active manual strategy. Wrong types were
	// already reported per-field; here we only pair a true HE with a manual
	// strategy.
	if he.activeTrue && strategy.activeManual {
		addIssue(res, IssueDependencyIncompatible, "dnsStrategy")
	}

	// Resolver requirements per effective mode.
	switch mode {
	case "auto":
		// Rule 7 (auto): no resolver required; an ACTIVE resolver is
		// incompatible. An explicitly INACTIVE resolver is allowed/retained.
		if server.activePresent {
			addIssue(res, IssueDependencyIncompatible, "dnsServer")
		}
		if serverURL.activePresent {
			addIssue(res, IssueDependencyIncompatible, "dnsServerUrl")
		}
	case "tcp", "udp":
		// Rule 6: active tcp/udp requires an ACTIVE VALID dnsServer. Missing,
		// inactive-only, or invalid-active never satisfies. An ACTIVE
		// dnsServerUrl is incompatible; an inactive one is retained.
		if !server.activeValid {
			// Distinguish "present but invalid" (already reported by shape)
			// from "absent / only inactive" (a real dependency gap). Only the
			// latter adds dependencyMissing.
			if !server.activePresent {
				addIssue(res, IssueDependencyMissing, "dnsServer")
			}
		}
		if serverURL.activePresent {
			addIssue(res, IssueDependencyIncompatible, "dnsServerUrl")
		}
	case "doh":
		// Rule 7: active doh requires an ACTIVE VALID dnsServerUrl. An ACTIVE
		// dnsServer is incompatible; an inactive one is retained.
		if !serverURL.activeValid {
			if !serverURL.activePresent {
				addIssue(res, IssueDependencyMissing, "dnsServerUrl")
			}
		}
		if server.activePresent {
			addIssue(res, IssueDependencyIncompatible, "dnsServer")
		}
	}
}

// dnsView builds the resolver field view. shapeOK is the precise grammar
// predicate; a field is activeValid only when present in active AND passing
// grammar. When an ACTIVE resolver fails precise grammar, a single value-free
// pattern issue is emitted here (the profile pattern is only the generic
// projection shape gate and is intentionally permissive; precise grammar is a
// domain rule). An active field that fails grammar is "present but not
// satisfying" for dependency purposes, without double-reporting.
func dnsView(res *Result, declared map[string]capability.Field, active, inactive map[string]any, name string, shapeOK func(string) bool) dnsFieldView {
	f, isDecl := declared[name]
	if !isDecl {
		return dnsFieldView{}
	}
	_ = f
	v := dnsFieldView{declared: true}
	if val, ok := active[name]; ok {
		v.activePresent = true
		if s, isStr := val.(string); isStr {
			if shapeOK(s) {
				v.activeValid = true
			} else {
				addIssue(res, IssuePatternViolation, name)
			}
		}
		// A non-string active resolver already produced typeMismatch per-field.
	}
	if _, ok := inactive[name]; ok {
		v.inactivePresent = true
	}
	return v
}

// dnsBoolView reports whether happyEyeballs is present-and-true in active.
// Wrong types were already reported per-field; a non-bool true is impossible.
func dnsBoolView(active map[string]any, name string) struct{ activeTrue bool } {
	out := struct{ activeTrue bool }{}
	if val, ok := active[name]; ok {
		if b, isBool := val.(bool); isBool && b {
			out.activeTrue = true
		}
	}
	return out
}

// dnsStrategyView reports whether an ACTIVE manual (non-auto) dnsStrategy is
// present. An invalid strategy token already produced enumViolation per-field;
// it is not treated as a manual strategy here to avoid a misleading cascade.
func dnsStrategyView(active map[string]any) struct{ activeManual bool } {
	out := struct{ activeManual bool }{}
	if val, ok := active["dnsStrategy"]; ok {
		if s, isStr := val.(string); isStr && s != "" && s != "auto" {
			switch s {
			case "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only":
				out.activeManual = true
			}
		}
	}
	return out
}
