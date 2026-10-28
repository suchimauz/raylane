package nodes

import (
	"github.com/suchimauz/raylane/internal/capability"
)

// This file holds the v4-US1-T011 mux-vision ACTIVE combination rule (FR-003
// minimal obligation, settled parent decisions FINAL). It runs as an explicit
// post-pass inside Validate, after the per-field generic checks, because it
// depends on the effective ACTIVE values of three fields against each field's
// OWN declared metadata.
//
// Rule (vless only). When ALL of the following hold on an otherwise-submitted
// VLESS document, the draft is refused for apply with EXACTLY ONE existing
// static value-free dependencyIncompatible on the declared concurrency path —
// the Validate tail then yields Invalid/notApplicable and preserves the exact
// input/raw document and maps:
//
//   - muxEnabled: independently eligible (declared, known/nonsecret,
//     supported-not-false, exact declared type "boolean"), actually present in
//     ACTIVE, actual bool true.
//   - flow: independently eligible (declared, known, supported-not-false, exact
//     declared type "enum"), actually present in ACTIVE, actual string admitted
//     by its OWN declared AllowedValues, exactly "xtls-rprx-vision" OR
//     "xtls-rprx-vision-udp443".
//   - concurrency: independently eligible (declared, known, supported-not-false,
//     exact declared type "integer"), actually present in ACTIVE, and passes its
//     OWN ordinary shape and bounds (reusing valueOK / asInt — no new parser,
//     no float conversion); the exact integer is >= 0.
//
// Rationale (D-016 / pinned upstream 1b1647cd): ordinary concurrency is a Go
// int16; when a mux block is ENABLED, an ordinary concurrency of zero
// (including an omitted scalar in an enabled emitted block) defaults upstream
// to 8 and positive constructs an ordinary manager, both unsafe for an active
// Vision flow. An exact integer >= 0 therefore cannot be faithfully emitted as
// a safe enabled Vision mux. This is a structural validator fact, NOT an
// engine/handshake/readiness certification.
//
// Silent combination controls (ordinary diagnostics and existing aggregates
// still apply; each participant's OWN bad value/declaration suppresses only
// THIS rule, never other rules):
//
//   - muxEnabled false / absent / inactive-only / wrong-type / ineligible;
//   - flow empty / absent / inactive-only / outside own enum / ineligible;
//   - concurrency absent / inactive-only / wrong shape / out of bounds /
//     negative (negative is ordinarily legal and disables) / ineligible;
//   - any actual non-vless protocol (even a custom trusted profile reusing all
//     names) never receives this product-specific rule;
//   - xudpConcurrency is NOT part of this condition: no positive-only
//     requirement, no prohibition of zero/negative, no invented dependency. It
//     keeps its independent signed-int16 generic domain.
//
// It never mutates the maps, never reads a secret value, and never echoes a
// byte. It does NOT reset Status or any prior aggregate (ChainCheck /
// StructuredCheck) — the added issue is folded into the main Validate tail.

// muxVisionFlowValues are the two ACTIVE flow enum spellings that make an
// enabled mux unsafe with an ordinary concurrency of exact integer >= 0.
var muxVisionFlowValues = map[string]bool{
	"xtls-rprx-vision":        true,
	"xtls-rprx-vision-udp443": true,
}

// checkMuxVisionRules adds the single combination issue when every participant
// is independently eligible and the combination is met. It reads only the
// effective ACTIVE values and each field's OWN declaration — never a secret,
// never an unrelated protocol, never a name hardcode inventing authority.
func checkMuxVisionRules(res *Result, protocol string, declared map[string]capability.Field, active map[string]any) {
	if protocol != "vless" {
		return // product-specific rule never leaks into another protocol
	}
	if !muxVisionEligibleBool(declared, active, "muxEnabled") {
		return
	}
	if !muxVisionEligibleFlow(declared, active, "flow") {
		return
	}
	cv, ok := muxVisionEligibleConcurrency(declared, active, "concurrency")
	if !ok || cv < 0 {
		return // absent / wrong shape / out of bounds / negative (disables) -> silent
	}
	addIssue(res, IssueDependencyIncompatible, "concurrency")
}

// muxVisionEligibleField reports whether name is independently eligible: it is
// declared, known/nonsecret, supported-not-false, and has the exact declared
// type want. A name hardcode alone never invents authority.
func muxVisionEligibleField(declared map[string]capability.Field, name, wantType string) (capability.Field, bool) {
	f, ok := declared[name]
	if !ok {
		return capability.Field{}, false
	}
	if f.Classification != "known" {
		return capability.Field{}, false // secret fields never participate as values
	}
	if f.HasSupported && !f.Supported {
		return capability.Field{}, false // supported=false is ineligible (omitted supported stays eligible)
	}
	if f.Type != wantType {
		return capability.Field{}, false
	}
	return f, true
}

// muxVisionEligibleBool reports whether name is an eligible declared boolean
// actually present in ACTIVE with actual bool true.
func muxVisionEligibleBool(declared map[string]capability.Field, active map[string]any, name string) bool {
	if _, ok := muxVisionEligibleField(declared, name, "boolean"); !ok {
		return false
	}
	v, present := active[name]
	if !present {
		return false
	}
	b, isBool := v.(bool)
	return isBool && b
}

// muxVisionEligibleFlow reports whether name is an eligible declared enum
// actually present in ACTIVE whose actual string is admitted by its OWN
// declared AllowedValues and equals one of the two Vision spellings.
func muxVisionEligibleFlow(declared map[string]capability.Field, active map[string]any, name string) bool {
	f, ok := muxVisionEligibleField(declared, name, "enum")
	if !ok {
		return false
	}
	v, present := active[name]
	if !present {
		return false
	}
	s, isStr := v.(string)
	if !isStr {
		return false
	}
	admitted := false
	for _, a := range f.AllowedValues {
		if a == s {
			admitted = true
			break
		}
	}
	if !admitted {
		return false // outside own enum -> ordinary enumViolation handles it; rule silent
	}
	return muxVisionFlowValues[s]
}

// muxVisionEligibleConcurrency reports whether name is an eligible declared
// integer actually present in ACTIVE that passes its OWN ordinary shape and
// bounds, returning the exact integer. It reuses valueOK + asInt (no new
// parser, no float conversion): a wrong shape or out-of-bounds value returns
// ok=false and the rule stays silent (the ordinary issue is already reported
// by the per-field check).
func muxVisionEligibleConcurrency(declared map[string]capability.Field, active map[string]any, name string) (int64, bool) {
	f, ok := muxVisionEligibleField(declared, name, "integer")
	if !ok {
		return 0, false
	}
	v, present := active[name]
	if !present {
		return 0, false
	}
	if valid, _ := valueOK(f, v); !valid {
		return 0, false // own bad shape/bounds -> ordinary issue only, no conditional duplicate
	}
	cv, isInt := asInt(v)
	if !isInt {
		return 0, false // exact integer required (whole value); fractions handled above
	}
	return cv, true
}
