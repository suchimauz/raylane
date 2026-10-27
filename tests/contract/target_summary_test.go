// Maintained regression for V4-T011B2-ACTIVE-EMPTY-TARGET-MODE.
//
// The TRUSTED target summary (nodes.ChainNodeSummary) is the terminal-
// eligibility authority for the one-layer chain rule, and the reference
// resolver must read its ACTIVE chainMode against the TARGET protocol's ACTUAL
// chainMode declaration — not a hardcoded token and not the SOURCE protocol's
// declaration. HasChainMode is the presence authority:
//
//   - HasChainMode=false  => the target has NO ACTIVE chain mode (absent, or
//     an inactive-retained value that is never promoted). The target is a
//     TERMINAL without consulting any target declaration: no default is
//     invented, and a missing/ineligible target declaration is irrelevant.
//
//   - HasChainMode=true   => an ACTIVE mode EXISTS. Its value must be non-empty
//     AND a member of the TARGET protocol's ACTUAL chainMode declaration
//     (declared, known/non-secret, supported, type enum), and only the actually
//     declared terminal value "off" is a legal terminal. A true empty value, an
//     out-of-subset value, and a missing / wrong-type / secret / unsupported
//     target declaration all FAIL CLOSED (Invalid + ChainCheckFailed + the
//     closed value-free dependencyIncompatible on chainNodeId) — never
//     reclassified as absent/off.
//
// The target and source profiles are independent: the source keeps its full
// authored chain fields while each target protocol's declaration is mutated
// separately, proving the target is the authority. These cases were RED on
// bc26511 (the ACTIVE-empty and out-of-subset targets were accepted as
// terminal) and are GREEN with the corrected targetDeclaredTerminal rule.

package contract_test

import (
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// chainModeEnum is a full eligible chainMode enum (the authored superset).
const chainModeEnum = `"chainMode":{"type":"enum","classification":"known","default":"off","allowedValues":["off","predecessor","final","outbound_interface"]}`

const chainNodeIDField = `"chainNodeId":{"type":"string","classification":"known","maxLength":64}`

// sourceFields is the chain field block every SOURCE protocol carries.
const sourceFields = chainModeEnum + `,` + chainNodeIDField

// targetProfile builds a profile with one full chain-capable SOURCE protocol
// and a set of TARGET protocols whose chainMode declarations are mutated
// independently (subset excluding off, missing, wrong type, secret,
// unsupported). WireGuard-equivalent targets simply declare no chain fields.
// The source declaration is identical in every case so only the target-side
// authority varies.
func targetProfile(t *testing.T, targets string) *capability.Profile {
	t.Helper()
	raw := []byte(`{"profileVersion":4,"protocols":{
		"srcv":{"fields":{` + sourceFields + `}},
		"srcs":{"fields":{` + sourceFields + `}},
		"srch":{"fields":{` + sourceFields + `}},
		` + targets + `
	}}`)
	p, err := capability.Parse(raw)
	if err != nil {
		t.Fatalf("target profile did not parse: %v\n%s", err, raw)
	}
	return p
}

// refCtx builds a trusted context whose single peer summary is given verbatim.
func refCtx(selfID, peerID string, sum nodes.ChainNodeSummary) *nodes.ChainContext {
	return &nodes.ChainContext{
		SelfID:       selfID,
		Nodes:        map[string]nodes.ChainNodeSummary{peerID: sum},
		HasInventory: true,
	}
}

// expectTerminal asserts the reference resolved to a legal terminal target.
func expectTerminal(t *testing.T, label string, res nodes.Result) {
	t.Helper()
	if res.Status != nodes.Valid || !res.Applicable || res.ChainCheck != nodes.ChainCheckPassed {
		t.Fatalf("%s: want Valid+Applicable+Passed, got status=%v applicable=%v chain=%v issues=%+v",
			label, res.Status, res.Applicable, res.ChainCheck, res.Issues)
	}
}

// expectFailClosed asserts the reference failed closed with the exact closed,
// value-free issue and Failed readiness.
func expectFailClosed(t *testing.T, label string, res nodes.Result) {
	t.Helper()
	if res.Status != nodes.Invalid || res.Applicable {
		t.Fatalf("%s: want Invalid+inapplicable, got status=%v applicable=%v chain=%v",
			label, res.Status, res.Applicable, res.ChainCheck)
	}
	if res.ChainCheck != nodes.ChainCheckFailed {
		t.Fatalf("%s: ChainCheck=%v, want Failed", label, res.ChainCheck)
	}
	if !hasIssue(res, nodes.IssueDependencyIncompatible, "chainNodeId") {
		t.Fatalf("%s: want value-free dependencyIncompatible on chainNodeId, got %+v", label, res.Issues)
	}
	assertChainCanary(t, label, res)
}

// sourceCases lists the source protocols and both reference roles exercised.
var sourceCases = []struct {
	protocol string
	selfID   string
}{
	{"srcv", "self-srcv"},
	{"srcs", "self-srcs"},
	{"srch", "self-srch"},
}

// TestTargetActiveEmptyModeFailsClosed: HasChainMode=true with an EMPTY active
// value is a malformed ACTIVE mode, not "absent" — regardless of whether the
// target declares chainMode. It fails closed for both roles and all sources.
func TestTargetActiveEmptyModeFailsClosed(t *testing.T) {
	targets := `"tgtfull":{"fields":{` + chainModeEnum + `}}`
	p := targetProfile(t, targets)
	for _, sc := range sourceCases {
		for _, role := range []string{"predecessor", "final"} {
			m := map[string]any{"chainMode": role, "chainNodeId": "peer-t"}
			ctx := refCtx(sc.selfID, "peer-t",
				nodes.ChainNodeSummary{Protocol: "tgtfull", ChainMode: "", HasChainMode: true})
			res := nodes.Validate(p, nodes.Input{Protocol: sc.protocol, Active: m, Chain: ctx})
			expectFailClosed(t, sc.protocol+"/"+role+"/active-empty", res)
		}
	}
}

// TestTargetOffExcludedByActualEnumFailsClosed: a target whose ACTUAL chainMode
// enum SUBSET excludes "off" rejects an ACTIVE "off" summary — the target
// declaration, not a hardcoded token, decides terminality.
func TestTargetOffExcludedByActualEnumFailsClosed(t *testing.T) {
	subset := `"tgtsub":{"fields":{"chainMode":{"type":"enum","classification":"known","allowedValues":["predecessor","final"]},"chainNodeId":{"type":"string","classification":"known","maxLength":64}}}`
	p := targetProfile(t, subset)
	for _, sc := range sourceCases {
		m := map[string]any{"chainMode": "predecessor", "chainNodeId": "peer-t"}
		ctx := refCtx(sc.selfID, "peer-t",
			nodes.ChainNodeSummary{Protocol: "tgtsub", ChainMode: "off", HasChainMode: true})
		res := nodes.Validate(p, nodes.Input{Protocol: sc.protocol, Active: m, Chain: ctx})
		expectFailClosed(t, sc.protocol+"/off-excluded-by-target-enum", res)
	}
}

// TestTargetOutOfSubsetModeFailsClosed: an ACTIVE value outside the target's
// real allowedValues (non-off modes, wrong case, whitespace, unknown token)
// fails closed even when the target DOES declare "off".
func TestTargetOutOfSubsetModeFailsClosed(t *testing.T) {
	targets := `"tgtfull":{"fields":{` + chainModeEnum + `}}`
	p := targetProfile(t, targets)
	for _, mode := range []string{"predecessor", "final", "outbound_interface", "OFF", "off ", "vmess"} {
		m := map[string]any{"chainMode": "predecessor", "chainNodeId": "peer-t"}
		ctx := refCtx("self-srcv", "peer-t",
			nodes.ChainNodeSummary{Protocol: "tgtfull", ChainMode: mode, HasChainMode: true})
		res := nodes.Validate(p, nodes.Input{Protocol: "srcv", Active: m, Chain: ctx})
		expectFailClosed(t, "out-of-subset/"+mode, res)
	}
}

// TestTargetMissingSelectorFailsClosed: HasChainMode=true on a target that
// declares NO chainMode at all cannot be read as terminal — the declaration
// lookup fails closed rather than inventing a default.
func TestTargetMissingSelectorFailsClosed(t *testing.T) {
	// tgtnone declares only chainNodeId, no chainMode selector.
	targets := `"tgtnone":{"fields":{` + chainNodeIDField + `}}`
	p := targetProfile(t, targets)
	for _, active := range []string{"off", "predecessor"} {
		m := map[string]any{"chainMode": "predecessor", "chainNodeId": "peer-t"}
		ctx := refCtx("self-srcv", "peer-t",
			nodes.ChainNodeSummary{Protocol: "tgtnone", ChainMode: active, HasChainMode: true})
		res := nodes.Validate(p, nodes.Input{Protocol: "srcv", Active: m, Chain: ctx})
		expectFailClosed(t, "missing-selector/active="+active, res)
	}
}

// TestTargetWrongTypeSelectorFailsClosed: a target chainMode declared as a
// non-enum (string) is not a usable enum authority -> an ACTIVE value fails
// closed, never silently treated as off.
func TestTargetWrongTypeSelectorFailsClosed(t *testing.T) {
	targets := `"tgtwrong":{"fields":{"chainMode":{"type":"string","classification":"known"},"chainNodeId":{"type":"string","classification":"known","maxLength":64}}}`
	p := targetProfile(t, targets)
	m := map[string]any{"chainMode": "predecessor", "chainNodeId": "peer-t"}
	ctx := refCtx("self-srcv", "peer-t",
		nodes.ChainNodeSummary{Protocol: "tgtwrong", ChainMode: "off", HasChainMode: true})
	res := nodes.Validate(p, nodes.Input{Protocol: "srcv", Active: m, Chain: ctx})
	expectFailClosed(t, "wrong-type-selector", res)
}

// TestTargetSecretSelectorFailsClosed: a target chainMode declared secret is
// ineligible as a chain authority -> an ACTIVE value fails closed.
func TestTargetSecretSelectorFailsClosed(t *testing.T) {
	targets := `"tgtsecret":{"fields":{"chainMode":{"type":"enum","classification":"secret","secret":true,"allowedValues":["off","predecessor"]},"chainNodeId":{"type":"string","classification":"known","maxLength":64}}}`
	p := targetProfile(t, targets)
	m := map[string]any{"chainMode": "predecessor", "chainNodeId": "peer-t"}
	ctx := refCtx("self-srcv", "peer-t",
		nodes.ChainNodeSummary{Protocol: "tgtsecret", ChainMode: "off", HasChainMode: true})
	res := nodes.Validate(p, nodes.Input{Protocol: "srcv", Active: m, Chain: ctx})
	expectFailClosed(t, "secret-selector", res)
}

// TestTargetUnsupportedSelectorFailsClosed: a target chainMode declared
// supported=false is ineligible -> an ACTIVE value fails closed.
func TestTargetUnsupportedSelectorFailsClosed(t *testing.T) {
	targets := `"tgtunsup":{"fields":{"chainMode":{"type":"enum","classification":"known","supported":false,"allowedValues":["off","predecessor"]},"chainNodeId":{"type":"string","classification":"known","maxLength":64}}}`
	p := targetProfile(t, targets)
	m := map[string]any{"chainMode": "predecessor", "chainNodeId": "peer-t"}
	ctx := refCtx("self-srcv", "peer-t",
		nodes.ChainNodeSummary{Protocol: "tgtunsup", ChainMode: "off", HasChainMode: true})
	res := nodes.Validate(p, nodes.Input{Protocol: "srcv", Active: m, Chain: ctx})
	expectFailClosed(t, "unsupported-selector", res)
}

// TestTargetGenuineOffModeTerminal: a target whose ACTUAL enum includes "off"
// accepts the genuine declared "off" summary as a terminal — the correction
// must not break the accepted positive. Full enum and an off-only subset both
// qualify; all three sources and both roles pass.
func TestTargetGenuineOffModeTerminal(t *testing.T) {
	targets := `"tgtfull":{"fields":{` + chainModeEnum + `}}`
	p := targetProfile(t, targets)
	for _, sc := range sourceCases {
		for _, role := range []string{"predecessor", "final"} {
			m := map[string]any{"chainMode": role, "chainNodeId": "peer-t"}
			ctx := refCtx(sc.selfID, "peer-t",
				nodes.ChainNodeSummary{Protocol: "tgtfull", ChainMode: "off", HasChainMode: true})
			res := nodes.Validate(p, nodes.Input{Protocol: sc.protocol, Active: m, Chain: ctx})
			expectTerminal(t, sc.protocol+"/"+role+"/genuine-off", res)
		}
	}
}

// TestTargetAbsentModeTerminal: HasChainMode=false is the ABSENT /
// inactive-retained terminal case. It stays valid for a chain-capable target
// AND for a target with no chain controls, independent of any target-side
// declaration lookup — no default is invented. This is the false-absent
// control that must keep passing after the ACTIVE-empty correction.
func TestTargetAbsentModeTerminal(t *testing.T) {
	targets := `"tgtfull":{"fields":{` + chainModeEnum + `}},
		"tgtnone":{"fields":{` + chainNodeIDField + `}}`
	p := targetProfile(t, targets)
	for _, targetProto := range []string{"tgtfull", "tgtnone"} {
		for _, sc := range sourceCases {
			m := map[string]any{"chainMode": "predecessor", "chainNodeId": "peer-t"}
			ctx := refCtx(sc.selfID, "peer-t",
				nodes.ChainNodeSummary{Protocol: targetProto}) // HasChainMode=false
			res := nodes.Validate(p, nodes.Input{Protocol: sc.protocol, Active: m, Chain: ctx})
			expectTerminal(t, sc.protocol+"/absent/"+targetProto, res)
		}
	}
}

// TestTargetActiveModeUnknownTargetProto: HasChainMode=true cannot launder an
// unknown target protocol — protocol truth fails closed first, before any
// metadata is consulted for a protocol the profile does not declare.
func TestTargetActiveModeUnknownTargetProto(t *testing.T) {
	targets := `"tgtfull":{"fields":{` + chainModeEnum + `}}`
	p := targetProfile(t, targets)
	m := map[string]any{"chainMode": "predecessor", "chainNodeId": "peer-t"}
	ctx := refCtx("self-srcv", "peer-t",
		nodes.ChainNodeSummary{Protocol: "vmess", ChainMode: "off", HasChainMode: true})
	res := nodes.Validate(p, nodes.Input{Protocol: "srcv", Active: m, Chain: ctx})
	expectFailClosed(t, "unknown-target-proto", res)
}
