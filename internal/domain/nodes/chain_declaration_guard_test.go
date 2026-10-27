package nodes

import (
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
)

// chainPartialProfile parses a minimal VALID profile with only the named chain
// field declarations on a single "probe" protocol. It proves the chain rules
// are declaration-driven: an absent or ineligible companion is never invented
// as a dependency target, and a protocol declaring no chain field is exempt.
func chainPartialProfile(t *testing.T, fields string) *capability.Profile {
	t.Helper()
	raw := `{"profileVersion":2,"protocols":{"probe":{"fields":{` + fields + `}}}}`
	p, err := capability.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("chain partial profile did not parse: %v\nfields=%s", err, fields)
	}
	return p
}

func chainHasIssue(res Result, code IssueCode, field string) bool {
	for _, is := range res.Issues {
		if is.Code == code && is.Field == field {
			return true
		}
	}
	return false
}

// TestChainDeclarationGuard_ModeOnlyNoInventedCompanion: a profile declaring
// ONLY chainMode must not have the rules invent chainNodeId/chainInterface
// dependency targets that the authority does not declare (mirrors DNS guard).
func TestChainDeclarationGuard_ModeOnlyNoInventedCompanion(t *testing.T) {
	modeOnly := chainPartialProfile(t,
		`"chainMode":{"type":"enum","classification":"known","allowedValues":["off","predecessor","final","outbound_interface"]}`)

	// predecessor with no companion declared: must NOT invent dependencyMissing.
	res := Validate(modeOnly, Input{Protocol: "probe", Active: map[string]any{"chainMode": "predecessor"}})
	if chainHasIssue(res, IssueDependencyMissing, "chainNodeId") {
		t.Fatalf("predecessor with no declared chainNodeId: invented dependencyMissing: %+v", res.Issues)
	}
	if chainHasIssue(res, IssueDependencyIncompatible, "chainNodeId") {
		t.Fatalf("predecessor with no declared companion: invented dependencyIncompatible: %+v", res.Issues)
	}
	if res.ChainCheck != ChainCheckNotRequired {
		t.Fatalf("predecessor, no companion declared: ChainCheck=%v, want NotRequired", res.ChainCheck)
	}

	// outbound_interface with no chainInterface declared: must NOT invent.
	res = Validate(modeOnly, Input{Protocol: "probe", Active: map[string]any{"chainMode": "outbound_interface"}})
	if chainHasIssue(res, IssueDependencyMissing, "chainInterface") || chainHasIssue(res, IssueDependencyIncompatible, "chainInterface") {
		t.Fatalf("outbound_interface with no declared chainInterface: invented issue: %+v", res.Issues)
	}
}

// TestChainDeclarationGuard_CompanionDeclaredEligibleTriggersRequirement: when
// the companion IS declared (known string), an active reference mode with no
// active companion is a GENUINE dependencyMissing.
func TestChainDeclarationGuard_CompanionDeclaredEligibleTriggersRequirement(t *testing.T) {
	full := chainPartialProfile(t,
		`"chainMode":{"type":"enum","classification":"known","allowedValues":["off","predecessor","final","outbound_interface"]},`+
			`"chainNodeId":{"type":"string","classification":"known","maxLength":64},`+
			`"chainInterface":{"type":"string","classification":"known","maxLength":64}`)

	// predecessor + declared chainNodeId, no active value -> genuine missing.
	res := Validate(full, Input{Protocol: "probe", Active: map[string]any{"chainMode": "predecessor"}})
	if !chainHasIssue(res, IssueDependencyMissing, "chainNodeId") {
		t.Fatalf("predecessor with declared chainNodeId but no value: want dependencyMissing, got %+v", res.Issues)
	}

	// outbound_interface + declared chainInterface, no active value -> genuine missing.
	res = Validate(full, Input{Protocol: "probe", Active: map[string]any{"chainMode": "outbound_interface"}})
	if !chainHasIssue(res, IssueDependencyMissing, "chainInterface") {
		t.Fatalf("outbound_interface with declared chainInterface but no value: want dependencyMissing, got %+v", res.Issues)
	}
}

// TestChainDeclarationGuard_UnsupportedCompanionNotInvented: an UNSUPPORTED
// declared companion is ineligible and never becomes a dependency target.
func TestChainDeclarationGuard_UnsupportedCompanionNotInvented(t *testing.T) {
	// chainNodeId declared supported=false: predecessor must not invent a
	// dependency target from it.
	p := chainPartialProfile(t,
		`"chainMode":{"type":"enum","classification":"known","allowedValues":["off","predecessor","final"]},`+
			`"chainNodeId":{"type":"string","classification":"known","maxLength":64,"supported":false}`)
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"chainMode": "predecessor"}})
	if chainHasIssue(res, IssueDependencyMissing, "chainNodeId") {
		t.Fatalf("unsupported chainNodeId must not be an invented dependency target: %+v", res.Issues)
	}
}

// TestChainDeclarationGuard_SecretCompanionIneligible: a secret-classified
// chainNodeId is ineligible and never a rule control.
func TestChainDeclarationGuard_SecretCompanionIneligible(t *testing.T) {
	p := chainPartialProfile(t,
		`"chainMode":{"type":"enum","classification":"known","allowedValues":["off","predecessor","final"]},`+
			`"chainNodeId":{"type":"string","classification":"secret","secret":true}`)
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"chainMode": "predecessor"}})
	if chainHasIssue(res, IssueDependencyMissing, "chainNodeId") {
		t.Fatalf("secret chainNodeId must not be a rule control: %+v", res.Issues)
	}
}

// TestChainDeclarationGuard_NoChainFieldsExempt: a profile with no chain field
// at all is exempt from all chain rules (WireGuard-as-source stays unaffected).
func TestChainDeclarationGuard_NoChainFieldsExempt(t *testing.T) {
	p := chainPartialProfile(t, `"server":{"type":"string","classification":"known"}`)
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"server": "x"}})
	if res.ChainCheck != ChainCheckNotRequired {
		t.Fatalf("no chain fields: ChainCheck=%v, want NotRequired", res.ChainCheck)
	}
	if len(res.Issues) != 0 {
		t.Fatalf("no chain fields: unexpected issues %+v", res.Issues)
	}
}

// TestChainDeclarationGuard_ModeWrongTypeNotSelector: a non-enum chainMode
// declaration is not a usable selector; an active chainNodeId under it is a
// stray reference (R3), but no reference-mode requirement is manufactured.
func TestChainDeclarationGuard_ModeWrongTypeNotSelector(t *testing.T) {
	p := chainPartialProfile(t,
		`"chainMode":{"type":"string","classification":"known"},`+
			`"chainNodeId":{"type":"string","classification":"known","maxLength":64}`)
	// chainMode is a string, not an enum -> not a selector (modeActive=false).
	// An ACTIVE chainNodeId under no usable mode is R3 incompatible.
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"chainMode": "predecessor", "chainNodeId": "x"}})
	if !chainHasIssue(res, IssueDependencyIncompatible, "chainNodeId") {
		t.Fatalf("string chainMode with active chainNodeId: want R3 incompatible, got %+v", res.Issues)
	}
}
