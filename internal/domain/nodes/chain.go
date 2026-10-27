package nodes

import (
	"strings"

	"github.com/suchimauz/raylane/internal/capability"
)

// This file holds the FR-006 one-layer chain validation rules (D-022/D-023/
// D-047). They run as an explicit post-pass inside Validate after the per-field
// shape checks, because they depend on the EFFECTIVE active chainMode and the
// TRUSTED chain context (self id, peer inventory, interface inventory) supplied
// by the caller — NEVER on submitted document values. They reuse the closed
// IssueCode vocabulary (no new codes) and report only declared field paths.
//
// Honesty is the central rule: a required reference/interface check that cannot
// run because its trusted context is missing is reported as ChainCheckNotRun
// (and makes the node inapplicable), NEVER as a silent PASS. A node is only
// applicable when every chain check it requires actually ran and passed.

// ChainCheckStatus is the honest aggregate outcome of the chain/reference and
// interface checks for one node. It is deliberately NOT a boolean so a caller
// can never read "Valid" as "references checked": NotRun and NotRequired are
// distinct from Passed.
type ChainCheckStatus int

const (
	// ChainCheckNotRequired: the node declares no active chain requirement
	// (no chain fields, or chainMode absent/off, or only inactive companions).
	// The chain rules do not gate this node's validity or applicability.
	ChainCheckNotRequired ChainCheckStatus = iota
	// ChainCheckNotRun: an active eligible reference or interface mode requires
	// trusted context (SelfID, inventory, or interface inventory) that was not
	// supplied. The required check could NOT run. This is NOT a pass: the node
	// stays structurally Valid but is NOT applicable for apply.
	ChainCheckNotRun
	// ChainCheckPassed: every chain check the node requires ran and passed.
	ChainCheckPassed
	// ChainCheckFailed: a chain check ran and produced an issue; the node is
	// Invalid and not applicable.
	ChainCheckFailed
)

// String returns a stable, value-free label for logs/tests.
func (s ChainCheckStatus) String() string {
	switch s {
	case ChainCheckNotRequired:
		return "not_required"
	case ChainCheckNotRun:
		return "not_run"
	case ChainCheckPassed:
		return "passed"
	case ChainCheckFailed:
		return "failed"
	}
	return "unknown"
}

// ChainContext is the TRUSTED, read-only context the chain rules need. It is
// assembled by the caller (the store boundary) from the saved/active node
// inventory — NEVER from the submitted document. A nil Chain or an absent
// inventory disables only the checks that need it (honest NotRun), never
// manufactures a PASS.
type ChainContext struct {
	// SelfID is this node's own trusted identity (empty for a not-yet-stored
	// node). An empty SelfID disables only the self-edge sub-check.
	SelfID string
	// Nodes maps a node id to its TRUSTED chain summary for every OTHER known
	// node. Values are trusted summaries, never submitted fields.
	Nodes map[string]ChainNodeSummary
	// HasInventory reports whether a reference inventory was actually available
	// in this context. false => the reference checks CANNOT run (NotRun).
	HasInventory bool
	// Interfaces is the TRUSTED set of known outbound interface names. nil =>
	// interface membership is NOT validated (configuration-only).
	Interfaces []string
	// HasInterfaceInventory reports whether a trusted interface inventory was
	// supplied. false => the interface membership check is NotRun.
	HasInterfaceInventory bool
}

// ChainNodeSummary is the TRUSTED summary of a referenced node. It has EXACTLY
// these fields — no second reference field is needed.
type ChainNodeSummary struct {
	// Protocol is the referenced node's protocol. It must be a protocol the
	// authored profile declares (R9'/target-protocol rule).
	Protocol string
	// ChainMode is the referenced node's ACTIVE chain mode ("" = absent).
	ChainMode string
	// HasChainMode reports whether the referenced node has an ACTIVE chain mode
	// present. An inactive retained chain mode does NOT count as active.
	HasChainMode bool
}

// chainFieldView is the small eligibility-gated view of one chain field.
type chainFieldView struct {
	declared bool
	eligible bool // declared + known + supported + expected scalar type
	// activePresent: present in the active bucket (shape may or may not pass).
	activePresent bool
	// activeValid: present in active AND a non-empty string within maxLength.
	activeValid bool
	// inactivePresent: present in the inactive bucket (retained, never promoted).
	inactivePresent bool
	// value is the active string value; consumed ONLY for membership/self
	// comparison, never echoed into a result.
	value string
}

// anyChainFieldDeclared reports whether the profile declares ANY of the
// participating chain fields. A profile with none of them (e.g. WireGuard as a
// SOURCE) is exempt from all chain rules — the ordinary unknown-field path
// handles any submitted keys. This mirrors anyDNSFieldDeclared.
func anyChainFieldDeclared(declared map[string]capability.Field) bool {
	for _, n := range []string{"chainMode", "chainNodeId", "chainInterface"} {
		if _, ok := declared[n]; ok {
			return true
		}
	}
	return false
}

// chainEligible reports whether a declared field may participate in the chain
// rules: known (not secret), supported, and of the expected scalar type. This
// is the declaration guard — it prevents inventing dependency targets the
// authority does not actually declare as usable. Mirrors dnsEligible.
func chainEligible(f capability.Field, wantType string) bool {
	if f.Classification != "known" {
		return false // secret-classified fields are never chain rule controls
	}
	if f.HasSupported && !f.Supported {
		return false // unsupported fields are not eligible requirement targets
	}
	return f.Type == wantType
}

// chainModeState reads the active chainMode against its ACTUAL declared
// metadata and reports the effective mode and whether it is USABLE. Unlike DNS,
// an ABSENT chainMode and an explicit "off" behave identically: both mean no
// chain requirement. The mode is usable only when it is an ELIGIBLE enum whose
// value is a member of the field's real AllowedValues; "off" and absent both
// yield the inert state (active=false). An out-of-subset value already produced
// enumViolation per-field and is not treated as a live mode here.
//
// Returns (mode, active, usable): mode is the raw active value ("" when absent
// or not a string), active is whether the mode selects a chain requirement
// (predecessor/final/outbound_interface), usable is whether the selector is an
// eligible in-subset enum.
func chainModeState(declared map[string]capability.Field, activeMap map[string]any) (mode string, active bool, usable bool) {
	f, isDecl := declared["chainMode"]
	if !isDecl {
		return "", false, false // no chain selector declared: no chain rules
	}
	// Eligibility BEFORE the absent branch: only an ELIGIBLE enum declaration
	// may act as a selector at all (mirrors dnsModeState).
	if f.Type != "enum" || !chainEligible(f, "enum") {
		return "", false, false
	}
	raw, present := activeMap["chainMode"]
	if !present {
		return "", false, true // eligible selector absent -> inert (like "off")
	}
	s, isStr := raw.(string)
	if !isStr {
		return "", false, false // non-string active value: typeMismatch already emitted
	}
	for _, a := range f.AllowedValues {
		if s == a {
			switch s {
			case "predecessor", "final", "outbound_interface":
				return s, true, true // live chain requirement
			default:
				return s, false, true // "off" or any other in-subset token: inert
			}
		}
	}
	return s, false, false // out-of-subset value: unusable, enumViolation already emitted
}

// chainStringView builds the eligibility-gated view of one chain string field
// (chainNodeId / chainInterface). A field is activeValid only when present in
// active AND a non-empty string within the declared maxLength; the per-field
// validator already emitted bounds/type findings, so this never double-reports.
// The value is captured for membership/self comparison only, never echoed.
func chainStringView(declared map[string]capability.Field, active, inactive map[string]any, name string) chainFieldView {
	f, isDecl := declared[name]
	if !isDecl {
		return chainFieldView{} // not declared: never a rule target
	}
	v := chainFieldView{declared: true, eligible: chainEligible(f, "string")}
	if val, ok := active[name]; ok {
		v.activePresent = true
		if v.eligible {
			if s, isStr := val.(string); isStr {
				v.value = s
				if chainInterfaceNameOK(f, s) {
					v.activeValid = true
				}
			}
		}
	}
	if _, ok := inactive[name]; ok {
		v.inactivePresent = true
	}
	return v
}

// chainInterfaceNameOK reports whether s satisfies the interface/reference-name
// SHAPE: non-empty, within the declared maxLength, and free of whitespace,
// control characters, '/' and NUL. This shape check is INDEPENDENT of any
// inventory and always runs for an eligible active companion. The same grammar
// applies to chainNodeId (a store UUID) and chainInterface (an interface name).
func chainInterfaceNameOK(f capability.Field, s string) bool {
	if s == "" {
		return false
	}
	if f.HasMaxLength && len(s) > f.MaxLength {
		return false
	}
	for _, r := range s {
		if r <= 0x1f || r == 0x7f { // control chars incl NUL
			return false
		}
		if r == '/' { // path separator: never a bare interface/node name
			return false
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || unicodeIsSpace(r) {
			return false
		}
	}
	return true
}

// unicodeIsSpace reports whether r is any Unicode space (supplementing the
// ASCII checks so a non-breaking or Unicode space is also rejected).
func unicodeIsSpace(r rune) bool {
	return r > 0x7f && strings.ContainsRune(
		"\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff", r)
}

// checkChainRules applies the FR-006 one-layer chain rules. It sets res.ChainCheck
// to the honest aggregate and, on any chain issue, marks the result Invalid and
// not applicable. declared/active/inactive are never mutated. chain is the
// trusted context (may be nil); it is read, never echoed.
//
// Rules (deterministic, value-free, closed IssueCode vocabulary):
//
//	R1 active predecessor/final requires an ACTIVE chainNodeId        -> dependencyMissing
//	R2 active outbound_interface requires an ACTIVE chainInterface     -> dependencyMissing
//	R3 active off + ACTIVE chainNodeId                                  -> dependencyIncompatible
//	R4 active off + ACTIVE chainInterface                               -> dependencyIncompatible
//	R5 active predecessor/final + ACTIVE chainInterface                 -> dependencyIncompatible
//	R6 active outbound_interface + ACTIVE chainNodeId                   -> dependencyIncompatible
//	R7 chainNodeId == trusted SelfID (self-edge)                        -> dependencyIncompatible
//	R8 chainNodeId not in trusted inventory (when inventory available)  -> dependencyMissing
//	R9' referenced node has an ACTIVE non-off chain mode (would close a
//	    cycle / is not a terminal target)                              -> dependencyIncompatible
//	R9' referenced node protocol unknown to the profile                 -> dependencyIncompatible
//	R11 active chainInterface not in trusted interface set (when the
//	    interface inventory is available)                              -> dependencyIncompatible
//
// An ACTIVE reference/interface mode whose required trusted context is missing
// yields ChainCheckNotRun + inapplicable (NOT invalid, NOT a pass). Only an
// ACTIVE eligible companion is checked; an INACTIVE companion is retained
// (D-016), never promoted, and never satisfies a requirement.
func checkChainRules(res *Result, declared map[string]capability.Field, active, inactive map[string]any, chain *ChainContext, profile *capability.Profile) {
	// Default: the chain rules do not gate this node.
	res.ChainCheck = ChainCheckNotRequired

	// Eligibility gate (B1 lesson): a profile that declares NO chain field at
	// all is exempt — WireGuard as a source stays unaffected.
	if !anyChainFieldDeclared(declared) {
		return
	}

	mode, modeActive, modeUsable := chainModeState(declared, active)
	nodeID := chainStringView(declared, active, inactive, "chainNodeId")
	iface := chainStringView(declared, active, inactive, "chainInterface")

	// nodeActive/ifaceActive report whether an ELIGIBLE companion field is
	// present in the ACTIVE bucket. Only an ELIGIBLE field participates in the
	// cross-field rules (the declaration guard): an ineligible active key
	// (unsupported/secret/wrong-type) already produced its own per-field finding
	// and is never invented as a dependency target or counted as a live
	// companion. An INACTIVE companion is retained (D-016), never promoted.
	nodeActive := nodeID.activePresent && nodeID.eligible
	ifaceActive := iface.activePresent && iface.eligible
	// A companion that is declared AND eligible but merely ABSENT/INACTIVE is a
	// genuine missing dependency (mirrors dnsView's !activeValid && !activePresent
	// under eligible): the mode names a real, usable field that was not supplied
	// active. An undeclared/ineligible companion never triggers the requirement.
	nodeMissing := nodeID.eligible && !nodeID.activePresent
	ifaceMissing := iface.eligible && !iface.activePresent

	// crossOk tracks whether every REQUIRED check that ran passed; anyRan
	// tracks whether a required context-dependent check actually ran; required
	// tracks whether such a check was genuinely required (an active eligible
	// companion present). NotRun applies ONLY when a check was required but
	// could not run for lack of trusted context — never when no companion was
	// eligible to check at all.
	crossOk := true
	anyRan := false
	required := false

	// Local compatibility rules R1-R6 run regardless of trusted context: they
	// compare only submitted ACTIVE presence against the effective mode.
	if modeActive && modeUsable {
		switch mode {
		case "predecessor", "final":
			// R1: needs an ACTIVE eligible chainNodeId. A declared+eligible but
			// absent/inactive companion is a genuine missing dependency; an
			// undeclared/ineligible one is never an invented target (silent).
			if nodeMissing {
				addIssue(res, IssueDependencyMissing, "chainNodeId")
				crossOk = false
			}
			// R5: an ACTIVE eligible chainInterface is incompatible with a
			// reference mode.
			if ifaceActive {
				addIssue(res, IssueDependencyIncompatible, "chainInterface")
				crossOk = false
			}
		case "outbound_interface":
			// R2: needs an ACTIVE eligible chainInterface.
			if ifaceMissing {
				addIssue(res, IssueDependencyMissing, "chainInterface")
				crossOk = false
			}
			// R6: an ACTIVE eligible chainNodeId is incompatible with an
			// interface mode.
			if nodeActive {
				addIssue(res, IssueDependencyIncompatible, "chainNodeId")
				crossOk = false
			}
		}
	}
	// R3/R4: an inert mode (off/absent) with an ACTIVE reference companion is
	// incompatible. This runs even when the selector is absent (an ACTIVE
	// chainNodeId under no chain mode is a stray live reference).
	if !modeActive {
		if nodeActive {
			addIssue(res, IssueDependencyIncompatible, "chainNodeId")
			crossOk = false
		}
		if ifaceActive {
			addIssue(res, IssueDependencyIncompatible, "chainInterface")
			crossOk = false
		}
	}

	// Reference resolution (R7 self-edge, R8 existence, R9' terminal/one-layer)
	// applies only to a SHAPE-VALID active chainNodeId (an ineligible-shape
	// reference already produced its per-field finding and cannot be resolved).
	// Only then is a trusted context needed; without it the check is honestly
	// NotRun.
	if modeActive && modeUsable && (mode == "predecessor" || mode == "final") && nodeActive {
		required = true
		if !nodeID.activeValid {
			// An ACTIVE but malformed reference can never satisfy the mode.
			addIssue(res, IssuePatternViolation, "chainNodeId")
			crossOk = false
			anyRan = true
		} else {
			refCheck := runReferenceChecks(res, nodeID, chain, profile)
			switch refCheck {
			case chainRefFailed:
				crossOk = false
				anyRan = true
			case chainRefRan:
				anyRan = true
			case chainRefNotRun:
				// Could not run: leave anyRan false so the aggregate is NotRun.
			}
		}
	}

	// Interface shape (always runs for an ACTIVE eligible chainInterface, no
	// inventory needed) and interface membership (R11, needs the interface
	// inventory). An out-of-shape interface already produced a pattern/bounds
	// finding per-field; the shape pass below is the explicit grammar gate for
	// the membership/NotRun decision.
	if modeActive && modeUsable && mode == "outbound_interface" && ifaceActive {
		required = true
		ifaceCheck := runInterfaceChecks(res, iface, chain)
		switch ifaceCheck {
		case chainRefFailed:
			crossOk = false
			anyRan = true
		case chainRefRan:
			anyRan = true
		case chainRefNotRun:
			// membership could not run: NotRun.
		}
	}

	// Aggregate the honest outcome.
	if !crossOk {
		res.ChainCheck = ChainCheckFailed
		return
	}
	// A required context-dependent check could not run -> NotRun + inapplicable.
	if modeActive && modeUsable && required && !anyRan {
		res.ChainCheck = ChainCheckNotRun
		res.Applicable = false
		return
	}
	if modeActive && modeUsable && anyRan {
		res.ChainCheck = ChainCheckPassed
		return
	}
	// Inert (off/absent/no-active-companion): nothing required, not penalized.
	res.ChainCheck = ChainCheckNotRequired
}

// chainRefResult enumerates the three outcomes of a context-dependent check.
type chainRefResult int

const (
	// chainRefNotRun: the trusted context needed to run was missing.
	chainRefNotRun chainRefResult = iota
	// chainRefRan: the check ran (and passed — a failure sets res issues).
	chainRefRan
	// chainRefFailed: the check ran and produced an issue.
	chainRefFailed
)

// runReferenceChecks applies R7 (self-edge), R8 (existence) and R9' (terminal /
// one-layer / known protocol) for an ACTIVE eligible chainNodeId. It returns
// whether the check ran, failed, or could not run. The referenced id is
// compared, never echoed. A missing trusted SelfID or inventory yields
// chainRefNotRun (the aggregate becomes NotRun + inapplicable), never a pass.
func runReferenceChecks(res *Result, nodeID chainFieldView, chain *ChainContext, profile *capability.Profile) chainRefResult {
	// A complete reference pass needs BOTH a trusted SelfID (for the self-edge
	// sub-check) and a trusted inventory (for existence). Without either, the
	// reference check cannot honestly run.
	if chain == nil || !chain.HasInventory {
		return chainRefNotRun
	}
	ok := true

	// R7 self-edge: needs a trusted SelfID. An empty SelfID means the self
	// sub-check cannot run -> the aggregate is NotRun.
	if chain.SelfID == "" {
		return chainRefNotRun
	}
	if nodeID.value == chain.SelfID {
		addIssue(res, IssueDependencyIncompatible, "chainNodeId")
		ok = false
	}

	// R8 existence: the referenced id must be present in the trusted inventory.
	sum, present := chain.Nodes[nodeID.value]
	if !present {
		// Fail closed: an id the inventory does not describe is NOT treated as
		// a valid terminal (no silent off).
		addIssue(res, IssueDependencyMissing, "chainNodeId")
		return chainRefFailed
	}

	// R9' target protocol must be a protocol the authored profile declares.
	if profile == nil || !profile.HasProtocol(sum.Protocol) {
		addIssue(res, IssueDependencyIncompatible, "chainNodeId")
		return chainRefFailed
	}
	// R9' one-layer: the referenced node must itself be a TERMINAL target — an
	// ACTIVE non-off chain mode on the referenced node would close a cycle, so
	// it is rejected. A referenced node with an ACTIVE chain mode outside the
	// target profile's AllowedValues also fails closed (not treated as off).
	if sum.HasChainMode {
		targetMode := sum.ChainMode
		if targetMode != "" && targetMode != "off" {
			addIssue(res, IssueDependencyIncompatible, "chainNodeId")
			return chainRefFailed
		}
		// ACTIVE but off/absent: terminal, acceptable. (An inactive retained
		// chain mode does not set HasChainMode, so it never reaches here.)
	}

	if !ok {
		return chainRefFailed
	}
	return chainRefRan
}

// runInterfaceChecks applies the interface SHAPE (always, no inventory) and
// interface MEMBERSHIP (R11, needs the trusted interface inventory). The shape
// pass reports an ineligible-shape ACTIVE interface as a pattern issue; the
// membership pass, when the inventory is available, requires the name to be a
// known interface. A missing inventory yields chainRefNotRun for membership.
func runInterfaceChecks(res *Result, iface chainFieldView, chain *ChainContext) chainRefResult {
	// SHAPE: always runs for an ACTIVE eligible chainInterface, independent of
	// any inventory. An ineligible-shape name already produced its per-field
	// finding; here it is a hard chain failure (the mode cannot be satisfied by
	// a malformed interface name).
	if !iface.activeValid {
		addIssue(res, IssuePatternViolation, "chainInterface")
		return chainRefFailed
	}

	// MEMBERSHIP (R11): needs the trusted interface inventory. Without it the
	// membership check cannot run -> NotRun (shape still passed).
	if chain == nil || !chain.HasInterfaceInventory {
		return chainRefNotRun
	}
	for _, known := range chain.Interfaces {
		if iface.value == known {
			return chainRefRan
		}
	}
	addIssue(res, IssueDependencyIncompatible, "chainInterface")
	return chainRefFailed
}
