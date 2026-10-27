// Package contract_test is the behavior contract for FR-006 one-layer chain
// validation (T010/T011-B2, D-022/D-023/D-047). It executes the REAL
// nodes.Validate / nodes.ValidateDocument against the authored v4 profile with
// a trusted chain context — not fixture linting. RED→GREEN: these cases fail
// before the chain rules exist and pass after.
//
// Honesty is asserted throughout: a required reference/interface check that
// lacks trusted context is ChainCheckNotRun + inapplicable (never a silent
// pass); an inert node (off/absent/no chain fields) is never penalized for a
// missing context; and canary values never leak into any result/issue/echo.
package contract_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// chainCanary values must never appear in any result, issue, projection or
// trusted-context echo.
const (
	chainNodeCanary  = "CANARY-CHAIN-NODE-ID-7f3a"
	chainIfaceCanary = "CANARY-CHAIN-IFACE-9b2c"
)

// chainBase returns a fresh, VALID active field map for the protocol, ready to
// have chain fields added. It reuses the authored-profile minimal valid shape.
func chainBase(protocol string) map[string]any {
	m := map[string]any{}
	for k, v := range minValid(protocol) {
		m[k] = v
	}
	return m
}

// refContext builds a trusted chain context with the given self id and peer
// inventory. Each peer entry is (id, protocol).
func refContext(selfID string, peers [][2]string, ifaces ...string) *nodes.ChainContext {
	inventory := map[string]nodes.ChainNodeSummary{}
	for _, pr := range peers {
		inventory[pr[0]] = nodes.ChainNodeSummary{Protocol: pr[1]}
	}
	return &nodes.ChainContext{
		SelfID: selfID, Nodes: inventory, HasInventory: len(peers) > 0,
		Interfaces: ifaces, HasInterfaceInventory: len(ifaces) > 0,
	}
}

// assertChainCanary serializes the result and fails if a chain canary leaked.
func assertChainCanary(t *testing.T, label string, v any) {
	t.Helper()
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(v); err != nil {
		t.Fatalf("%s: encode: %v", label, err)
	}
	for _, c := range []string{chainNodeCanary, chainIfaceCanary} {
		if bytes.Contains(buf.Bytes(), []byte(c)) {
			t.Fatalf("%s: chain canary %q leaked: %s", label, c, buf.String())
		}
	}
}

// TestChainOffAndAbsentNotRequired: an off/absent chainMode is never penalized
// for a missing context — ChainCheckNotRequired, applicability unchanged.
func TestChainOffAndAbsentNotRequired(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range []string{"vless", "socks5", "http"} {
		// absent chainMode
		res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: chainBase(proto), SecretPresence: trustedPresenceFor(proto)})
		if res.ChainCheck != nodes.ChainCheckNotRequired {
			t.Fatalf("%s absent chainMode: ChainCheck=%v, want NotRequired", proto, res.ChainCheck)
		}
		if !res.Applicable || res.Status != nodes.Valid {
			t.Fatalf("%s absent chainMode: must stay valid+applicable, got %+v", proto, res)
		}
		// explicit off
		m := chainBase(proto)
		m["chainMode"] = "off"
		res = nodes.Validate(p, nodes.Input{Protocol: proto, Active: m, SecretPresence: trustedPresenceFor(proto)})
		if res.ChainCheck != nodes.ChainCheckNotRequired {
			t.Fatalf("%s off chainMode: ChainCheck=%v, want NotRequired", proto, res.ChainCheck)
		}
		if !res.Applicable || res.Status != nodes.Valid {
			t.Fatalf("%s off chainMode: must stay valid+applicable, got %+v", proto, res)
		}
		assertChainCanary(t, proto+" off", res)
	}
}

// TestChainWireGuardSourceExempt: WireGuard declares no chain fields, so it is
// exempt from all chain rules even if a stray chain key is submitted (handled
// by the ordinary unknown-field path, not the chain rules).
func TestChainWireGuardSourceExempt(t *testing.T) {
	p := loadProfile(t)
	m := minValid("wireguard")
	m["chainMode"] = "predecessor"
	m["chainNodeId"] = chainNodeCanary
	res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: m, SecretPresence: trustedPresenceFor("wireguard")})
	// The chain fields are UNKNOWN to WireGuard -> invalid via unknownField, and
	// ChainCheck stays NotRequired (the chain rules never ran).
	if res.ChainCheck != nodes.ChainCheckNotRequired {
		t.Fatalf("wireguard source: ChainCheck=%v, want NotRequired (exempt)", res.ChainCheck)
	}
	if !hasIssue(res, nodes.IssueUnknownField, "unknown") {
		t.Fatalf("wireguard chain key must be unknownField, got %+v", res.Issues)
	}
	assertChainCanary(t, "wireguard source", res)
}

// TestChainReferenceRequiresContext: an active predecessor/final reference
// with no trusted context is ChainCheckNotRun + inapplicable, but stays
// structurally Valid (a check that did not run is NOT a semantic violation).
func TestChainReferenceRequiresContext(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range []string{"vless", "socks5", "http"} {
		for _, mode := range []string{"predecessor", "final"} {
			m := chainBase(proto)
			m["chainMode"] = mode
			m["chainNodeId"] = chainNodeCanary
			// nil context: no inventory.
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: m, SecretPresence: trustedPresenceFor(proto)})
			if res.Status != nodes.Valid {
				t.Fatalf("%s %s nil ctx: must stay structurally Valid, got %+v", proto, mode, res.Issues)
			}
			if res.ChainCheck != nodes.ChainCheckNotRun {
				t.Fatalf("%s %s nil ctx: ChainCheck=%v, want NotRun", proto, mode, res.ChainCheck)
			}
			if res.Applicable {
				t.Fatalf("%s %s nil ctx: must be inapplicable (NotRun is not a pass)", proto, mode)
			}
			assertChainCanary(t, proto+" "+mode+" nilctx", res)
		}
	}
}

// TestChainReferenceMissingSelfIDNotRun: a full inventory but an empty trusted
// SelfID means the self-edge sub-check cannot run -> aggregate NotRun.
func TestChainReferenceMissingSelfIDNotRun(t *testing.T) {
	p := loadProfile(t)
	m := chainBase("vless")
	m["chainMode"] = "predecessor"
	m["chainNodeId"] = "peer-1"
	ctx := refContext("", [][2]string{{"peer-1", "vless"}})
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: m, SecretPresence: trustedPresenceFor("vless"), Chain: ctx})
	if res.Status != nodes.Valid {
		t.Fatalf("missing selfID: must stay Valid, got %+v", res.Issues)
	}
	if res.ChainCheck != nodes.ChainCheckNotRun {
		t.Fatalf("missing selfID: ChainCheck=%v, want NotRun", res.ChainCheck)
	}
	if res.Applicable {
		t.Fatalf("missing selfID: must be inapplicable")
	}
}

// TestChainReferencePassed: an active reference to a terminal peer with a full
// trusted context passes; WireGuard is an eligible terminal target (R10').
func TestChainReferencePassed(t *testing.T) {
	p := loadProfile(t)
	peers := [][2]string{{"peer-v", "vless"}, {"peer-w", "wireguard"}, {"peer-s", "socks5"}}
	cases := []struct{ proto, target string }{
		{"vless", "peer-v"}, {"vless", "peer-w"},
		{"socks5", "peer-s"}, {"socks5", "peer-w"},
		{"http", "peer-v"}, {"http", "peer-w"},
	}
	for _, c := range cases {
		for _, mode := range []string{"predecessor", "final"} {
			m := chainBase(c.proto)
			m["chainMode"] = mode
			m["chainNodeId"] = c.target
			ctx := refContext("self-"+c.proto, peers)
			res := nodes.Validate(p, nodes.Input{Protocol: c.proto, Active: m, SecretPresence: trustedPresenceFor(c.proto), Chain: ctx})
			if res.Status != nodes.Valid || !res.Applicable {
				t.Fatalf("%s %s->%s: want Valid+Applicable, got status=%v applicable=%v issues=%+v", c.proto, mode, c.target, res.Status, res.Applicable, res.Issues)
			}
			if res.ChainCheck != nodes.ChainCheckPassed {
				t.Fatalf("%s %s->%s: ChainCheck=%v, want Passed", c.proto, mode, c.target, res.ChainCheck)
			}
		}
	}
}

// TestChainSelfReferenceRejected: an active reference to this node's own id is
// a self-edge cycle -> dependencyIncompatible on chainNodeId, Invalid.
func TestChainSelfReferenceRejected(t *testing.T) {
	p := loadProfile(t)
	m := chainBase("vless")
	m["chainMode"] = "predecessor"
	m["chainNodeId"] = "self-vless"
	ctx := refContext("self-vless", [][2]string{{"peer-v", "vless"}})
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: m, SecretPresence: trustedPresenceFor("vless"), Chain: ctx})
	if res.Status != nodes.Invalid || res.Applicable {
		t.Fatalf("self-edge: want Invalid+inapplicable, got %+v", res)
	}
	if !hasIssue(res, nodes.IssueDependencyIncompatible, "chainNodeId") {
		t.Fatalf("self-edge: want dependencyIncompatible on chainNodeId, got %+v", res.Issues)
	}
	if res.ChainCheck != nodes.ChainCheckFailed {
		t.Fatalf("self-edge: ChainCheck=%v, want Failed", res.ChainCheck)
	}
}

// TestChainNonexistentTargetRejected: an active reference to an id the trusted
// inventory does not describe fails closed (dependencyMissing), NOT treated as off.
func TestChainNonexistentTargetRejected(t *testing.T) {
	p := loadProfile(t)
	m := chainBase("vless")
	m["chainMode"] = "final"
	m["chainNodeId"] = chainNodeCanary
	ctx := refContext("self-vless", [][2]string{{"peer-v", "vless"}})
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: m, SecretPresence: trustedPresenceFor("vless"), Chain: ctx})
	if res.Status != nodes.Invalid {
		t.Fatalf("nonexistent target: want Invalid, got %+v", res.Issues)
	}
	if !hasIssue(res, nodes.IssueDependencyMissing, "chainNodeId") {
		t.Fatalf("nonexistent target: want dependencyMissing on chainNodeId, got %+v", res.Issues)
	}
	assertChainCanary(t, "nonexistent target", res)
}

// TestChainSecondLayerRejected: a referenced node with an ACTIVE non-off chain
// mode is not a terminal target (would close a cycle) -> dependencyIncompatible.
func TestChainSecondLayerRejected(t *testing.T) {
	p := loadProfile(t)
	// Build a context where peer-v itself declares an ACTIVE predecessor mode.
	ctx := &nodes.ChainContext{
		SelfID: "self-vless",
		Nodes: map[string]nodes.ChainNodeSummary{
			"peer-v":   {Protocol: "vless", ChainMode: "predecessor", HasChainMode: true},
			"peer-off": {Protocol: "vless", ChainMode: "off", HasChainMode: true},
		},
		HasInventory: true,
	}
	// Active non-off chain on the target -> rejected.
	m := chainBase("vless")
	m["chainMode"] = "predecessor"
	m["chainNodeId"] = "peer-v"
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: m, SecretPresence: trustedPresenceFor("vless"), Chain: ctx})
	if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueDependencyIncompatible, "chainNodeId") {
		t.Fatalf("second-layer: want Invalid + dependencyIncompatible, got %+v", res.Issues)
	}
	// Terminal target with an ACTIVE off chain mode -> allowed.
	m["chainNodeId"] = "peer-off"
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: m, SecretPresence: trustedPresenceFor("vless"), Chain: ctx})
	if res.Status != nodes.Valid || res.ChainCheck != nodes.ChainCheckPassed {
		t.Fatalf("off-chain terminal: want Valid+Passed, got %+v", res)
	}
}

// TestChainUnknownProtocolTargetRejected: a referenced node whose protocol is
// unknown to the profile (e.g. vmess) is rejected.
func TestChainUnknownProtocolTargetRejected(t *testing.T) {
	p := loadProfile(t)
	m := chainBase("vless")
	m["chainMode"] = "predecessor"
	m["chainNodeId"] = "peer-x"
	ctx := refContext("self-vless", [][2]string{{"peer-x", "vmess"}})
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: m, SecretPresence: trustedPresenceFor("vless"), Chain: ctx})
	if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueDependencyIncompatible, "chainNodeId") {
		t.Fatalf("unknown-protocol target: want Invalid + dependencyIncompatible, got %+v", res.Issues)
	}
}

// TestChainMissingActiveCompanion: a predecessor mode with no ACTIVE
// chainNodeId is dependencyMissing; the companion is required.
func TestChainMissingActiveCompanion(t *testing.T) {
	p := loadProfile(t)
	m := chainBase("socks5")
	m["chainMode"] = "predecessor"
	// No chainNodeId at all.
	res := nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: m, SecretPresence: trustedPresenceFor("socks5")})
	if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueDependencyMissing, "chainNodeId") {
		t.Fatalf("predecessor without companion: want dependencyMissing, got %+v", res.Issues)
	}
}

// TestChainInactiveCompanionRetainedNotSatisfying: an INACTIVE chainNodeId does
// NOT satisfy an active predecessor mode (D-016: retained, never promoted).
func TestChainInactiveCompanionRetainedNotSatisfying(t *testing.T) {
	p := loadProfile(t)
	m := chainBase("vless")
	m["chainMode"] = "predecessor"
	ctx := refContext("self-vless", [][2]string{{chainNodeCanary, "vless"}})
	res := nodes.Validate(p, nodes.Input{
		Protocol: "vless", Active: m,
		Inactive:       map[string]any{"chainNodeId": chainNodeCanary},
		SecretPresence: trustedPresenceFor("vless"), Chain: ctx,
	})
	if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueDependencyMissing, "chainNodeId") {
		t.Fatalf("inactive companion must not satisfy predecessor: want dependencyMissing, got %+v", res.Issues)
	}
	assertChainCanary(t, "inactive companion", res)
}

// TestChainOffWithInactiveStaleTargetValid: off mode + an INACTIVE chainNodeId
// pointing at a node that no longer exists is VALID — off needs no reference.
func TestChainOffWithInactiveStaleTargetValid(t *testing.T) {
	p := loadProfile(t)
	m := chainBase("vless")
	m["chainMode"] = "off"
	res := nodes.Validate(p, nodes.Input{
		Protocol: "vless", Active: m,
		Inactive:       map[string]any{"chainNodeId": chainNodeCanary},
		SecretPresence: trustedPresenceFor("vless"),
	})
	if res.Status != nodes.Valid || !res.Applicable {
		t.Fatalf("off+inactive stale target: want Valid+Applicable, got %+v", res)
	}
	if res.ChainCheck != nodes.ChainCheckNotRequired {
		t.Fatalf("off+inactive stale target: ChainCheck=%v, want NotRequired", res.ChainCheck)
	}
}

// TestChainModeIncompatibilities: the mutually-alternative mode rules R3-R6.
func TestChainModeIncompatibilities(t *testing.T) {
	p := loadProfile(t)
	ctx := refContext("self-vless", [][2]string{{"peer-v", "vless"}})

	// R3: off + ACTIVE chainNodeId -> incompatible.
	m := chainBase("vless")
	m["chainMode"] = "off"
	m["chainNodeId"] = "peer-v"
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: m, SecretPresence: trustedPresenceFor("vless"), Chain: ctx})
	if !hasIssue(res, nodes.IssueDependencyIncompatible, "chainNodeId") || res.Status != nodes.Invalid {
		t.Fatalf("R3 off+nodeId: want incompatible, got %+v", res.Issues)
	}

	// R4: off + ACTIVE chainInterface -> incompatible.
	m = chainBase("vless")
	m["chainMode"] = "off"
	m["chainInterface"] = "eth0"
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: m, SecretPresence: trustedPresenceFor("vless")})
	if !hasIssue(res, nodes.IssueDependencyIncompatible, "chainInterface") || res.Status != nodes.Invalid {
		t.Fatalf("R4 off+iface: want incompatible on chainInterface, got %+v", res.Issues)
	}

	// R5: predecessor + ACTIVE chainInterface -> incompatible.
	m = chainBase("vless")
	m["chainMode"] = "predecessor"
	m["chainNodeId"] = "peer-v"
	m["chainInterface"] = "eth0"
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: m, SecretPresence: trustedPresenceFor("vless"), Chain: ctx})
	if !hasIssue(res, nodes.IssueDependencyIncompatible, "chainInterface") || res.Status != nodes.Invalid {
		t.Fatalf("R5 predecessor+iface: want incompatible on chainInterface, got %+v", res.Issues)
	}

	// R6: outbound_interface + ACTIVE chainNodeId -> incompatible.
	m = chainBase("vless")
	m["chainMode"] = "outbound_interface"
	m["chainInterface"] = "eth0"
	m["chainNodeId"] = "peer-v"
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: m, SecretPresence: trustedPresenceFor("vless"), Chain: ctx})
	if !hasIssue(res, nodes.IssueDependencyIncompatible, "chainNodeId") || res.Status != nodes.Invalid {
		t.Fatalf("R6 iface+nodeId: want incompatible on chainNodeId, got %+v", res.Issues)
	}
}

// TestChainOutboundInterface: interface shape always runs; membership needs the
// trusted interface inventory (no inventory -> NotRun + inapplicable).
func TestChainOutboundInterface(t *testing.T) {
	p := loadProfile(t)
	// No interface inventory: shape runs (valid name) but membership is NotRun.
	m := chainBase("http")
	m["chainMode"] = "outbound_interface"
	m["chainInterface"] = "eth0"
	res := nodes.Validate(p, nodes.Input{Protocol: "http", Active: m, SecretPresence: trustedPresenceFor("http")})
	if res.Status != nodes.Valid {
		t.Fatalf("iface no-inventory: must stay structurally Valid, got %+v", res.Issues)
	}
	if res.ChainCheck != nodes.ChainCheckNotRun {
		t.Fatalf("iface no-inventory: ChainCheck=%v, want NotRun", res.ChainCheck)
	}
	if res.Applicable {
		t.Fatalf("iface no-inventory: must be inapplicable (membership not run)")
	}

	// Membership with the interface in the trusted set -> Passed.
	ctx := refContext("self-http", nil, "eth0", "wlan0")
	res = nodes.Validate(p, nodes.Input{Protocol: "http", Active: m, SecretPresence: trustedPresenceFor("http"), Chain: ctx})
	if res.Status != nodes.Valid || !res.Applicable || res.ChainCheck != nodes.ChainCheckPassed {
		t.Fatalf("iface in-set: want Valid+Applicable+Passed, got %+v", res)
	}

	// Membership with an unknown interface -> dependencyIncompatible.
	m2 := chainBase("http")
	m2["chainMode"] = "outbound_interface"
	m2["chainInterface"] = chainIfaceCanary
	res = nodes.Validate(p, nodes.Input{Protocol: "http", Active: m2, SecretPresence: trustedPresenceFor("http"), Chain: ctx})
	if res.Status != nodes.Invalid || !hasIssue(res, nodes.IssueDependencyIncompatible, "chainInterface") {
		t.Fatalf("iface unknown: want Invalid + dependencyIncompatible, got %+v", res.Issues)
	}
	assertChainCanary(t, "iface unknown", res)
}

// TestChainInterfaceShapeRejected: malformed interface names (empty, slash,
// whitespace, control, over-long) are rejected by the interface shape grammar.
func TestChainInterfaceShapeRejected(t *testing.T) {
	p := loadProfile(t)
	bad := []string{
		"",                      // empty
		"eth 0",                 // whitespace
		"eth\t0",                // tab
		"a/b",                   // slash
		strings.Repeat("i", 65), // over 64
		"eth\x00net",            // NUL
	}
	for _, name := range bad {
		m := chainBase("socks5")
		m["chainMode"] = "outbound_interface"
		m["chainInterface"] = name
		ctx := refContext("self-socks5", nil, "eth0")
		res := nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: m, SecretPresence: trustedPresenceFor("socks5"), Chain: ctx})
		if res.Status != nodes.Invalid {
			t.Fatalf("iface %q: want Invalid, got %+v", name, res.Issues)
		}
	}
}

// TestChainNodeIdMaxLength: a chainNodeId over 64 chars is a bounds violation.
func TestChainNodeIdMaxLength(t *testing.T) {
	p := loadProfile(t)
	m := chainBase("vless")
	m["chainMode"] = "predecessor"
	m["chainNodeId"] = strings.Repeat("n", 65)
	ctx := refContext("self-vless", nil)
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: m, SecretPresence: trustedPresenceFor("vless"), Chain: ctx})
	if !hasIssue(res, nodes.IssueBoundsViolation, "chainNodeId") {
		t.Fatalf("over-long chainNodeId: want boundsViolation, got %+v", res.Issues)
	}
}

// TestChainInterfaceMaxLength: a chainInterface over 64 chars is a bounds violation.
func TestChainInterfaceMaxLength(t *testing.T) {
	p := loadProfile(t)
	m := chainBase("http")
	m["chainMode"] = "outbound_interface"
	m["chainInterface"] = strings.Repeat("i", 65)
	res := nodes.Validate(p, nodes.Input{Protocol: "http", Active: m, SecretPresence: trustedPresenceFor("http")})
	if !hasIssue(res, nodes.IssueBoundsViolation, "chainInterface") {
		t.Fatalf("over-long chainInterface: want boundsViolation, got %+v", res.Issues)
	}
}

// TestChainDocumentWithContext: the shared adapter honors the trusted context
// (exact envelope, exact raw preservation) and reports ChainCheck honestly.
func TestChainDocumentWithContext(t *testing.T) {
	p := loadProfile(t)
	peers := [][2]string{{"peer-v", "vless"}}
	full := refContext("self-vless", peers)
	// Build a canonical envelope with an active predecessor reference.
	original := []byte(`{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"ws","security":"tls","chainMode":"predecessor","chainNodeId":"peer-v"},"inactive":{},"unknown":{}}}`)

	// With a full trusted context -> Valid, Passed, applicable.
	got, err := nodes.ValidateDocumentWithContext(p, original, map[string]bool{"uuid": true}, full)
	if err != nil {
		t.Fatalf("ValidateDocumentWithContext(full): %v", err)
	}
	if got.Validation != domain.ValidationValid || !got.Result.Applicable || got.Result.ChainCheck != nodes.ChainCheckPassed {
		t.Fatalf("full ctx: want Valid+Applicable+Passed, got %+v", got.Result)
	}

	// With nil context -> still decodes, structurally Valid, but NotRun +
	// inapplicable. Raw bytes preserved exactly.
	gotNil, err := nodes.ValidateDocument(p, original, map[string]bool{"uuid": true})
	if err != nil {
		t.Fatalf("ValidateDocument(nil): %v", err)
	}
	if gotNil.Validation != domain.ValidationValid {
		t.Fatalf("nil ctx: want structurally Valid, got %+v", gotNil.Result.Issues)
	}
	if gotNil.Result.ChainCheck != nodes.ChainCheckNotRun || gotNil.Result.Applicable {
		t.Fatalf("nil ctx: want NotRun + inapplicable, got %+v", gotNil.Result)
	}
	if !bytes.Equal(gotNil.Document.Raw, original) {
		t.Fatalf("nil ctx: exact raw not preserved")
	}

	// No context value ever appears in any serialized result echo.
	assertChainCanary(t, "document ctx", got.Result)
	assertChainCanary(t, "document nilctx", gotNil.Result)
}

// TestChainInvalidDraftSaveableFR009: an invalid chain draft (self-edge) still
// preserves its EXACT raw bytes for honest storage (FR-009) — validation never
// rewrites, drops, or defaults a submitted value.
func TestChainInvalidDraftSaveableFR009(t *testing.T) {
	p := loadProfile(t)
	original := []byte(`{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"ws","security":"tls","chainMode":"predecessor","chainNodeId":"self-vless"},"inactive":{},"unknown":{}}}`)
	ctx := refContext("self-vless", [][2]string{{"peer-v", "vless"}})
	got, err := nodes.ValidateDocumentWithContext(p, original, map[string]bool{"uuid": true}, ctx)
	if err != nil {
		t.Fatalf("ValidateDocumentWithContext: %v", err)
	}
	if got.Validation != domain.ValidationInvalid {
		t.Fatalf("self-edge draft: want ValidationInvalid, got %v", got.Validation)
	}
	if !bytes.Equal(got.Document.Raw, original) {
		t.Fatalf("invalid chain draft: exact raw not preserved")
	}
	// The submitted self id must NOT appear in the value-free result.
	assertChainCanary(t, "fr009", got.Result)
}

// TestChainOnlyInactiveValuesNotRequired: a node with ONLY inactive chain
// values (no active mode) is NotRequired — never penalized for missing context.
func TestChainOnlyInactiveValuesNotRequired(t *testing.T) {
	p := loadProfile(t)
	res := nodes.Validate(p, nodes.Input{
		Protocol: "vless", Active: chainBase("vless"),
		Inactive:       map[string]any{"chainNodeId": chainNodeCanary, "chainInterface": "eth0"},
		SecretPresence: trustedPresenceFor("vless"),
	})
	if res.ChainCheck != nodes.ChainCheckNotRequired || !res.Applicable || res.Status != nodes.Valid {
		t.Fatalf("only inactive chain values: want NotRequired+Valid+Applicable, got %+v", res)
	}
	assertChainCanary(t, "only inactive", res)
}
