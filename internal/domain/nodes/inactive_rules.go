package nodes

import "github.com/suchimauz/raylane/internal/capability"

// This file holds the FR-005 / D-1 unsupported-inactive applicability rule.
// It runs as an explicit post-pass inside Validate, after the per-field generic
// checks, because it depends on the INACTIVE bucket's effective key presence
// against each field's OWN declared metadata.
//
// D-1 (docs/engineering/foundation-decisions.md 18-31, EXACT): "A declared-but-
// unsupported field is preserved inactive and prevents apply." Concretely: an
// INACTIVE map key whose DECLARED field carries HasSupported && !Supported makes
// the node NOT applicable for apply — and NOTHING else. The field stays a
// preserved, valid, retainable draft: no new IssueCode, no Status Invalid, no
// readiness aggregate, no shape re-check, no force-activation, no default
// materialization. The node remains Status Valid with zero additional issues;
// only Applicable is reduced (below).
//
// The gate is keyed on ACTUAL INACTIVE key PRESENCE plus the field's OWN
// declaration (HasSupported && !Supported) — never on a name/protocol hardcode
// and never on boolean truthiness or a default-off value. A present value of
// `false` COUNTS as present (presence, not truthiness, drives the gate). A
// null / wrong-typed / nested inactive value is preserved verbatim and is NOT
// shape-checked or activated. Default-off SUPPORTED inactive fields do NOT gate
// (HasSupported && Supported is not the unsupported condition), and ABSENT
// unsupported defaults never appear and never gate.
//
// It never mutates the maps, never reads a secret value, and never echoes a
// byte. It does NOT reset Status or any prior aggregate (ChainCheck /
// StructuredCheck) — it only reduces Applicability in the main Validate tail.

// unsupportedInactiveGate reports whether any ACTUAL INACTIVE key is a declared
// unsupported field (own HasSupported && !Supported). It reads only key presence
// and the declared metadata — never a value — so presence of `false`, null, or
// any wrong-typed value all count the same (present). Undeclared inactive keys
// are ordinary unknowns (already handled by the caller) and never reach here.
func unsupportedInactiveGate(declared map[string]capability.Field, inactive map[string]any) bool {
	for name := range inactive {
		f, isDecl := declared[name]
		if !isDecl {
			continue // undeclared inactive key: ordinary unknown, not a D-1 gate
		}
		if f.HasSupported && !f.Supported {
			return true // declared-but-unsupported present inactive prevents apply
		}
	}
	return false
}
