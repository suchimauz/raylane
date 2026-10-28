// Package nodes is the node-field validation seam (T011-A). It executes the
// authored capability profile's required/type/bounds/enum/dependency rules
// against a submitted node envelope, producing deterministic, value-free
// results. It is pure validation: no storage, no transport, no compiler, no
// network.
//
// Preservation over correction is the central rule: absent fields stay absent,
// explicit defaults stay present, inactive data is retained, and an invalid
// submitted value remains in the caller's original raw bytes for honest draft
// storage — validation never rewrites, drops, or defaults a submitted value.
//
// Secret fields are evaluated by TRUSTED sealed-state presence (supplied by the
// store boundary), never by a client-provided boolean and never by reading a
// plaintext value. No secret or unknown value ever enters a result, issue,
// projection or log.
package nodes

import (
	"github.com/suchimauz/raylane/internal/capability"
)

// IssueCode is the CLOSED vocabulary of validation issue kinds. Like the
// diagnostic codes, the set is fixed; a result can only carry these constants,
// never caller bytes. Each code maps to one static, value-free reason string.
type IssueCode string

const (
	// IssueRequiredMissing: an authored required field is absent.
	IssueRequiredMissing IssueCode = "requiredMissing"
	// IssueRequiredSecretMissing: an authored required secret has no trusted
	// sealed presence.
	IssueRequiredSecretMissing IssueCode = "requiredSecretMissing"
	// IssueTypeMismatch: a field value does not match its declared type.
	IssueTypeMismatch IssueCode = "typeMismatch"
	// IssueEnumViolation: an enum value is not in the declared allowed set.
	IssueEnumViolation IssueCode = "enumViolation"
	// IssueBoundsViolation: an integer/length/item bound is violated.
	IssueBoundsViolation IssueCode = "boundsViolation"
	// IssuePatternViolation: a string does not match its declared pattern.
	IssuePatternViolation IssueCode = "patternViolation"
	// IssueArrayItemViolation: an array element is the wrong type, out of the
	// item bound, or a nested container.
	IssueArrayItemViolation IssueCode = "arrayItemViolation"
	// IssueDependencyMissing: a field with dependencies.requires is present but
	// a required target is absent.
	IssueDependencyMissing IssueCode = "dependencyMissing"
	// IssueDependencyIncompatible: a field is present alongside an
	// incompatibleWith target.
	IssueDependencyIncompatible IssueCode = "dependencyIncompatible"
	// IssueUnsupportedField: a declared field is not applicable (supported=
	// false or activeByDefault handling places it out of scope for validity).
	IssueUnsupportedField IssueCode = "unsupportedField"
	// IssueUnknownField: a submitted field is not declared by the profile.
	IssueUnknownField IssueCode = "unknownField"
	// IssueReservedByteRange: the WireGuard reserved array carries a byte
	// outside 0..255 (narrow documented domain semantic for the 0-or-3 byte
	// list; the profile schema has no per-item bound key).
	IssueReservedByteRange IssueCode = "reservedByteRange"
	// IssueSecretPlaintextSubmitted: a declared secret FIELD NAME was submitted
	// as a key with a value in the active or inactive map. Secret material
	// travels only through the sealed store with trusted presence; the key is
	// refused regardless of the value (any type, including null) and
	// regardless of sealed presence. Declared field name only — never a value.
	IssueSecretPlaintextSubmitted IssueCode = "secretPlaintextSubmitted"
	// IssueQuarantineBucketNotEmpty: the explicit unknown bucket carries any
	// entry. Quarantine data is preserved but the node is not applicable until
	// the source fixes the submission. Generic bucket path, value-free.
	IssueQuarantineBucketNotEmpty IssueCode = "quarantineBucketNotEmpty"
	// IssueMalformedEnvelope: the submission is well-formed JSON but does not
	// match the CLOSED canonical envelope exactly (missing/null/non-object
	// member, non-string or empty protocol, unknown member at any level, or a
	// duplicate key at any level). Fixed path, static reason, never input
	// bytes; carried together with the typed ErrNotANodeEnvelope.
	IssueMalformedEnvelope IssueCode = "malformedEnvelope"
	// IssueEnvelopeMemberConflict: a name appears in two submitted buckets at
	// once (active vs inactive vs quarantine). The buckets must be disjoint or
	// the stored node is ambiguous about which view owns the name. Fixed
	// generic path "fields", static reason — the colliding NAME is attacker-
	// controlled and never echoes.
	IssueEnvelopeMemberConflict IssueCode = "envelopeMemberConflict"
)

// issueReason maps each code to ONE static, value-free reason. It is the only
// source of outward issue text.
var issueReason = map[IssueCode]string{
	IssueRequiredMissing:          "a required field is missing",
	IssueRequiredSecretMissing:    "a required secret has no stored value",
	IssueTypeMismatch:             "a field has the wrong type",
	IssueEnumViolation:            "a field value is not an allowed choice",
	IssueBoundsViolation:          "a field value is outside its allowed range",
	IssuePatternViolation:         "a field value has an invalid format",
	IssueArrayItemViolation:       "an array element is invalid",
	IssueDependencyMissing:        "a required companion field is missing",
	IssueDependencyIncompatible:   "a field conflicts with another present field",
	IssueUnsupportedField:         "a declared field is not supported here",
	IssueUnknownField:             "a field is not recognized",
	IssueReservedByteRange:        "a reserved byte is outside 0..255",
	IssueSecretPlaintextSubmitted: "a secret value must be stored as a secret, not submitted as a field value",
	IssueQuarantineBucketNotEmpty: "unrecognized data is quarantined and must be corrected before the node applies",
	IssueMalformedEnvelope:        "the payload does not match the canonical node envelope",
	IssueEnvelopeMemberConflict:   "a field is submitted in more than one bucket",
}

func (c IssueCode) valid() bool { _, ok := issueReason[c]; return ok }

// Issue is one deterministic, value-free validation finding. Field is the
// declared (profile-authored) field path when known; for an attacker-
// controlled unknown name it is the generic bucket path "unknown" so the opaque
// name never echoes into a result. Reason is a package constant, never bytes.
type Issue struct {
	Code   IssueCode `json:"code"`
	Field  string    `json:"field"`
	Reason string    `json:"reason"`
}

// Input is the trusted, typed validation input. SecretPresence is supplied by
// the store boundary (which knows sealed state), NEVER by the client: a caller
// cannot assert a secret exists by passing a boolean.
type Input struct {
	// Protocol selects the profile protocol (vless/socks5/http/wireguard).
	Protocol string
	// Active holds the submitted active field map (decoded JSON object).
	Active map[string]any
	// Inactive holds fields the caller explicitly marks inactive. These are
	// preserved and validated for shape but do not gate active validity.
	Inactive map[string]any
	// SecretPresence maps declared secret field names to whether a sealed
	// value exists, from the store's trusted HasValue.
	SecretPresence map[string]bool
	// Unknown holds the entries of the explicit client "unknown" bucket, kept
	// QUARANTINED: they are never merged into Active, never satisfy required
	// or dependency presence, and any nonempty Unknown makes the node
	// invalid/not applicable (generic value-free issue). It exists so the
	// adapter can hand the whole submission over without laundering it.
	Unknown map[string]any
	// Chain is the trusted chain/reference context assembled by the store
	// boundary from the saved/active node inventory. nil or HasInventory=false
	// means no reference inventory is available: the reference rules are then
	// NOT RUN (honest ChainCheckNotRun + inapplicable), never a silent PASS.
	// It is read, never echoed, and never derived from the submitted document.
	Chain *ChainContext
}

// Result is the validation outcome. Status is domain.ValidationValid or
// domain.ValidationInvalid. Applicable is false when the node cannot be
// validated as a usable configuration (unknown protocol, an unresolved
// capability, an unsupported protocol, any invalid finding, OR a check that
// could not run — ChainCheckNotRun / StructuredCheckNotRun). A node can be
// structurally Valid yet NOT applicable: NotRun is "could not verify", never a
// pass, so such a node is never presented as apply-ready. Issues are
// deterministic and value-free. Secrets lists the DECLARED secret field names
// (never values). Unknown lists attacker-controlled unknown names under the
// generic bucket path, never the raw name. ProjectedActive/Inactive are the
// allowlisted, value-copied safe projection for the valid subset.
type Result struct {
	Status     Validity
	Applicable bool
	Issues     []Issue
	// Declared secret field names (presence-evaluated), never values.
	Secrets []string
	// Unknown attacker-controlled names, reported only under the bucket path.
	Unknown []string
	// ChainCheck is the honest aggregate status of the FR-006 chain/reference
	// and interface checks. ChainCheckNotRun means a required check could not
	// run for lack of trusted context — NOT a pass; the node is then not
	// applicable for apply even though it may be structurally Valid.
	ChainCheck ChainCheckStatus
	// StructuredCheck is the honest aggregate readiness status of the FR-003
	// structured-object targets (xhttpExtra/finalMask). StructuredCheckNotRun
	// means an ACTIVE eligible opaque object has no real engine-compatibility
	// checker — it is structurally Valid but NOT applicable for apply (Ready is
	// reserved for a future real compat checker and is never produced here).
	// Failed means a real structured incompatibility was decided (the wrong-xhttp
	// mode). It is deliberately separate from ChainCheck and does NOT overlap it.
	StructuredCheck StructuredCheckStatus
}

// StructuredCheckStatus is the honest aggregate outcome of the FR-003
// structured-object readiness check for one node. It is deliberately NOT a
// boolean and deliberately separate from ChainCheckStatus so a caller can never
// read "Valid" as "structured content checked for engine compatibility":
// NotRun and NotRequired are distinct, and Ready is reserved for a future real
// compatibility checker that this increment does not ship.
type StructuredCheckStatus int

const (
	// StructuredCheckNotRequired: the node declares no ACTIVE eligible structured
	// object target (no xhttpExtra/finalMask active, or only ineligible
	// declarations). The structured readiness rule does not gate this node.
	StructuredCheckNotRequired StructuredCheckStatus = iota
	// StructuredCheckReady: reserved for a future REAL engine-compatibility
	// checker. It is UNREACHABLE in this increment: no shipped path produces it.
	StructuredCheckReady
	// StructuredCheckFailed: a structured check RAN and produced an issue (the
	// wrong-xhttp mode). The node is Invalid and not applicable.
	StructuredCheckFailed
	// StructuredCheckNotRun: an ACTIVE eligible structured object exists but the
	// real engine-compatibility checker is not implemented. The object is
	// structurally Valid but NOT applicable for apply — this is NOT a pass and
	// NOT engine/handshake/network proof.
	StructuredCheckNotRun
)

// String returns a stable, value-free label for logs/tests.
func (s StructuredCheckStatus) String() string {
	switch s {
	case StructuredCheckNotRequired:
		return "not_required"
	case StructuredCheckReady:
		return "ready"
	case StructuredCheckFailed:
		return "failed"
	case StructuredCheckNotRun:
		return "not_run"
	}
	return "unknown"
}

// Validity is the two-way validation verdict produced by an explicit Validate
// call. It deliberately reuses the domain semantics (Valid/Invalid) but stays
// local to avoid an import cycle with the store-facing domain package.
type Validity int

const (
	Invalid Validity = iota
	Valid
)

// Validate executes the profile's authored rules against the trusted input.
// It never reads a secret value, never echoes an unknown or secret value, and
// never mutates the input maps. Results are deterministic (sorted field order).
func Validate(profile *capability.Profile, in Input) Result {
	res := Result{Status: Valid, Applicable: true}
	if profile == nil || !profile.HasProtocol(in.Protocol) {
		// Unknown protocol fails closed: nothing is applicable, nothing valid.
		res.Status = Invalid
		res.Applicable = false
		res.Issues = append(res.Issues, Issue{Code: IssueUnknownField, Field: "protocol", Reason: issueReason[IssueUnknownField]})
		return res
	}
	names := profile.FieldNames(in.Protocol)
	declared := make(map[string]capability.Field, len(names))
	for _, n := range names {
		f, _ := profile.Field(in.Protocol, n)
		declared[n] = f
		if f.Classification == "secret" {
			res.Secrets = append(res.Secrets, n)
		}
	}

	active := in.Active
	if active == nil {
		active = map[string]any{}
	}
	inactive := in.Inactive
	if inactive == nil {
		inactive = map[string]any{}
	}

	// Collect the full submitted declared-field presence (active + inactive)
	// for dependency resolution, and detect unknown fields. Trusted sealed
	// secret presence is REAL semantic presence too: a declared secret held
	// only in the sealed store (no plaintext key anywhere) still participates
	// in requires/incompatibleWith resolution — omitting it would report a
	// bogus dependencyMissing for a correctly-sealed node.
	present := make(map[string]bool, len(active)+len(inactive))
	for _, n := range sortedKeys(active) {
		present[n] = true
	}
	for _, n := range sortedKeys(inactive) {
		present[n] = true
	}
	for _, n := range sortedKeysBool(in.SecretPresence) {
		if in.SecretPresence[n] {
			present[n] = true
		}
	}
	// Unknown fields: any submitted name not declared. Report under the
	// generic bucket path so an attacker-controlled name never echoes.
	for _, n := range sortedKeys(active) {
		if _, ok := declared[n]; !ok {
			res.Unknown = append(res.Unknown, "unknown")
			addIssue(&res, IssueUnknownField, "unknown")
		}
	}
	for _, n := range sortedKeys(inactive) {
		if _, ok := declared[n]; !ok {
			res.Unknown = append(res.Unknown, "unknown")
			addIssue(&res, IssueUnknownField, "unknown")
		}
	}
	// Buckets must be disjoint: a name submitted in two buckets at once (for
	// instance BOTH in active and in quarantine) is ambiguous — which view
	// owns it? — and is refused once under a fixed generic path, never the
	// colliding name. Checked before per-field rules so no bucket can launder
	// the duplicate into a normal value check.
	if envelopeBucketsOverlap(active, inactive, in.Unknown) {
		addIssue(&res, IssueEnvelopeMemberConflict, "fields")
	}
	// The explicit quarantine bucket is never promoted: its entries — declared
	// names, secret names or new ones — do not participate in presence,
	// dependencies or values. ANY entry in it invalidates the node with one
	// generic, value-free issue (reported once regardless of entry count).
	if len(in.Unknown) > 0 {
		res.Unknown = append(res.Unknown, "unknown")
		addIssue(&res, IssueQuarantineBucketNotEmpty, "unknown")
	}

	// Per-field validation, in sorted declaration order for determinism.
	for _, n := range sortedKeysOf(declared) {
		f := declared[n]
		inActive := active[n]
		_, hasActive := active[n]
		_, hasInactive := inactive[n]
		has := hasActive || hasInactive

		// Required check. For a KNOWN field, presence means the field is a key
		// in active/inactive. For a SECRET field, presence means the TRUSTED
		// sealed state (SecretPresence) — a secret appearing as a key in the
		// active map is a submitted VALUE (possibly a plaintext smuggle), never
		// presence, and must not satisfy the requirement.
		if f.Classification == "secret" {
			// A secret key submitted WITH a value in either bucket is plaintext
			// smuggling: refused regardless of the value or trusted sealed
			// presence, because the store — not the submitter — owns secret
			// material. The declared name is reported; the value is never read.
			if hasActive || hasInactive {
				addIssue(&res, IssueSecretPlaintextSubmitted, n)
			}
			// Required-secrecy is satisfied ONLY by trusted sealed presence.
			if f.Required && !in.SecretPresence[n] {
				addIssue(&res, IssueRequiredSecretMissing, n)
			}
		} else if f.Required && !has {
			addIssue(&res, IssueRequiredMissing, n)
		}

		// Secret presence for an optional-but-present secret is trusted-state
		// only; a missing sealed value on an optional secret is not an error,
		// it is simply absent (presence drives apply later, not validity here).
		// The secret plaintext-key refusal above already fired for any such key.

		// Active declared fields are validated for shape. Inactive declared
		// fields are PRESERVED, not corrected: they stay in the caller's raw
		// draft for a possible later return and are not shape-gated here (a
		// collapsed/off option keeps its value; reactivation must not lose it).
		// An invalid ACTIVE value is what makes the node invalid/inapplicable.
		// A secret never has its submitted value checked — the key itself was
		// refused above; checkValue fails closed on a secret regardless.
		if hasActive && f.Classification != "secret" {
			checkValue(&res, n, f, inActive)
		}

		// Dependency rules. Presence of the SOURCE field — active, inactive or
		// trusted sealed (for secrets) — drives requires/incompatibleWith: a
		// sealed-only secret still depends on what it was authored to depend
		// on (e.g. mldsa65Seed requires security). A required secret without
		// trusted presence already produced requiredSecretMissing above; it
		// contributes no further dependency findings.
		hasTrustedSecret := f.Classification == "secret" && in.SecretPresence[n]
		if (hasActive || hasInactive || hasTrustedSecret) && f.Dependencies != nil {
			for _, tgt := range f.Dependencies.Requires {
				if !present[tgt] {
					addIssue(&res, IssueDependencyMissing, n)
				}
			}
			for _, tgt := range f.Dependencies.IncompatibleWith {
				if present[tgt] {
					addIssue(&res, IssueDependencyIncompatible, n)
				}
			}
		}
	}

	// FR-004 value-conditional DNS / Happy Eyeballs cross-field rules. These
	// run after the per-field shape checks and reuse the closed IssueCode
	// vocabulary. They read the effective active dnsMode (membership by the
	// field's ACTUAL declared AllowedValues) and the active-valid / active-
	// invalid / inactive resolver split, and never mutate the maps or echo a
	// value. The independent HE rule is not gated on a usable mode selector.
	mode, modeUsable := dnsModeState(declared, active)
	checkDNSRules(&res, declared, active, inactive, mode, modeUsable)

	// FR-006 one-layer chain validation (D-022/D-023/D-047). Runs after the
	// per-field shape checks, keyed on the effective active chainMode and the
	// TRUSTED chain context (never the submitted document). Sets res.ChainCheck
	// honestly (NotRequired/NotRun/Passed/Failed) and, on a chain issue or a
	// NotRun, adjusts applicability below.
	checkChainRules(&res, declared, active, inactive, in.Chain, profile)

	// FR-002 structural REALITY/transport compatibility (D-009..D-012/D-016).
	// Runs after the per-field shape checks: it reads the EFFECTIVE ACTIVE values
	// of BOTH the transport and security selectors (each independently eligible
	// enum whose value is a member of its own ACTUAL AllowedValues). When
	// security=reality and transport is one of the structurally refused canonical
	// choices {mkcp,ws,httpupgrade}, it adds ONE static value-free
	// dependencyIncompatible on the declared transport path. An ineligible /
	// absent / out-of-subset selector keeps the rule silent (ordinary generic
	// issues remain ordinary). No map mutation, no secret read, no new IssueCode.
	checkTransportRules(&res, declared, active)

	// FR-007 credential-intent / trusted-sealed-presence rule (D-016/D-043).
	// Runs after the per-field shape checks: it reads the EFFECTIVE ACTIVE
	// authMode selector and the TRUSTED sealed-presence booleans (never submitted
	// bytes). It certifies presence compatibility ONLY (explicit none accepts any
	// presence; explicit userpass requires every eligible credential sealed; a
	// truly-absent selector resolves none/userpass from the eligible companion
	// split and flags a legacy PARTIAL pair as an invalid, retainable draft —
	// never a silent no-auth). An ineligible/undeclared selector and an
	// inactive-only selector run no demands. No map mutation, no secret value
	// read, no new IssueCode.
	checkAuthRules(&res, declared, active, inactive, in.SecretPresence)

	// FR-008 typed public WireGuard key/address rule (D-049, FR-009/019). Runs
	// after the per-field shape checks: it content-checks the two independently
	// eligible declared known/non-secret/supported ACTIVE fields publicKey
	// (string) and localAddresses (array of string) — for the wireguard
	// protocol ONLY, guarded by the ACTUAL input protocol (an unguarded rule
	// would leak the WireGuard key shape onto vless.publicKey, the REALITY key,
	// which follows its own metadata and is untouched). Each field is gated on
	// its OWN generic valueOK passing (no duplicate ordinary issue) and the two
	// are independent (no early-return coupling). One static value-free issue per
	// offending field (patternViolation@publicKey / arrayItemViolation@
	// localAddresses); no map mutation, no secret read, no new IssueCode.
	checkWireGuardTypedRules(&res, in.Protocol, declared, active)

	// FR-003 structured-object readiness (D-014/D-015/D-016/D-050). Runs after
	// the per-field shape checks: a real non-nil JSON object is a valid shape for
	// an eligible declared object field, but an ACTIVE opaque object with no real
	// engine-compat checker must never become apply-ready. Sets res.StructuredCheck
	// honestly (NotRequired / NotRun / Failed; Ready is reserved for a future real
	// checker and is unreachable here) and, on a NotRun/Failed, reduces
	// applicability below. Protocol-scoped by the ACTUAL input protocol to
	// vless.xhttpExtra / vless.finalMask / wireguard.finalMask so the readiness
	// and xhttp-mode rules never leak into other protocols. One static value-free
	// issue (dependencyIncompatible@xhttpExtra) on the decided wrong-xhttp mode;
	// no map mutation, no secret read, no new IssueCode.
	checkStructuredRules(&res, in.Protocol, declared, active)

	// FR-005 / D-1 unsupported-inactive applicability. An ACTUAL INACTIVE key
	// whose DECLARED field carries HasSupported && !Supported is preserved as a
	// valid draft but prevents apply (D-1): it reduces Applicable ONLY. No new
	// IssueCode, no Status Invalid, no readiness aggregate, no shape re-check,
	// no force-activation/default. Presence (not truthiness) drives the gate, so
	// an inactive `false` counts; null/wrong-typed values are preserved verbatim.
	// Never resets Status or a prior ChainCheck/StructuredCheck outcome.
	if unsupportedInactiveGate(declared, inactive) {
		res.Applicable = false
	}

	if len(res.Issues) > 0 {
		res.Status = Invalid
		// An invalid node is not applicable as a usable configuration.
		res.Applicable = false
	}
	sortIssues(res.Issues)
	return res
}

// checkValue validates one active declared field value, adding deterministic
// value-free issues on failure.
func checkValue(res *Result, name string, f capability.Field, val any) {
	if f.Classification == "secret" {
		// Fail closed: a secret's submitted value is never inspected and never
		// treated as a normal value. Validate refuses the plaintext key before
		// calling this; reaching here with a secret is a programming error and
		// still produces the value-free refusal, never a value echo.
		addIssue(res, IssueSecretPlaintextSubmitted, name)
		return
	}
	// supported=false declared fields are not applicable for active use.
	if f.HasSupported && !f.Supported {
		addIssue(res, IssueUnsupportedField, name)
		return
	}
	validateKnownValue(res, name, f, val)
}

// validateKnownValue runs the type/bounds/enum/pattern/array rules for one
// known non-secret field value, appending the matching closed code.
func validateKnownValue(res *Result, name string, f capability.Field, val any) {
	ok, code := valueOK(f, val)
	if !ok {
		addIssue(res, code, name)
	}
}

// valueOK checks a known scalar/array value against the field metadata and
// returns the first violated closed code. Secret values never reach here.
func valueOK(f capability.Field, val any) (bool, IssueCode) {
	switch f.Type {
	case "string":
		s, ok := val.(string)
		if !ok {
			return false, IssueTypeMismatch
		}
		if f.HasMaxLength && len(s) > f.MaxLength {
			return false, IssueBoundsViolation
		}
		if f.HasMinLength && len(s) < f.MinLength {
			return false, IssueBoundsViolation
		}
		if f.Pattern != "" && !matchString(f, s) {
			return false, IssuePatternViolation
		}
		return true, ""
	case "integer":
		n, ok := asInt(val)
		if !ok {
			// A syntactically valid number that is integral but beyond the
			// representable range is OUT OF RANGE, not the wrong type.
			if numberOutOfRange(val) {
				return false, IssueBoundsViolation
			}
			return false, IssueTypeMismatch
		}
		if f.HasMinimum && n < f.Minimum {
			return false, IssueBoundsViolation
		}
		if f.HasMaximum && n > f.Maximum {
			return false, IssueBoundsViolation
		}
		return true, ""
	case "boolean":
		if _, ok := val.(bool); !ok {
			return false, IssueTypeMismatch
		}
		return true, ""
	case "object":
		// FR-003 object SHAPE: a real, non-nil JSON object is a valid shape.
		// Both a nonempty nested map and a real empty {} are valid; a typed-nil
		// map (DIRECT seam) or a JSON null (canonical) is NOT an object and fails
		// typeMismatch like any wrong type. Emptiness is never rejected (no
		// len(m)==0 gate): an empty object is a legitimate structured value. The
		// CONTENT of an opaque object is not validated here — readiness for the
		// product targets (xhttpExtra/finalMask) is a separate honest aggregate
		// reported in Result.StructuredCheck (see structured_rules.go).
		if m, ok := val.(map[string]any); ok && m != nil {
			return true, ""
		}
		return false, IssueTypeMismatch
	case "enum":
		s, ok := val.(string)
		if !ok {
			return false, IssueTypeMismatch
		}
		for _, a := range f.AllowedValues {
			if s == a {
				return true, ""
			}
		}
		return false, IssueEnumViolation
	case "array":
		arr, ok := val.([]any)
		if !ok {
			return false, IssueTypeMismatch
		}
		if f.HasMaxItems && len(arr) > f.MaxItems {
			return false, IssueBoundsViolation
		}
		if f.HasMinItems && len(arr) < f.MinItems {
			return false, IssueBoundsViolation
		}
		// Narrow WireGuard reserved domain semantic: the authored rule is exactly
		// 0 OR 3 bytes. The profile schema has no per-item or cross-count bound
		// key, so the 0-or-3 cardinality is enforced here as a documented domain
		// rule alongside the per-byte 0..255 range below.
		if f.Name == "reserved" && len(arr) != 0 && len(arr) != 3 {
			return false, IssueBoundsViolation
		}
		for _, el := range arr {
			if _, isObj := el.(map[string]any); isObj {
				return false, IssueArrayItemViolation
			}
			if _, isArr := el.([]any); isArr {
				return false, IssueArrayItemViolation
			}
			if f.ItemType == "integer" {
				n, ok := asInt(el)
				if !ok {
					return false, IssueArrayItemViolation
				}
				// Narrow WireGuard reserved domain semantic: byte range 0..255.
				// Detected by the field name; only applies to reserved.
				if f.Name == "reserved" && (n < 0 || n > 255) {
					return false, IssueReservedByteRange
				}
			} else {
				if _, ok := el.(string); !ok {
					return false, IssueArrayItemViolation
				}
			}
		}
		return true, ""
	}
	return false, IssueTypeMismatch
}

// matchString reports whether s matches the field's pattern. The compiled
// regexp is owned by the profile; nodes reaches it through the profile-backed
// helper rather than recompiling an attacker-influenced pattern.
func matchString(f capability.Field, s string) bool {
	return capability.MatchPattern(f, s)
}

// bucketIssueField documents the invariant that keeps a verdict renderable
// without echoing submission bytes: a path is either structural vocabulary
// ("fields"/"unknown"/"envelope", see fixedIssuePath) or a DECLARED profile
// name from the closed capability vocabulary — never a submitted key. addIssue
// rejects the one combination that would break it: a fixed structural code
// naming something other than structural vocabulary. Name-scoped codes are
// emitted only from the declared-field loop, so their name is declared by
// construction.
func bucketIssueField(c IssueCode, n string) string {
	if fixedIssuePath(c) && !isStructuralPath(n) {
		// Unreachable for package call sites; fail closed to the fixed word
		// rather than surface a name an attacker chose.
		if c == IssueUnknownField {
			return "unknown"
		}
		return "fields"
	}
	return n
}

// isStructuralPath reports the closed set of non-field paths a verdict may use.
func isStructuralPath(n string) bool {
	switch n {
	case "fields", "unknown", "envelope", "protocol":
		return true
	}
	return false
}

// fixedIssuePath reports the codes whose path is structural vocabulary rather
// than a field name. Their call sites pass one of the constants above.
func fixedIssuePath(c IssueCode) bool {
	switch c {
	case IssueEnvelopeMemberConflict, IssueQuarantineBucketNotEmpty,
		IssueMalformedEnvelope, IssueUnknownField:
		return true
	default:
		return false
	}
}
