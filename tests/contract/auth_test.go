// Maintained behavior contract for FR-007 credential intent + trusted sealed
// presence (D-016/D-043). It executes the REAL capability authority and the
// REAL nodes.Validate against the authored profile AND declaration-guard
// partial profiles — not fixture linting or AST inspection.
//
// Central guarantee: explicit no-auth (none) and user/password (userpass)
// intent has deterministic presence compatibility; a legacy PARTIAL credential
// pair (exactly one of username/password stored with no explicit selector) is
// an INVALID but RETAINABLE draft — never silently downgraded to no-auth.
// Presence is trusted sealed state ONLY; the pure rule certifies presence
// compatibility, never byte validity, content, engine readiness, or successful
// authentication. All issues are on the fixed declared path "authMode" and
// value-free (no secret value, no presence value, no submitted bytes echo).

package contract_test

import (
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// authInput wraps nodes.Validate with an explicit trusted presence map so each
// case states exactly which sealed credentials exist.
func authValidate(t *testing.T, p *capability.Profile, proto string, active, inactive map[string]any, presence map[string]bool) nodes.Result {
	t.Helper()
	if active == nil {
		active = map[string]any{}
	}
	if inactive == nil {
		inactive = map[string]any{}
	}
	return nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, Inactive: inactive, SecretPresence: presence})
}

// expectAuthOK asserts a coherent, valid, applicable result.
func expectAuthOK(t *testing.T, label string, res nodes.Result) {
	t.Helper()
	if res.Status != nodes.Valid || !res.Applicable {
		t.Fatalf("%s: want Valid+Applicable, got status=%v applicable=%v issues=%+v",
			label, res.Status, res.Applicable, res.Issues)
	}
	assertNoCanary(t, label, res)
}

// expectAuthIssue asserts a closed, value-free authMode issue (dependencyMissing
// for a partial pair / missing eligible credential, or dependencyIncompatible
// for a disallowed inferred mode) with Invalid + not-applicable, and that no
// canary leaked.
func expectAuthIssue(t *testing.T, label string, res nodes.Result, code nodes.IssueCode) {
	t.Helper()
	if res.Status != nodes.Invalid || res.Applicable {
		t.Fatalf("%s: want Invalid+not-applicable, got status=%v applicable=%v issues=%+v",
			label, res.Status, res.Applicable, res.Issues)
	}
	if !hasIssue(res, code, "authMode") {
		t.Fatalf("%s: want %s on authMode, got %+v", label, code, res.Issues)
	}
	assertNoCanary(t, label, res)
}

// creds returns a trusted presence map with exactly the named credentials set
// to true (the others absent).
func creds(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

// TestAuthModeExplicitNone: explicit ACTIVE "none" is coherent with ANY trusted
// credential presence — none, username only, both. Credentials remain sealed and
// untouched (no clear / GC / downgrade). Both socks5 and http, valid + applicable.
func TestAuthModeExplicitNone(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range []string{"socks5", "http"} {
		active := minValid(proto)
		active["authMode"] = "none"
		for _, c := range []struct {
			label string
			pres  map[string]bool
		}{
			{"nopresence", creds()},
			{"useronly", creds("username")},
			{"both", creds("username", "password")},
		} {
			res := authValidate(t, p, proto, active, nil, c.pres)
			expectAuthOK(t, proto+"/none/"+c.label, res)
		}
	}
}

// TestAuthModeExplicitUserpass: explicit ACTIVE "userpass" requires BOTH
// eligible credentials sealed. Both present => valid; missing either =>
// dependencyMissing on authMode, Invalid/not-applicable (never silent no-auth).
func TestAuthModeExplicitUserpass(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range []string{"socks5", "http"} {
		active := minValid(proto)
		active["authMode"] = "userpass"
		both := authValidate(t, p, proto, active, nil, creds("username", "password"))
		expectAuthOK(t, proto+"/userpass/both", both)

		nouser := authValidate(t, p, proto, active, nil, creds("password"))
		expectAuthIssue(t, proto+"/userpass/nouser", nouser, nodes.IssueDependencyMissing)
		nopass := authValidate(t, p, proto, active, nil, creds("username"))
		expectAuthIssue(t, proto+"/userpass/nopass", nopass, nodes.IssueDependencyMissing)
		none := authValidate(t, p, proto, active, nil, creds())
		expectAuthIssue(t, proto+"/userpass/none", none, nodes.IssueDependencyMissing)
	}
}

// TestAuthModeTrulyAbsent: selector absent from BOTH buckets. The real profile
// has two eligible credentials:
//
//	none present     => coherent none (valid)
//	both present     => coherent userpass (valid)
//	exactly one      => dependencyMissing on authMode (legacy partial pair,
//	                    invalid retainable draft, NEVER silent no-auth)
func TestAuthModeTrulyAbsent(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range []string{"socks5", "http"} {
		active := minValid(proto) // no authMode key in either bucket
		none := authValidate(t, p, proto, active, nil, creds())
		expectAuthOK(t, proto+"/absent/none", none)

		both := authValidate(t, p, proto, active, nil, creds("username", "password"))
		expectAuthOK(t, proto+"/absent/both", both)

		useronly := authValidate(t, p, proto, active, nil, creds("username"))
		expectAuthIssue(t, proto+"/absent/useronly", useronly, nodes.IssueDependencyMissing)
		passonly := authValidate(t, p, proto, active, nil, creds("password"))
		expectAuthIssue(t, proto+"/absent/passonly", passonly, nodes.IssueDependencyMissing)
	}
}

// TestAuthModeAbsentPreservesSecretPlaintextRefusal: a submitted plaintext
// secret key is still refused even under explicit none / absent intent — the
// auth rule never launders a secretPlaintextSubmitted, and trusted presence
// does not make a submitted secret value acceptable.
func TestAuthModeAbsentPreservesSecretPlaintextRefusal(t *testing.T) {
	p := loadProfile(t)
	active := minValid("socks5")
	active["authMode"] = "none"
	active["username"] = secretCanary // plaintext smuggle of a secret name
	res := authValidate(t, p, "socks5", active, nil, creds("username", "password"))
	if res.Status != nodes.Invalid {
		t.Fatalf("plaintext secret under none: want Invalid, got %+v", res.Issues)
	}
	if !hasIssue(res, nodes.IssueSecretPlaintextSubmitted, "username") {
		t.Fatalf("plaintext secret under none: want secretPlaintextSubmitted, got %+v", res.Issues)
	}
	assertNoCanary(t, "plaintext-secret-none", res)
}

// TestAuthModeInactiveOnlySelector: authMode present ONLY in the inactive
// bucket is PRESERVED, NOT legacy absence — it runs no credential activation or
// fallback/demand. Credentials stay sealed and untouched; the node is otherwise
// valid. A shape-invalid retained inactive value is not promoted.
func TestAuthModeInactiveOnlySelector(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range []string{"socks5", "http"} {
		active := minValid(proto) // no authMode in active
		for _, retained := range []any{"userpass", 12345, true} {
			inactive := map[string]any{"authMode": retained}
			for _, pres := range []map[string]bool{creds(), creds("username")} {
				res := authValidate(t, p, proto, active, inactive, pres)
				expectAuthOK(t, proto+"/inactive-only", res)
			}
		}
	}
}

// TestAuthModeActiveInactiveCollision: authMode in BOTH buckets stays the
// generic envelopeMemberConflict (not an auth finding); presence value never
// leaks.
func TestAuthModeActiveInactiveCollision(t *testing.T) {
	p := loadProfile(t)
	active := minValid("socks5")
	active["authMode"] = "none"
	inactive := map[string]any{"authMode": "userpass"}
	res := authValidate(t, p, "socks5", active, inactive, creds("username", "password"))
	if res.Status != nodes.Invalid {
		t.Fatalf("collision: want Invalid, got %+v", res.Issues)
	}
	if !hasIssue(res, nodes.IssueEnvelopeMemberConflict, "fields") {
		t.Fatalf("collision: want envelopeMemberConflict, got %+v", res.Issues)
	}
	assertNoCanary(t, "collision", res)
}

// TestAuthModeNullIsTypeMismatch: an active authMode:null in an otherwise
// canonical bucket is a per-field typeMismatch (accepted outer envelope), NOT a
// malformedEnvelope and NOT an auth demand. Exact raw is retained separately
// by ValidateDocument (D-016); here we assert the shape finding only.
func TestAuthModeNullIsTypeMismatch(t *testing.T) {
	p := loadProfile(t)
	active := minValid("socks5")
	active["authMode"] = nil
	res := authValidate(t, p, "socks5", active, nil, creds())
	if res.Status != nodes.Invalid {
		t.Fatalf("null authMode: want Invalid, got %+v", res.Issues)
	}
	if !hasIssue(res, nodes.IssueTypeMismatch, "authMode") {
		t.Fatalf("null authMode: want typeMismatch on authMode, got %+v", res.Issues)
	}
	assertNoCanary(t, "null-authmode", res)
}

// --- Declaration-guard partial profiles (real parser, actual metadata) ---

// authGuardProfile builds a profile with one protocol having a `server`
// string + an `authMode` declaration and the given credential fields, so each
// case mutates the selector / companion metadata independently (declaration
// authority, not the full authored profile).
func authGuardProfile(t *testing.T, authModeDecl, credDecls string) *capability.Profile {
	t.Helper()
	fields := `"server":{"type":"string","classification":"known"}`
	if authModeDecl != "" {
		fields += `,` + authModeDecl
	}
	if credDecls != "" {
		fields += `,` + credDecls
	}
	raw := []byte(`{"profileVersion":5,"protocols":{"p":{"fields":{` + fields + `}}}}`)
	prof, err := capability.Parse(raw)
	if err != nil {
		t.Fatalf("auth guard profile did not parse: %v\n%s", err, raw)
	}
	return prof
}

const fullAuthMode = `"authMode":{"type":"enum","classification":"known","allowedValues":["none","userpass"]}`
const twoCreds = `"username":{"type":"string","classification":"secret","secret":true},"password":{"type":"string","classification":"secret","secret":true}`

// TestAuthSelectorUndeclaredIsInert: a protocol with credentials but NO
// authMode selector is unaffected — any presence split is valid, no demand.
func TestAuthSelectorUndeclaredIsInert(t *testing.T) {
	p := authGuardProfile(t, "", twoCreds)
	for _, pres := range []map[string]bool{creds(), creds("username"), creds("username", "password")} {
		res := authValidate(t, p, "p", map[string]any{"server": "x"}, nil, pres)
		expectAuthOK(t, "undeclared/"+presenceLabel(pres), res)
	}
}

// TestAuthSelectorIneligibleIsInert: a declared authMode that is secret /
// wrong-type / unsupported / out-of-subset is INERT even when absent — no
// absent-resolution and no invented credential demand runs from it.
func TestAuthSelectorIneligibleIsInert(t *testing.T) {
	decls := []struct{ label, decl string }{
		{"secret", `"authMode":{"type":"enum","classification":"secret","secret":true,"allowedValues":["none","userpass"]}`},
		{"wrongtype", `"authMode":{"type":"string","classification":"known"}`},
		{"unsupported", `"authMode":{"type":"enum","classification":"known","supported":false,"allowedValues":["none","userpass"]}`},
		// A subset-only enum is still an ELIGIBLE selector (it participates in
		// absent-resolution and exercises subset authority); it is NOT inert.
		// Genuine ineligibility is secret / wrong-type / unsupported metadata.
	}
	for _, d := range decls {
		// Absent selector + a legacy partial pair: an ELIGIBLE absent selector
		// would flag it; an ineligible one must not.
		p := authGuardProfile(t, d.decl, twoCreds)
		res := authValidate(t, p, "p", map[string]any{"server": "x"}, nil, creds("username"))
		expectAuthOK(t, "ineligible-absent/"+d.label, res)
		// An ACTIVE value gets only its own ORDINARY per-field finding (never an
		// auth demand). secret->secretPlaintextSubmitted, unsupported->
		// unsupportedField. wrongtype("none" is a valid STRING per a string
		// declaration) and outofsubset("none" is a valid enum member) produce no
		// per-field error and run no auth demand -> simply valid/inert.
		res2 := authValidate(t, p, "p", map[string]any{"server": "x", "authMode": "none"}, nil, creds())
		switch d.label {
		case "secret", "unsupported":
			if res2.Status == nodes.Valid {
				t.Fatalf("ineligible active %s: want an ordinary per-field issue, got valid", d.label)
			}
		default: // wrongtype: "none" is a valid STRING per a string declaration
			if res2.Status != nodes.Valid {
				t.Fatalf("ineligible active %s: want valid/inert (no demand, no per-field error), got %+v", d.label, res2.Issues)
			}
		}
		assertNoCanary(t, "ineligible-active/"+d.label, res2)
	}
}

// TestAuthActualEnumSubsetAuthority: the inferred effective mode must belong to
// the selector's ACTUAL allowedValues. A subset that excludes "userpass"
// refuses an inferred userpass (both credentials present, absent selector)
// with dependencyIncompatible — never silently invents a disallowed mode. A
// subset that excludes "none" refuses an inferred none.
func TestAuthActualEnumSubsetAuthority(t *testing.T) {
	// Subset WITHOUT userpass: both credentials present => inferred userpass is
	// not in the subset -> dependencyIncompatible on authMode.
	noUserpass := `"authMode":{"type":"enum","classification":"known","allowedValues":["none"]}`
	p := authGuardProfile(t, noUserpass, twoCreds)
	res := authValidate(t, p, "p", map[string]any{"server": "x"}, nil, creds("username", "password"))
	expectAuthIssue(t, "subset-no-userpass/both", res, nodes.IssueDependencyIncompatible)
	// none still coherent in that subset.
	resNone := authValidate(t, p, "p", map[string]any{"server": "x"}, nil, creds())
	expectAuthOK(t, "subset-no-userpass/none", resNone)

	// Subset WITHOUT none: no credentials => inferred none is not in the
	// subset -> dependencyIncompatible.
	noNone := `"authMode":{"type":"enum","classification":"known","allowedValues":["userpass"]}`
	p2 := authGuardProfile(t, noNone, twoCreds)
	res2 := authValidate(t, p2, "p", map[string]any{"server": "x"}, nil, creds())
	expectAuthIssue(t, "subset-no-none/none", res2, nodes.IssueDependencyIncompatible)
	resBoth := authValidate(t, p2, "p", map[string]any{"server": "x"}, nil, creds("username", "password"))
	expectAuthOK(t, "subset-no-none/both", resBoth)
}

// TestAuthPartialEligibleCompanions: only ELIGIBLE (secret string, supported)
// declared companions count. A wrong-type / known / unsupported / undeclared
// companion is never an invented credential target.
func TestAuthPartialEligibleCompanions(t *testing.T) {
	// Only username is an eligible credential; password is declared KNOWN
	// (wrong classification) so it never counts as a credential.
	oneEligible := `"username":{"type":"string","classification":"secret","secret":true},"password":{"type":"string","classification":"known"}`
	p := authGuardProfile(t, fullAuthMode, oneEligible)
	// userpass requires the one eligible credential only.
	res := authValidate(t, p, "p", map[string]any{"server": "x", "authMode": "userpass"}, nil, creds("username"))
	expectAuthOK(t, "one-eligible/userpass-username", res)
	resMiss := authValidate(t, p, "p", map[string]any{"server": "x", "authMode": "userpass"}, nil, creds())
	expectAuthIssue(t, "one-eligible/userpass-missing", resMiss, nodes.IssueDependencyMissing)
	// Absent selector: with one eligible credential, present => userpass,
	// absent => none. The known "password" never participates.
	resAbsent := authValidate(t, p, "p", map[string]any{"server": "x"}, nil, creds("username"))
	expectAuthOK(t, "one-eligible/absent-userpass", resAbsent)
	resAbsentNone := authValidate(t, p, "p", map[string]any{"server": "x"}, nil, creds())
	expectAuthOK(t, "one-eligible/absent-none", resAbsentNone)
}

// TestAuthZeroEligibleCompanionsNoDemand: a profile with an eligible authMode
// but NO eligible credential companions invents no demand and no unsupported
// issue — explicit userpass and absent selector are both simply coherent.
func TestAuthZeroEligibleCompanionsNoDemand(t *testing.T) {
	p := authGuardProfile(t, fullAuthMode, "")
	res := authValidate(t, p, "p", map[string]any{"server": "x", "authMode": "userpass"}, nil, creds())
	expectAuthOK(t, "zero-elig/userpass", res)
	resAbsent := authValidate(t, p, "p", map[string]any{"server": "x"}, nil, creds())
	expectAuthOK(t, "zero-elig/absent", resAbsent)
}

// presenceLabel gives a short deterministic label for a presence split.
func presenceLabel(m map[string]bool) string {
	switch {
	case m["username"] && m["password"]:
		return "both"
	case m["username"]:
		return "useronly"
	case m["password"]:
		return "passonly"
	default:
		return "none"
	}
}
