package nodes

import (
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
)

// partialProfile parses a minimal but VALID profile with only the named DNS
// field declarations on a single protocol. It is used to prove the cross-field
// rules are declaration-driven: an absent/unsupported companion must never be
// invented as a dependency target. Returns nil+false on parse failure.
func partialProfile(t *testing.T, fields string) *capability.Profile {
	t.Helper()
	raw := `{"profileVersion":2,"protocols":{"probe":{"fields":{` + fields + `}}}}`
	p, err := capability.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("partial profile did not parse: %v\nfields=%s", err, fields)
	}
	return p
}

// hasIssueCode reports whether the result carries an issue with the given code
// on ANY field (the declaration-guard defect emits on an undeclared name).
func hasIssueCode(res Result, code IssueCode) bool {
	for _, is := range res.Issues {
		if is.Code == code {
			return true
		}
	}
	return false
}

// TestDeclarationGuard_ModeOnlyNoInventedResolver is V4-T011B1-DNS-
// DECLARATION-GUARD. A profile declaring ONLY dnsMode (known enum) must NOT
// have the cross-field rules invent dnsServer/dnsServerUrl dependency targets
// that the authority does not declare.
func TestDeclarationGuard_ModeOnlyNoInventedResolver(t *testing.T) {
	modeOnly := partialProfile(t, `"dnsMode":{"type":"enum","classification":"known","allowedValues":["auto","tcp","udp","doh"]}`)

	// tcp with no resolver field declared: must NOT emit dependencyMissing on
	// an undeclared dnsServer.
	res := Validate(modeOnly, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "tcp"}})
	if hasIssueCode(res, IssueDependencyMissing) {
		t.Fatalf("tcp with no declared dnsServer: invented dependencyMissing: %+v", res.Issues)
	}
	if hasIssueCode(res, IssueDependencyIncompatible) {
		t.Fatalf("tcp with no declared resolver: invented dependencyIncompatible: %+v", res.Issues)
	}

	// doh with no resolver declared: must NOT invent dnsServerUrl.
	res = Validate(modeOnly, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "doh"}})
	if hasIssueCode(res, IssueDependencyMissing) || hasIssueCode(res, IssueDependencyIncompatible) {
		t.Fatalf("doh with no declared dnsServerUrl: invented issue: %+v", res.Issues)
	}

	// auto with an UNKNOWN submitted resolver key: the unknown is reported as
	// unknownField (ordinary validator), NOT dependencyIncompatible.
	res = Validate(modeOnly, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "auto", "dnsServer": "203.0.113.10"}})
	if hasIssueCode(res, IssueDependencyIncompatible) {
		t.Fatalf("auto with undeclared dnsServer key: must be unknown only, not dependencyIncompatible: %+v", res.Issues)
	}
	if !hasIssueCode(res, IssueUnknownField) {
		t.Fatalf("auto with undeclared dnsServer key: expected the ordinary unknownField finding: %+v", res.Issues)
	}
}

// TestDeclarationGuard_ServerAndModeNoInventedUrl: a profile declaring
// dnsMode + dnsServer but NOT dnsServerUrl must not invent a dnsServerUrl
// requirement under doh.
func TestDeclarationGuard_ServerAndModeNoInventedUrl(t *testing.T) {
	p := partialProfile(t,
		`"dnsMode":{"type":"enum","classification":"known","allowedValues":["auto","tcp","udp","doh"]},`+
			`"dnsServer":{"type":"string","classification":"known","minLength":1,"maxLength":253}`)
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "doh", "dnsServer": "203.0.113.10"}})
	if hasIssueCode(res, IssueDependencyMissing) {
		t.Fatalf("doh with declared dnsServer but no dnsServerUrl: invented dnsServerUrl dependencyMissing: %+v", res.Issues)
	}
}

// TestDeclarationGuard_UnsupportedCompanionNotRequired: a resolver declared
// supported:false is not eligible as an active requirement target — tcp must
// NOT emit dependencyMissing demanding an unsupported field be present.
func TestDeclarationGuard_UnsupportedCompanionNotRequired(t *testing.T) {
	p := partialProfile(t,
		`"dnsMode":{"type":"enum","classification":"known","allowedValues":["auto","tcp","udp","doh"]},`+
			`"dnsServer":{"type":"string","classification":"known","minLength":1,"maxLength":253,"supported":false}`)
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "tcp"}})
	if hasIssueCode(res, IssueDependencyMissing) {
		t.Fatalf("tcp with only an UNSUPPORTED dnsServer: must not demand it: %+v", res.Issues)
	}
}

// TestDeclarationGuard_PartialProfileStillEnforces: when BOTH the selector and
// the eligible companion ARE declared, the requirement still fires (the guard
// must not disable legitimate rules).
func TestDeclarationGuard_PartialProfileStillEnforces(t *testing.T) {
	p := partialProfile(t,
		`"dnsMode":{"type":"enum","classification":"known","allowedValues":["auto","tcp","udp","doh"]},`+
			`"dnsServer":{"type":"string","classification":"known","minLength":1,"maxLength":253}`)
	// tcp + declared dnsServer but absent -> dependencyMissing on dnsServer.
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "tcp"}})
	if !hasIssueOnField(res, IssueDependencyMissing, "dnsServer") {
		t.Fatalf("tcp with declared dnsServer absent: want dependencyMissing on dnsServer, got %+v", res.Issues)
	}
	// tcp + active valid dnsServer -> valid.
	res = Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "tcp", "dnsServer": "203.0.113.10"}})
	if res.Status != Valid {
		t.Fatalf("tcp + declared valid dnsServer: want valid, got %+v", res.Issues)
	}
}

// TestDeclarationGuard_HEOnlyNoInventedStrategy: HE helpers must not invent a
// dnsStrategy incompatibility when dnsStrategy is undeclared; and an active
// true HE alone is fine.
func TestDeclarationGuard_HEOnlyNoInventedStrategy(t *testing.T) {
	heOnly := partialProfile(t, `"happyEyeballs":{"type":"boolean","classification":"known"}`)
	res := Validate(heOnly, Input{Protocol: "probe", Active: map[string]any{"happyEyeballs": true}})
	if hasIssueCode(res, IssueDependencyIncompatible) {
		t.Fatalf("HE-only profile: invented dnsStrategy incompatibility: %+v", res.Issues)
	}
	// HE true with an UNKNOWN submitted strategy key: unknown only, not incompatible.
	res = Validate(heOnly, Input{Protocol: "probe", Active: map[string]any{"happyEyeballs": true, "dnsStrategy": "prefer_ipv4"}})
	if hasIssueCode(res, IssueDependencyIncompatible) {
		t.Fatalf("HE-only profile + unknown strategy key: must be unknown only: %+v", res.Issues)
	}
	if !hasIssueCode(res, IssueUnknownField) {
		t.Fatalf("HE-only + unknown strategy key: expected ordinary unknownField: %+v", res.Issues)
	}
}

// TestDeclarationGuard_HEStrategyBothDeclaredStillEnforces: when both HE and a
// manual strategy are declared, the incompatibility still fires.
func TestDeclarationGuard_HEStrategyBothDeclaredStillEnforces(t *testing.T) {
	p := partialProfile(t,
		`"happyEyeballs":{"type":"boolean","classification":"known"},`+
			`"dnsStrategy":{"type":"enum","classification":"known","allowedValues":["auto","prefer_ipv4"]}`)
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"happyEyeballs": true, "dnsStrategy": "prefer_ipv4"}})
	if !hasIssueOnField(res, IssueDependencyIncompatible, "dnsStrategy") {
		t.Fatalf("declared HE+manual strategy: want dependencyIncompatible on dnsStrategy, got %+v", res.Issues)
	}
}

func hasIssueOnField(res Result, code IssueCode, field string) bool {
	for _, is := range res.Issues {
		if is.Code == code && is.Field == field {
			return true
		}
	}
	return false
}

// --- Selector eligibility + actual allowedValues (V4-T011B1 selector-R2) ---
//
// The residual V4-T011B1-DNS-DECLARATION-GUARD: dnsModeState hardcoded the enum
// tokens and discarded the field metadata, and dnsStrategyView hardcoded the
// manual-strategy tokens instead of reading the field's actual AllowedValues.
// A profile may therefore declare dnsMode as a boolean/string, as an enum with
// a SUBSET of modes, or dnsStrategy with a subset — and the rules must obey
// the ACTUAL declared authority (membership + type + support + classification),
// not a fixed token list. valueOK already validates a value against the real
// AllowedValues; these tests pin that the cross-field rules do the same.

// TestSelectorEligibility_NonEnumModeDoesNotDemand: a dnsMode declared as a
// NON-enum (boolean, or a plain known string) must not be treated as an enum
// selector and must not manufacture a resolver demand. The ordinary per-field
// validator reports the field's own finding; the cross-field rules stay silent.
func TestSelectorEligibility_NonEnumModeDoesNotDemand(t *testing.T) {
	// boolean declaration + string "tcp" value -> typeMismatch:dnsMode only.
	boolMode := partialProfile(t,
		`"dnsMode":{"type":"boolean","classification":"known"},`+
			`"dnsServer":{"type":"string","classification":"known","minLength":1,"maxLength":253}`)
	res := Validate(boolMode, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "tcp"}})
	if !hasIssueOnField(res, IssueTypeMismatch, "dnsMode") {
		t.Fatalf("boolean dnsMode + tcp: want typeMismatch:dnsMode, got %+v", res.Issues)
	}
	if hasIssueCode(res, IssueDependencyMissing) || hasIssueCode(res, IssueDependencyIncompatible) {
		t.Fatalf("boolean dnsMode + tcp: must not demand a resolver: %+v", res.Issues)
	}

	// known STRING declaration + "tcp": the value is a valid string; the field
	// is not an enum selector, so no type error is invented and no demand.
	strMode := partialProfile(t,
		`"dnsMode":{"type":"string","classification":"known","minLength":1,"maxLength":16},`+
			`"dnsServer":{"type":"string","classification":"known","minLength":1,"maxLength":253}`)
	res = Validate(strMode, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "tcp"}})
	if hasIssueOnField(res, IssueTypeMismatch, "dnsMode") {
		t.Fatalf("string dnsMode + tcp: must not invent a type error: %+v", res.Issues)
	}
	if hasIssueCode(res, IssueDependencyMissing) || hasIssueCode(res, IssueDependencyIncompatible) {
		t.Fatalf("string dnsMode + tcp: must not demand a resolver: %+v", res.Issues)
	}
}

// TestSelectorEligibility_ModeSubsetMembership: dnsMode enum with an
// allowedValues SUBSET (e.g. [auto,doh]) — a submitted tcp is an enumViolation
// per actual metadata and must NOT trigger a resolver demand. Membership is
// defined by the declared metadata, not the hardcoded token switch.
func TestSelectorEligibility_ModeSubsetMembership(t *testing.T) {
	p := partialProfile(t,
		`"dnsMode":{"type":"enum","classification":"known","allowedValues":["auto","doh"]},`+
			`"dnsServer":{"type":"string","classification":"known","minLength":1,"maxLength":253},`+
			`"dnsServerUrl":{"type":"string","classification":"known","minLength":1,"maxLength":2048}`)
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "tcp"}})
	if !hasIssueOnField(res, IssueEnumViolation, "dnsMode") {
		t.Fatalf("dnsMode subset [auto,doh] + tcp: want enumViolation:dnsMode, got %+v", res.Issues)
	}
	if hasIssueCode(res, IssueDependencyMissing) || hasIssueCode(res, IssueDependencyIncompatible) {
		t.Fatalf("dnsMode subset [auto,doh] + tcp: must not demand a resolver: %+v", res.Issues)
	}
	// Positive control: doh IS in the subset and still requires the ELIGIBLE
	// dnsServerUrl companion (declared here), producing dependencyMissing.
	res = Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "doh"}})
	if !hasIssueOnField(res, IssueDependencyMissing, "dnsServerUrl") {
		t.Fatalf("doh in subset with eligible dnsServerUrl absent: want dependencyMissing:dnsServerUrl, got %+v", res.Issues)
	}
}

// TestSelectorEligibility_SecretModeDoesNotDemand: a secret-classified dnsMode
// yields secretPlaintextSubmitted for the active value and must NOT drive any
// resolver demand or inspect the secret.
func TestSelectorEligibility_SecretModeDoesNotDemand(t *testing.T) {
	p := partialProfile(t,
		`"dnsMode":{"type":"string","classification":"secret","secret":true},`+
			`"dnsServer":{"type":"string","classification":"known","minLength":1,"maxLength":253}`)
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "tcp"}})
	if !hasIssueOnField(res, IssueSecretPlaintextSubmitted, "dnsMode") {
		t.Fatalf("secret dnsMode: want secretPlaintextSubmitted:dnsMode, got %+v", res.Issues)
	}
	if hasIssueCode(res, IssueDependencyMissing) || hasIssueCode(res, IssueDependencyIncompatible) {
		t.Fatalf("secret dnsMode: must not demand a resolver or interpret the secret: %+v", res.Issues)
	}
}

// TestSelectorEligibility_UnsupportedModeDoesNotDemand: an unsupported enum
// selector yields the ordinary unsupported finding and must not cascade into a
// resolver demand.
func TestSelectorEligibility_UnsupportedModeDoesNotDemand(t *testing.T) {
	p := partialProfile(t,
		`"dnsMode":{"type":"enum","classification":"known","supported":false,"allowedValues":["auto","tcp","udp","doh"]},`+
			`"dnsServer":{"type":"string","classification":"known","minLength":1,"maxLength":253}`)
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "tcp"}})
	if !hasIssueOnField(res, IssueUnsupportedField, "dnsMode") {
		t.Fatalf("unsupported dnsMode: want unsupportedField:dnsMode, got %+v", res.Issues)
	}
	if hasIssueCode(res, IssueDependencyMissing) || hasIssueCode(res, IssueDependencyIncompatible) {
		t.Fatalf("unsupported dnsMode: must not demand a resolver: %+v", res.Issues)
	}
}

// TestSelectorEligibility_StrategySubsetMembership: dnsStrategy enum with a
// SUBSET (e.g. [auto,prefer_ipv4]) — a submitted ipv4_only is an enumViolation
// per actual metadata and must NOT trigger the HE conflict. Membership is by
// actual AllowedValues, not the hardcoded manual-token switch.
func TestSelectorEligibility_StrategySubsetMembership(t *testing.T) {
	p := partialProfile(t,
		`"happyEyeballs":{"type":"boolean","classification":"known"},`+
			`"dnsStrategy":{"type":"enum","classification":"known","allowedValues":["auto","prefer_ipv4"]}`)
	// ipv4_only is NOT in the declared subset -> enumViolation only, no conflict.
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"happyEyeballs": true, "dnsStrategy": "ipv4_only"}})
	if !hasIssueOnField(res, IssueEnumViolation, "dnsStrategy") {
		t.Fatalf("strategy subset [auto,prefer_ipv4] + ipv4_only: want enumViolation:dnsStrategy, got %+v", res.Issues)
	}
	if hasIssueOnField(res, IssueDependencyIncompatible, "dnsStrategy") {
		t.Fatalf("strategy subset + out-of-subset token: must NOT conflict: %+v", res.Issues)
	}
	// Positive control: prefer_ipv4 IS in the subset and still conflicts with HE.
	res = Validate(p, Input{Protocol: "probe", Active: map[string]any{"happyEyeballs": true, "dnsStrategy": "prefer_ipv4"}})
	if !hasIssueOnField(res, IssueDependencyIncompatible, "dnsStrategy") {
		t.Fatalf("HE + permitted prefer_ipv4: want dependencyIncompatible:dnsStrategy, got %+v", res.Issues)
	}
}

// TestSelectorEligibility_HEIndependentOfBadMode: an unrelated invalid/usable
// dnsMode selector must not suppress the independent HE-vs-manual-strategy
// conflict, and must not cascade a resolver demand from the bad selector.
func TestSelectorEligibility_HEIndependentOfBadMode(t *testing.T) {
	// Invalid enum value (not in declared subset) alongside a valid HE+manual
	// strategy: HE conflict STILL fires; the bad selector adds only its own
	// enumViolation and no resolver demand.
	p := partialProfile(t,
		`"dnsMode":{"type":"enum","classification":"known","allowedValues":["auto","doh"]},`+
			`"happyEyeballs":{"type":"boolean","classification":"known"},`+
			`"dnsStrategy":{"type":"enum","classification":"known","allowedValues":["auto","prefer_ipv4"]},`+
			`"dnsServer":{"type":"string","classification":"known","minLength":1,"maxLength":253}`)
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{
		"dnsMode":       "tcp", // not in [auto,doh] -> enumViolation, unusable selector
		"happyEyeballs": true,
		"dnsStrategy":   "prefer_ipv4",
	}})
	if !hasIssueOnField(res, IssueDependencyIncompatible, "dnsStrategy") {
		t.Fatalf("HE conflict must be independent of an invalid selector: want dependencyIncompatible:dnsStrategy, got %+v", res.Issues)
	}
	if !hasIssueOnField(res, IssueEnumViolation, "dnsMode") {
		t.Fatalf("invalid selector must still report its own enumViolation:dnsMode, got %+v", res.Issues)
	}
	if hasIssueCode(res, IssueDependencyMissing) {
		t.Fatalf("invalid selector must not cascade a resolver demand: %+v", res.Issues)
	}
}

// TestSelectorEligibility_PermittedModeStillEnforces: the eligible permitted
// controls still demand and satisfy companions (regression guard).
func TestSelectorEligibility_PermittedModeStillEnforces(t *testing.T) {
	p := partialProfile(t,
		`"dnsMode":{"type":"enum","classification":"known","allowedValues":["auto","tcp","udp","doh"]},`+
			`"dnsServer":{"type":"string","classification":"known","minLength":1,"maxLength":253},`+
			`"dnsServerUrl":{"type":"string","classification":"known","minLength":1,"maxLength":2048}`)
	// tcp + declared eligible dnsServer ABSENT -> demand it.
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "tcp"}})
	if !hasIssueOnField(res, IssueDependencyMissing, "dnsServer") {
		t.Fatalf("permitted tcp + absent eligible dnsServer: want dependencyMissing:dnsServer, got %+v", res.Issues)
	}
	// tcp + active valid dnsServer -> satisfied.
	res = Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "tcp", "dnsServer": "203.0.113.10"}})
	if res.Status != Valid {
		t.Fatalf("permitted tcp + valid dnsServer: want valid, got %+v", res.Issues)
	}
	// Explicit auto (absent-value distinct) with an active resolver -> incompatible.
	res = Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "auto", "dnsServer": "203.0.113.10"}})
	if !hasIssueOnField(res, IssueDependencyIncompatible, "dnsServer") {
		t.Fatalf("explicit auto + active dnsServer: want dependencyIncompatible:dnsServer, got %+v", res.Issues)
	}
}

// TestDoHPreciseGrammar_DirectPredicate is V4-T011B1-DOH-PRECISE-GRAMMAR at the
// direct seam: the precise predicate must reject raw empty fragment/query and
// explicit empty authority port EVEN without a profile regex, while keeping
// valid host / bracketed IPv6 / legal escaped path positives.
func TestDoHPreciseGrammar_DirectPredicate(t *testing.T) {
	mustReject := []string{
		"https://dns.example/dns-query#",          // empty fragment marker
		"https://dns.example/dns-query?",          // empty query marker
		"https://dns.example:/dns-query",          // explicit empty authority port
		"https://dns.example:0/dns-query",         // port 0
		"https://dns.example:65536/dns-query",     // port out of range
		"https://user:pass@dns.example/dns-query", // userinfo
		"https://dns.example\\path",               // backslash
	}
	for _, s := range mustReject {
		if dnsServerUrlOK(s) {
			t.Errorf("dnsServerUrlOK(%q) = true, want false", s)
		}
	}
	mustAccept := []string{
		"https://dns.example/dns-query",
		"https://dns.example",               // no path
		"https://dns.example:853/dns-query", // valid port
		"https://[2001:db8::1]/dns-query",   // bracketed IPv6
		"https://[2001:db8::1]:853/",        // IPv6 + port + root path
		"https://dns.example/dns%2Fquery",   // legal escaped path
		"https://dns.example/a%23b%3Fc",     // %23/%3F are path DATA, not raw markers
		"https://203.0.113.10/dns-query",    // IPv4 host
	}
	for _, s := range mustAccept {
		if !dnsServerUrlOK(s) {
			t.Errorf("dnsServerUrlOK(%q) = false, want true", s)
		}
	}
}

// TestDoHPreciseGrammar_PatternFreeValidate: a VALID pattern-free profile
// declaring known dnsMode enum + dnsServerUrl string (no regex) must still
// precisely reject a raw empty `#`/empty-port DoH URL through real Validate.
func TestDoHPreciseGrammar_PatternFreeValidate(t *testing.T) {
	p := partialProfile(t,
		`"dnsMode":{"type":"enum","classification":"known","allowedValues":["auto","tcp","udp","doh"]},`+
			`"dnsServerUrl":{"type":"string","classification":"known","minLength":1,"maxLength":2048}`)
	bad := []string{
		"https://dns.example/dns-query#",
		"https://dns.example/dns-query?",
		"https://dns.example:/dns-query",
	}
	for _, u := range bad {
		res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "doh", "dnsServerUrl": u}})
		if res.Status == Valid {
			t.Fatalf("pattern-free doh url=%q must be invalid", u)
		}
		if !hasIssueOnField(res, IssuePatternViolation, "dnsServerUrl") {
			t.Fatalf("pattern-free doh url=%q: want patternViolation on dnsServerUrl, got %+v", u, res.Issues)
		}
	}
	// Positive control: a valid URL passes end-to-end.
	res := Validate(p, Input{Protocol: "probe", Active: map[string]any{"dnsMode": "doh", "dnsServerUrl": "https://dns.example/dns-query"}})
	if res.Status != Valid {
		t.Fatalf("pattern-free valid doh url: want valid, got %+v", res.Issues)
	}
}

// TestDoHPreciseGrammar_DoesNotLeakMarkers: rejected raw markers never echo.
func TestDoHPreciseGrammar_DoesNotLeakMarkers(t *testing.T) {
	// The precise predicate must not accept a fragment-only or query-only URL,
	// and a rejected raw marker never leaks through any surface here.
	if dnsServerUrlOK("https://dns.example/#") {
		t.Fatalf("raw fragment-only URL accepted")
	}
	if dnsServerUrlOK("https://dns.example/?") {
		t.Fatalf("raw query-only URL accepted")
	}
}
