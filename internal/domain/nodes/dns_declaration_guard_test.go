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
