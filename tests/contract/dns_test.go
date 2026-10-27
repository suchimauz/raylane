// Package contract_test — B1 DNS / Happy Eyeballs behavior contract.
//
// These are REAL nodes.Validate + ValidateDocument executions against the
// authored v3 profile, not source/fixture checks. They pin the FR-004
// node-host DNS Auto/TCP/UDP/DoH modes and independent Happy Eyeballs rules
// (D-019/D-020/D-046), including preservation of inactive manual preference
// and exact submitted bytes (D-012/D-015/D-016). Positive controls ensure the
// validator is not reject-everything.
package contract_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// resolverCanary / credentialCanary / quarantineCanary must NEVER appear in a
// validation result/issue/diagnostic/log. (A valid known DNS value MAY appear
// in an explicitly requested projection, but never in a *result*.)
const (
	resolverCanary   = "203.0.113.999" // invalid dotted IPv4 (octet 999)
	credentialCanary = "https://user:CANARY-DOH-PASS@dns.example/dns-query"
	quarantineCanary = "CANARY-QUARANTINE-DNS"
)

func dnsProtos() []string { return []string{"vless", "socks5", "http"} }

// assertResultNoDNSCanary: a *validation result* must never carry the resolver,
// credential or quarantine canary anywhere in its serialized form.
func assertResultNoDNSCanary(t *testing.T, label string, res nodes.Result) {
	t.Helper()
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(res); err != nil {
		t.Fatalf("%s: encode result: %v", label, err)
	}
	for _, c := range []string{resolverCanary, credentialCanary, quarantineCanary, secretCanary, unknownCanary, urlCredCanary} {
		if bytes.Contains(buf.Bytes(), []byte(c)) {
			t.Fatalf("%s: canary %q leaked into validation result: %s", label, c, buf.String())
		}
	}
}

// TestDNSAbsentDefaultsValid: with NO DNS fields submitted, each of the three
// protocols is still valid+applicable (defaults auto/absent do not gate, and
// absence is never materialized into the submitted map).
func TestDNSAbsentDefaultsValid(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range dnsProtos() {
		t.Run(proto, func(t *testing.T) {
			active := minValid(proto)
			before, _ := json.Marshal(active)
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if res.Status != nodes.Valid || !res.Applicable {
				t.Fatalf("%s minimal valid without DNS: %+v", proto, res.Issues)
			}
			after, _ := json.Marshal(active)
			if !bytes.Equal(before, after) {
				t.Fatalf("%s: Validate mutated submitted map", proto)
			}
			if _, ok := active["dnsMode"]; ok {
				t.Fatalf("%s: absent dnsMode was materialized into the map", proto)
			}
			assertResultNoDNSCanary(t, proto, res)
		})
	}
}

// TestDNSExplicitAutoValid: explicit dnsMode=auto with no resolver is valid.
func TestDNSExplicitAutoValid(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range dnsProtos() {
		t.Run(proto, func(t *testing.T) {
			active := minValid(proto)
			active["dnsMode"] = "auto"
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if res.Status != nodes.Valid || !res.Applicable {
				t.Fatalf("%s dnsMode=auto: %+v", proto, res.Issues)
			}
		})
	}
}

// TestDNSAutoWithActiveResolverIncompatible: effective auto + an ACTIVE
// resolver is a conflict (rule 7/2); an explicitly INACTIVE resolver is allowed
// and retained.
func TestDNSAutoWithActiveResolverIncompatible(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range dnsProtos() {
		t.Run(proto+"/active-resolver-rejected", func(t *testing.T) {
			active := minValid(proto)
			active["dnsMode"] = "auto"
			active["dnsServer"] = "203.0.113.10"
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if !hasIssue(res, nodes.IssueDependencyIncompatible, "dnsServer") {
				t.Fatalf("%s auto+active dnsServer: want dependencyIncompatible on dnsServer, got %+v", proto, res.Issues)
			}
			if res.Applicable {
				t.Fatalf("%s: auto+active resolver must be inapplicable", proto)
			}
			assertResultNoDNSCanary(t, proto, res)
		})
		t.Run(proto+"/inactive-resolver-allowed", func(t *testing.T) {
			active := minValid(proto)
			active["dnsMode"] = "auto"
			inactive := map[string]any{"dnsServer": "203.0.113.10", "dnsServerUrl": "https://dns.example/dns-query"}
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, Inactive: inactive, SecretPresence: trustedPresenceFor(proto)})
			if res.Status != nodes.Valid {
				t.Fatalf("%s auto+inactive resolver must be valid (retained, not promoted): %+v", proto, res.Issues)
			}
		})
	}
}

// TestDNSTcpUdpRequireActiveServer: active tcp/udp needs an ACTIVE valid
// dnsServer; missing, inactive-only, or unknown-only never satisfies; an
// active dnsServerUrl is incompatible.
func TestDNSTcpUdpRequireActiveServer(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range dnsProtos() {
		for _, mode := range []string{"tcp", "udp"} {
			t.Run(proto+"/"+mode+"/missing", func(t *testing.T) {
				active := minValid(proto)
				active["dnsMode"] = mode
				res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
				if !hasIssue(res, nodes.IssueDependencyMissing, "dnsServer") {
					t.Fatalf("%s %s no resolver: want dependencyMissing on dnsServer, got %+v", proto, mode, res.Issues)
				}
				if res.Applicable {
					t.Fatalf("%s %s missing resolver must be inapplicable", proto, mode)
				}
			})
			t.Run(proto+"/"+mode+"/valid", func(t *testing.T) {
				active := minValid(proto)
				active["dnsMode"] = mode
				active["dnsServer"] = "203.0.113.10"
				res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
				if res.Status != nodes.Valid || !res.Applicable {
					t.Fatalf("%s %s valid resolver: %+v", proto, mode, res.Issues)
				}
			})
			t.Run(proto+"/"+mode+"/inactive-only-resolver-not-satisfy", func(t *testing.T) {
				active := minValid(proto)
				active["dnsMode"] = mode
				inactive := map[string]any{"dnsServer": "203.0.113.10"}
				res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, Inactive: inactive, SecretPresence: trustedPresenceFor(proto)})
				if !hasIssue(res, nodes.IssueDependencyMissing, "dnsServer") {
					t.Fatalf("%s %s inactive-only resolver: want dependencyMissing, got %+v", proto, mode, res.Issues)
				}
			})
			t.Run(proto+"/"+mode+"/url-incompatible", func(t *testing.T) {
				active := minValid(proto)
				active["dnsMode"] = mode
				active["dnsServer"] = "203.0.113.10"
				active["dnsServerUrl"] = "https://dns.example/dns-query"
				res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
				if !hasIssue(res, nodes.IssueDependencyIncompatible, "dnsServerUrl") {
					t.Fatalf("%s %s active url: want dependencyIncompatible on dnsServerUrl, got %+v", proto, mode, res.Issues)
				}
			})
		}
	}
}

// TestDNSDohRequireActiveUrl: active doh needs an ACTIVE valid dnsServerUrl;
// active dnsServer is incompatible.
func TestDNSDohRequireActiveUrl(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range dnsProtos() {
		t.Run(proto+"/missing", func(t *testing.T) {
			active := minValid(proto)
			active["dnsMode"] = "doh"
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if !hasIssue(res, nodes.IssueDependencyMissing, "dnsServerUrl") {
				t.Fatalf("%s doh no url: want dependencyMissing on dnsServerUrl, got %+v", proto, res.Issues)
			}
		})
		t.Run(proto+"/valid", func(t *testing.T) {
			active := minValid(proto)
			active["dnsMode"] = "doh"
			active["dnsServerUrl"] = "https://dns.example/dns-query"
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if res.Status != nodes.Valid || !res.Applicable {
				t.Fatalf("%s doh valid url: %+v", proto, res.Issues)
			}
		})
		t.Run(proto+"/server-incompatible", func(t *testing.T) {
			active := minValid(proto)
			active["dnsMode"] = "doh"
			active["dnsServerUrl"] = "https://dns.example/dns-query"
			active["dnsServer"] = "203.0.113.10"
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if !hasIssue(res, nodes.IssueDependencyIncompatible, "dnsServer") {
				t.Fatalf("%s doh active server: want dependencyIncompatible on dnsServer, got %+v", proto, res.Issues)
			}
		})
		t.Run(proto+"/inactive-url-not-satisfy", func(t *testing.T) {
			active := minValid(proto)
			active["dnsMode"] = "doh"
			inactive := map[string]any{"dnsServerUrl": "https://dns.example/dns-query"}
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, Inactive: inactive, SecretPresence: trustedPresenceFor(proto)})
			if !hasIssue(res, nodes.IssueDependencyMissing, "dnsServerUrl") {
				t.Fatalf("%s doh inactive-only url: want dependencyMissing, got %+v", proto, res.Issues)
			}
		})
	}
}

// TestDNSModeInvalidNotCorrected: an invalid dnsMode is a loud enum/type
// violation, never rewritten or defaulted; no misleading duplicate cascade.
func TestDNSModeInvalidNotCorrected(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range dnsProtos() {
		t.Run(proto+"/enum", func(t *testing.T) {
			active := minValid(proto)
			active["dnsMode"] = "bogus"
			before, _ := json.Marshal(active)
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if !hasIssue(res, nodes.IssueEnumViolation, "dnsMode") {
				t.Fatalf("%s invalid dnsMode: want enumViolation, got %+v", proto, res.Issues)
			}
			after, _ := json.Marshal(active)
			if !bytes.Equal(before, after) || active["dnsMode"] != "bogus" {
				t.Fatalf("%s: invalid dnsMode was rewritten/defaulted", proto)
			}
		})
		t.Run(proto+"/wrong-type", func(t *testing.T) {
			active := minValid(proto)
			active["dnsMode"] = float64(7)
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if !hasIssue(res, nodes.IssueTypeMismatch, "dnsMode") {
				t.Fatalf("%s wrong-type dnsMode: want typeMismatch, got %+v", proto, res.Issues)
			}
		})
	}
}

// TestDNSServerGrammar: dnsServer accepts bare IPv4, hostname/trailing dot,
// bracketed IPv6 with valid port; rejects bad octets, bad brackets, bad labels,
// ports 0/65536/empty/nonnumeric, and never echoes the bad value.
func TestDNSServerGrammar(t *testing.T) {
	p := loadProfile(t)
	valid := []string{
		"203.0.113.10",
		"resolver.example",
		"resolver.example.",
		"203.0.113.10:53",
		"[2001:db8::1]",
		"[2001:db8::1]:853",
		"resolver.example:5353",
	}
	invalid := []string{
		"203.0.113.999",      // bad octet
		"203.0.113.10:0",     // port 0
		"203.0.113.10:65536", // port too big
		"203.0.113.10:",      // empty port
		"203.0.113.10:abc",   // nonnumeric port
		"-bad.example",       // leading hyphen label
		"bad-.example",       // trailing hyphen label
		"2001:db8::1",        // IPv6 without brackets
		"[2001:db8::1",       // unbalanced bracket
		"203.0.113.10 extra", // whitespace
		"",                   // empty
	}
	for _, proto := range dnsProtos() {
		for _, srv := range valid {
			t.Run(proto+"/ok/"+srv, func(t *testing.T) {
				active := minValid(proto)
				active["dnsMode"] = "tcp"
				active["dnsServer"] = srv
				res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
				if res.Status != nodes.Valid {
					t.Fatalf("%s dnsServer=%q want valid, got %+v", proto, srv, res.Issues)
				}
			})
		}
		for _, srv := range invalid {
			t.Run(proto+"/bad/"+srv, func(t *testing.T) {
				active := minValid(proto)
				active["dnsMode"] = "tcp"
				active["dnsServer"] = srv
				res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
				if res.Status == nodes.Valid {
					t.Fatalf("%s dnsServer=%q must be invalid", proto, srv)
				}
				// A pattern/bounds/type issue must be present, and the bad value
				// must not be echoed.
				if len(res.Issues) == 0 {
					t.Fatalf("%s dnsServer=%q produced no issue", proto, srv)
				}
				assertResultNoDNSCanary(t, proto, res)
			})
		}
	}
}

// TestDNSDohUrlGrammar: dnsServerUrl accepts valid https DoH URLs with
// host/path/port/IPv6; rejects other scheme, userinfo, query/fragment, empty
// host/port, control/backslash, and malformed escapes.
func TestDNSDohUrlGrammar(t *testing.T) {
	p := loadProfile(t)
	valid := []string{
		"https://dns.example/dns-query",
		"https://dns.example",
		"https://dns.example:853/dns-query",
		"https://[2001:db8::1]/dns-query",
		"https://[2001:db8::1]:853/",
		"https://203.0.113.10/dns-query",
	}
	invalid := []string{
		"http://dns.example/dns-query",            // wrong scheme
		"https://user:pass@dns.example/dns-query", // userinfo
		"https://dns.example/dns-query?x=1",       // query
		"https://dns.example/dns-query#frag",      // fragment
		"https://dns.example/dns-query?",          // empty query marker
		"https://dns.example/dns-query#",          // empty fragment marker
		"https://:853/dns-query",                  // empty host
		"https://dns.example:0/dns-query",         // port 0
		"https://dns.example:65536/dns-query",     // port too big
		"https://dns.example:abc/dns-query",       // nonnumeric port
		"https://dns.example\\path",               // backslash
		"https://dns.exa mple/dns-query",          // whitespace/control
		"https://dns.example/%zz",                 // invalid escape
		"ftp://dns.example/dns-query",             // other scheme
	}
	for _, proto := range dnsProtos() {
		for _, u := range valid {
			t.Run(proto+"/ok/"+u, func(t *testing.T) {
				active := minValid(proto)
				active["dnsMode"] = "doh"
				active["dnsServerUrl"] = u
				res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
				if res.Status != nodes.Valid {
					t.Fatalf("%s dnsServerUrl=%q want valid, got %+v", proto, u, res.Issues)
				}
			})
		}
		for _, u := range invalid {
			t.Run(proto+"/bad/"+u, func(t *testing.T) {
				active := minValid(proto)
				active["dnsMode"] = "doh"
				active["dnsServerUrl"] = u
				res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
				if res.Status == nodes.Valid {
					t.Fatalf("%s dnsServerUrl=%q must be invalid", proto, u)
				}
				if len(res.Issues) == 0 {
					t.Fatalf("%s dnsServerUrl=%q produced no issue", proto, u)
				}
				assertResultNoDNSCanary(t, proto, res)
			})
		}
	}
}

// TestDNSHappyEyeballsIndependent: HE true with a manual strategy is a
// conflict on the strategy; with strategy auto/absent it is fine. An INACTIVE
// true HE does not disable an active manual strategy. Wrong type is
// typeMismatch, never coerced.
func TestDNSHappyEyeballsIndependent(t *testing.T) {
	p := loadProfile(t)
	for _, proto := range dnsProtos() {
		t.Run(proto+"/he-with-manual-conflict", func(t *testing.T) {
			active := minValid(proto)
			active["happyEyeballs"] = true
			active["dnsStrategy"] = "prefer_ipv4"
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if !hasIssue(res, nodes.IssueDependencyIncompatible, "dnsStrategy") {
				t.Fatalf("%s HE+manual: want dependencyIncompatible on dnsStrategy, got %+v", proto, res.Issues)
			}
		})
		t.Run(proto+"/he-with-auto-ok", func(t *testing.T) {
			active := minValid(proto)
			active["happyEyeballs"] = true
			active["dnsStrategy"] = "auto"
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if res.Status != nodes.Valid {
				t.Fatalf("%s HE+auto strategy must be valid: %+v", proto, res.Issues)
			}
		})
		t.Run(proto+"/he-absent-strategy-manual-ok", func(t *testing.T) {
			active := minValid(proto)
			active["happyEyeballs"] = true
			// no dnsStrategy submitted
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if res.Status != nodes.Valid {
				t.Fatalf("%s HE alone must be valid: %+v", proto, res.Issues)
			}
		})
		t.Run(proto+"/inactive-he-keeps-manual-strategy", func(t *testing.T) {
			active := minValid(proto)
			active["dnsStrategy"] = "prefer_ipv6"
			inactive := map[string]any{"happyEyeballs": true}
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, Inactive: inactive, SecretPresence: trustedPresenceFor(proto)})
			if res.Status != nodes.Valid {
				t.Fatalf("%s inactive HE + active manual strategy must be valid: %+v", proto, res.Issues)
			}
		})
		t.Run(proto+"/he-wrong-type", func(t *testing.T) {
			active := minValid(proto)
			active["happyEyeballs"] = "yes"
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if !hasIssue(res, nodes.IssueTypeMismatch, "happyEyeballs") {
				t.Fatalf("%s HE wrong type: want typeMismatch, got %+v", proto, res.Issues)
			}
		})
		t.Run(proto+"/both-he-states", func(t *testing.T) {
			for _, v := range []bool{true, false} {
				active := minValid(proto)
				active["happyEyeballs"] = v
				res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
				if res.Status != nodes.Valid {
					t.Fatalf("%s happyEyeballs=%v must be valid: %+v", proto, v, res.Issues)
				}
			}
		})
	}
}

// TestDNSStrategyFiveValues: all five manual/auto strategy values accepted;
// legacy happy_eyeballs is a loud enumViolation with the raw value preserved.
func TestDNSStrategyFiveValues(t *testing.T) {
	p := loadProfile(t)
	five := []string{"auto", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"}
	for _, proto := range dnsProtos() {
		for _, s := range five {
			t.Run(proto+"/"+s, func(t *testing.T) {
				active := minValid(proto)
				active["dnsStrategy"] = s
				res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
				if res.Status != nodes.Valid {
					t.Fatalf("%s strategy=%s must be valid: %+v", proto, s, res.Issues)
				}
			})
		}
		t.Run(proto+"/legacy-happy-eyeballs-rejected", func(t *testing.T) {
			active := minValid(proto)
			active["dnsStrategy"] = "happy_eyeballs"
			before, _ := json.Marshal(active)
			res := nodes.Validate(p, nodes.Input{Protocol: proto, Active: active, SecretPresence: trustedPresenceFor(proto)})
			if !hasIssue(res, nodes.IssueEnumViolation, "dnsStrategy") {
				t.Fatalf("%s legacy happy_eyeballs: want enumViolation, got %+v", proto, res.Issues)
			}
			if res.Applicable {
				t.Fatalf("%s legacy token must be inapplicable", proto)
			}
			after, _ := json.Marshal(active)
			if !bytes.Equal(before, after) || active["dnsStrategy"] != "happy_eyeballs" {
				t.Fatalf("%s: legacy strategy token was rewritten", proto)
			}
		})
	}
}

// TestDNSWireGuardUnchanged: wireguard is NOT subjected to DNS rules (it has
// no DNS declarations) and stays valid with its minimal config.
func TestDNSWireGuardUnchanged(t *testing.T) {
	p := loadProfile(t)
	active := minValid("wireguard")
	res := nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: active, SecretPresence: trustedPresenceFor("wireguard")})
	if res.Status != nodes.Valid {
		t.Fatalf("wireguard must be unaffected by DNS rules: %+v", res.Issues)
	}
}

// TestDNSValidateDocumentExactRaw: ValidateDocument preserves EXACT submitted
// bytes for a semantically-invalid DNS draft (e.g. HE+manual conflict, and a
// legacy strategy token) and marks it ValidationInvalid.
func TestDNSValidateDocumentExactRaw(t *testing.T) {
	p := loadProfile(t)
	envelope := func(active map[string]any) []byte {
		doc := map[string]any{
			"protocol": "vless",
			"fields": map[string]any{
				"active":   active,
				"inactive": map[string]any{},
				"unknown":  map[string]any{},
			},
		}
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal envelope: %v", err)
		}
		return b
	}
	base := minValid("vless")
	trusted := trustedPresenceFor("vless")

	// Case 1: HE + manual strategy conflict.
	a1 := map[string]any{}
	for k, v := range base {
		a1[k] = v
	}
	a1["happyEyeballs"] = true
	a1["dnsStrategy"] = "prefer_ipv4"
	orig1 := envelope(a1)
	got1, err1 := nodes.ValidateDocument(p, orig1, trusted)
	if err1 != nil {
		t.Fatalf("envelope decode: %v", err1)
	}
	if got1.Validation != domain.ValidationInvalid {
		t.Fatalf("want ValidationInvalid, got %v", got1.Validation)
	}
	if !bytes.Equal(got1.Document.Raw, orig1) {
		t.Fatalf("exact raw not preserved for HE+manual conflict")
	}
	if !hasIssue(got1.Result, nodes.IssueDependencyIncompatible, "dnsStrategy") {
		t.Fatalf("want dependencyIncompatible on dnsStrategy, got %+v", got1.Result.Issues)
	}

	// Case 2: legacy strategy token preserved verbatim.
	a2 := map[string]any{}
	for k, v := range base {
		a2[k] = v
	}
	a2["dnsStrategy"] = "happy_eyeballs"
	orig2 := envelope(a2)
	got2, err2 := nodes.ValidateDocument(p, orig2, trusted)
	if err2 != nil {
		t.Fatalf("envelope decode: %v", err2)
	}
	if got2.Validation != domain.ValidationInvalid {
		t.Fatalf("legacy token: want ValidationInvalid, got %v", got2.Validation)
	}
	if !bytes.Equal(got2.Document.Raw, orig2) {
		t.Fatalf("legacy token: exact raw not preserved")
	}
	if !hasIssue(got2.Result, nodes.IssueEnumViolation, "dnsStrategy") {
		t.Fatalf("legacy token: want enumViolation, got %+v", got2.Result.Issues)
	}

	// Case 3: malformed JSON still fails the syntax gate (not persisted).
	if _, err := nodes.ValidateDocument(p, []byte("{not json"), trusted); !errors.Is(err, domain.ErrMalformedJSON) {
		t.Fatalf("malformed JSON must stay ErrMalformedJSON, got %v", err)
	}
}

// TestDNSProjectionValidKnownReturned: a VALID known DNS value IS read and
// projected (round-trip), while secret/unknown values stay filtered. The
// resolver value may appear in an explicitly requested projection, but never
// in a validation *result*.
func TestDNSProjectionValidKnownReturned(t *testing.T) {
	p := loadProfile(t)
	active := minValid("vless")
	active["dnsMode"] = "tcp"
	active["dnsServer"] = "203.0.113.10"
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: active, SecretPresence: trustedPresenceFor("vless")})
	if res.Status != nodes.Valid {
		t.Fatalf("valid DNS node must be valid: %+v", res.Issues)
	}
	// Projection returns the valid known scalar.
	proj, err := p.ProjectNodeFields("vless", active, map[string]bool{"uuid": true}, nil)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if proj.Active["dnsServer"] != "203.0.113.10" {
		t.Fatalf("projection must round-trip valid known dnsServer, got %+v", proj.Active)
	}
	if proj.Active["dnsMode"] != "tcp" {
		t.Fatalf("projection must round-trip valid known dnsMode, got %+v", proj.Active)
	}
	// A secret is presence-only and never a value; a secret NOT submitted as a
	// key does not appear in the projection at all (the store owns sealed
	// material, and the projection iterates submitted field keys). What must
	// hold: no secret VALUE anywhere, and the known DNS scalars round-trip.
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(proj); err != nil {
		t.Fatalf("encode projection: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte(secretCanary)) {
		t.Fatalf("secret value leaked into projection")
	}
}
