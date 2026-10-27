package api_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/api"
)

// authoredProfile loads the repository's authored capability profile bytes
// directly — in the product these bytes come only from trusted service
// initialization, never from the process cwd or from clients. Test access is
// via an explicit path passed to the test binary's working directory.
func authoredProfile(t *testing.T) *api.Profile {
	t.Helper()
	raw, err := os.ReadFile("../../contracts/capability-profile.json")
	if err != nil {
		t.Fatalf("read authored profile: %v", err)
	}
	p, err := api.ParseCapabilityProfile(raw)
	if err != nil {
		t.Fatalf("ParseCapabilityProfile(authored): %v", err)
	}
	if p.Version() != 3 {
		t.Fatalf("profile version = %d, want 3", p.Version())
	}
	return p
}

const (
	secretCanary  = "CANARY-SECRET-VALUE-5d4c"
	unknownCanary = "CANARY-UNKNOWN-FIELD-88"
	nestedCanary  = "CANARY-NESTED-LEAF-71"
	urlCredCanary = "https://user:CANARY-URL-PASS@host.example"
)

func TestProfileFailsClosedOnBadMetadata(t *testing.T) {
	cases := map[string]string{
		"empty":                "",
		"garbage":              "not json at all {{{",
		"missing version":      `{"protocols":{"vless":{"fields":{"server":{"type":"string","classification":"known"}}}}}`,
		"zero version":         `{"profileVersion":0,"protocols":{"vless":{"fields":{"server":{"type":"string","classification":"known"}}}}}`,
		"no protocols":         `{"profileVersion":1,"protocols":{}}`,
		"bad type":             `{"profileVersion":1,"protocols":{"vless":{"fields":{"server":{"type":"weird","classification":"known"}}}}}`,
		"bad class":            `{"profileVersion":1,"protocols":{"vless":{"fields":{"server":{"type":"string","classification":"maybe"}}}}}`,
		"secret flag on known": `{"profileVersion":1,"protocols":{"vless":{"fields":{"server":{"type":"string","classification":"known","secret":true}}}}}`,
		"secret without flag":  `{"profileVersion":1,"protocols":{"vless":{"fields":{"u":{"type":"string","classification":"secret"}}}}}`,
		"enum without values":  `{"profileVersion":1,"protocols":{"vless":{"fields":{"t":{"type":"enum","classification":"known"}}}}}`,
		"array wrong itemType": `{"profileVersion":1,"protocols":{"vless":{"fields":{"a":{"type":"array","classification":"known","itemType":"object"}}}}}`,
		"inverted bounds":      `{"profileVersion":1,"protocols":{"vless":{"fields":{"s":{"type":"string","classification":"known","minLength":9,"maxLength":2}}}}}`,
		"bad regex":            `{"profileVersion":1,"protocols":{"wireguard":{"fields":{"r":{"type":"string","classification":"known","pattern":"([0-9"}}}}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := api.ParseCapabilityProfile([]byte(raw))
			if err == nil {
				t.Fatalf("accepted malformed profile (%s)", name)
			}
			if p != nil {
				t.Fatal("non-nil profile with error")
			}
			if !strings.Contains(err.Error(), "profile rejected") {
				t.Fatalf("err = %v, want ErrProfileRejected text", err)
			}
		})
	}
}

func TestProjectUnknownProtocolEmpty(t *testing.T) {
	p := authoredProfile(t)
	_, err := api.ProjectNodeFields(p, "not-a-protocol", map[string]any{"server": "h"}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("unknown protocol err = %v", err)
	}
}

// TestProjectAllFourProtocols walks every protocol with a representative
// valid node: declared known fields must project, declared secrets appear
// ONLY as presence booleans, and the whole projection must be JSON-safe with
// no secret canaries anywhere in serialization.
func TestProjectAllFourProtocols(t *testing.T) {
	p := authoredProfile(t)
	type tc struct {
		proto    string
		fields   map[string]any
		presence map[string]bool
		wantKeys []string // known fields expected in active
		secretOn []string // secret fields expected present=true
	}
	cases := []tc{
		{"vless", map[string]any{
			"server": "v.example", "serverPort": float64(443), "uuid": secretCanary,
			"transport": "ws", "security": "tls", "alpn": []any{"h3", "h2"},
			"tfo": true, "finalMask": map[string]any{"leaf": nestedCanary},
			"xhttpExtra": map[string]any{"deep": map[string]any{"leaf": nestedCanary}},
		}, map[string]bool{"uuid": true},
			[]string{"server", "serverPort", "transport", "security"},
			[]string{"uuid"}},
		{"socks5", map[string]any{
			"server": "s.example", "serverPort": float64(1080),
			"username": secretCanary, "password": secretCanary,
			"udpAssociate": true, "chainMode": "off",
		}, map[string]bool{"username": true, "password": true},
			[]string{"server", "serverPort", "udpAssociate", "chainMode"},
			[]string{"username", "password"}},
		{"http", map[string]any{
			"server": "h.example", "serverPort": float64(8443), "tls": true,
			"username": secretCanary, "password": secretCanary,
		}, map[string]bool{"username": false, "password": true},
			[]string{"server", "serverPort", "tls"},
			[]string{"password"}},
		{"wireguard", map[string]any{
			"endpoint": "w.example", "endpointPort": float64(51820),
			"publicKey": "pub", "privateKey": secretCanary, "preSharedKey": secretCanary,
			"localAddresses": []any{"10.0.0.2/32"}, "mtu": float64(1420), "keepAlive": float64(25),
			"reserved":  []any{float64(0), float64(0), float64(0)},
			"finalMask": map[string]any{"leaf": nestedCanary},
		}, map[string]bool{"privateKey": true},
			[]string{"endpoint", "endpointPort", "publicKey", "localAddresses", "mtu", "keepAlive", "reserved"},
			[]string{"privateKey"}},
	}
	for _, c := range cases {
		t.Run(c.proto, func(t *testing.T) {
			proj, err := api.ProjectNodeFields(p, c.proto, c.fields, c.presence, nil)
			if err != nil {
				t.Fatalf("project: %v", err)
			}
			for _, k := range c.wantKeys {
				if _, ok := proj.Active[k]; !ok {
					t.Errorf("declared known field %s missing from active", k)
				}
			}
			// Secrets: presence booleans only.
			for k, want := range c.presence {
				got, ok := proj.Secrets[k]
				if !ok || got != want {
					t.Errorf("secret %s presence = %v,%v want %v", k, got, ok, want)
				}
			}
			// tfo is supported:false -> must be inactive, never active.
			if c.proto == "vless" {
				if _, inActive := proj.Active["tfo"]; inActive {
					t.Error("unsupported field tfo leaked into active")
				}
				if _, inInactive := proj.Inactive["tfo"]; !inInactive {
					t.Error("unsupported field tfo missing from inactive")
				}
			}
			// finalMask / xhttpExtra: opaque objects must NOT be copied.
			for _, opaque := range []string{"finalMask", "xhttpExtra"} {
				for _, m := range []map[string]any{proj.Active, proj.Inactive} {
					if v, ok := m[opaque]; ok {
						t.Errorf("opaque object %s leaked into projection: %v", opaque, v)
					}
				}
				if _, declared := c.fields[opaque]; declared {
					found := false
					for _, u := range proj.Unsupported {
						if u == opaque {
							found = true
						}
					}
					if !found {
						t.Errorf("opaque %s not reported in Unsupported", opaque)
					}
				}
			}
			// Serialization of the whole projection must carry no canaries.
			out, err := json.Marshal(proj)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			for _, canary := range []string{secretCanary, nestedCanary} {
				if bytes.Contains(out, []byte(canary)) {
					t.Fatalf("canary %q present in serialized projection", canary)
				}
			}
			// The projection JSON decodes as plain JSON objects of expected shape.
			var back map[string]any
			if err := json.Unmarshal(out, &back); err != nil {
				t.Fatalf("projection not plain json: %v", err)
			}
		})
	}
}

func TestUnknownNestedAndTypedFailuresAreFiltered(t *testing.T) {
	p := authoredProfile(t)
	fields := map[string]any{
		// valid declared known
		"server":     "ok.example",
		"serverPort": float64(1),
		// unknown at top level
		"mysteryField":    unknownCanary,
		"secretLookalike": map[string]any{"token": urlCredCanary},
		// declared known but WRONG type
		"sni":             map[string]any{"nested": nestedCanary},
		"xudpConcurrency": "not-a-number",
		// declared known array with an object inside -> whole value refused
		"alpn": []any{"h2", map[string]any{"evil": nestedCanary}},
		// declared known out-of-allowed-values enum
		"security": "quantum",
		// declared secret with a value: must NEVER pass the value
		"uuid": secretCanary,
	}
	proj, err := api.ProjectNodeFields(p, "vless", fields, map[string]bool{"uuid": true}, nil)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	out, _ := json.Marshal(proj)
	for _, canary := range []string{unknownCanary, nestedCanary, urlCredCanary, secretCanary} {
		if bytes.Contains(out, []byte(canary)) {
			t.Fatalf("canary %q leaked in projection: %s", canary, out)
		}
	}
	if proj.Active["server"] != "ok.example" {
		t.Errorf("valid field lost: %v", proj.Active)
	}
	for _, bad := range []string{"mysteryField", "secretLookalike", "sni", "xudpConcurrency", "alpn", "security"} {
		for _, m := range []map[string]any{proj.Active, proj.Inactive} {
			if _, ok := m[bad]; ok {
				t.Errorf("filtered field %s present in projection", bad)
			}
		}
	}
	if v, ok := proj.Secrets["uuid"]; !ok || !v {
		t.Errorf("uuid presence = %v,%v", v, ok)
	}
	// SecretUpdate sentinel semantics preserved by this package.
	if !api.SecretUpdateIsReservedSentinel("__RAYLANE_SECRET_UNCHANGED_V1__") {
		t.Error("exact sentinel must be recognized")
	}
	for _, legit := range []string{"••••", "********", "***", "«hidden»", "__RAYLANE_SECRET_UNCHANGED_V1__x", "__raylane_secret_unchanged_v1__"} {
		if api.SecretUpdateIsReservedSentinel(legit) {
			t.Errorf("mask-lookalike %q must be a legitimate value", legit)
		}
	}
}

func TestInactiveFilteringBothDirections(t *testing.T) {
	p := authoredProfile(t)
	// declared activeByDefault:false -> inactive automatically (finalMask);
	// declared supported:false -> inactive automatically (tfo);
	// caller-marked inactive moves a normally-active field.
	proj, err := api.ProjectNodeFields(p, "socks5", map[string]any{
		"server": "a", "serverPort": float64(2), "tfo": true, "udpAssociate": false,
	}, nil, map[string]bool{"server": true})
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if _, ok := proj.Inactive["server"]; !ok {
		t.Error("caller-marked inactive field not in inactive")
	}
	if _, ok := proj.Active["server"]; ok {
		t.Error("inactive field present in active")
	}
	if _, ok := proj.Inactive["tfo"]; !ok {
		t.Error("unsupported field must be inactive")
	}
	if _, ok := proj.Active["tfo"]; ok {
		t.Error("unsupported field leaked to active")
	}
}

// TestDiagnosticsClosedVocabulary covers T007-S2: the diagnostic API takes
// only closed-vocabulary codes and emits ONLY package-owned constant text,
// and only for protocols whose authored profile declares the mapped carrier
// field as a known string. A credential-bearing caller string has no
// parameter to travel through — even a forced cast of one is rejected.
func TestDiagnosticsClosedVocabulary(t *testing.T) {
	// Profile bytes with an explicit known-string carrier ("notes") so the
	// mechanism itself is exercisable without touching the contracts file.
	raw := `{"profileVersion":1,"protocols":{"p":{"fields":{"sni":{"type":"string","classification":"known","maxLength":253},"server":{"type":"string","classification":"known","maxLength":253},"uuid":{"type":"string","classification":"secret","secret":true}}}}}`
	p, err := api.ParseCapabilityProfile([]byte(raw))
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	// The reviewer's exact attack class: an arbitrary credential-shaped
	// string forced through DiagnosticCode must be an unknown code, dropped.
	credential := api.DiagnosticCode("https://user:CANARY-PASSWORD@host.example")
	got := api.BuildDiagnostic(p, "p", []api.DiagnosticCode{
		api.DiagConfigParseFailed,
		api.DiagApplyPending,
		credential,
		api.DiagnosticCode("42"),
		api.DiagnosticCode(""),
	})
	out, _ := json.Marshal(got)
	if bytes.Contains(out, []byte("CANARY-PASSWORD")) {
		t.Fatalf("credential-shaped cast leaked: %s", out)
	}
	// Only valid codes whose carrier is declared are emitted, with fixed text.
	if len(got) != 2 {
		t.Fatalf("expected exactly the 2 valid codes, got %v", got)
	}
	if e, ok := got[string(api.DiagConfigParseFailed)]; !ok || e.Code != api.DiagConfigParseFailed || e.Value == "" {
		t.Errorf("valid code missing or valueless: %v", got)
	}
	// Value bytes come from the package, never the caller.
	for _, e := range got {
		if strings.Contains(e.Value, "CANARY") {
			t.Fatalf("caller bytes in emitted value: %v", e)
		}
	}
	// Unknown protocol still emits nothing (fail-closed preserved).
	if d := api.BuildDiagnostic(p, "nope", []api.DiagnosticCode{api.DiagApplyPending}); len(d) != 0 {
		t.Errorf("unknown protocol emitted diagnostics: %v", d)
	}
	// The REAL authored profile: carriers exist only where the field is
	// declared known-string (vless/http declare sni; socks5/wireguard do
	// not), so emission is profile-gated and codes never invent fields.
	ap := authoredProfile(t)
	if d := api.BuildDiagnostic(ap, "socks5", []api.DiagnosticCode{api.DiagConfigParseFailed}); len(d) != 0 {
		t.Errorf("socks5 has no carrier yet emitted %v", d)
	}
	if d := api.BuildDiagnostic(ap, "vless", []api.DiagnosticCode{api.DiagConfigParseFailed}); len(d) != 1 {
		t.Errorf("vless carrier declared yet emitted %v", d)
	}
	for _, e := range api.BuildDiagnostic(ap, "vless", []api.DiagnosticCode{api.DiagConfigParseFailed, api.DiagSecretMissing}) {
		if e.Value == "" {
			t.Errorf("empty package text: %v", e)
		}
	}
	// JSON shape is plain and value-bearing codes never alias caller input.
	var back map[string]api.Diagnostic
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("diagnostics not plain json: %v", err)
	}
}

func TestNilProfileAndNilGuards(t *testing.T) {
	var p *api.Profile
	if _, err := api.ProjectNodeFields(p, "vless", map[string]any{"server": "x"}, nil, nil); err == nil {
		t.Error("nil profile must fail closed")
	}
	if d := api.BuildDiagnostic(p, "vless", []api.DiagnosticCode{api.DiagApplyPending}); len(d) != 0 {
		t.Error("nil profile diagnostics must be empty")
	}
}

func TestArrayFieldsProjectScalarOnly(t *testing.T) {
	// Array behavior asserted separately with profile-conforming values.
	p := authoredProfile(t)
	proj, err := api.ProjectNodeFields(p, "vless", map[string]any{
		"server": "a", "serverPort": float64(1), "alpn": []any{"h2", "h3"},
		"pinSHA256": []any{"abcd", "ef01"},
	}, nil, nil)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if arr, ok := proj.Active["alpn"].([]any); !ok || len(arr) != 2 {
		t.Errorf("alpn not projected: %v", proj.Active["alpn"])
	}
	if arr, ok := proj.Active["pinSHA256"].([]any); !ok || len(arr) != 2 {
		t.Errorf("pinSHA256 not projected: %v", proj.Active["pinSHA256"])
	}
}
