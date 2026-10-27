// Maintained behavior contract for v4-US1-FR003-FR008-structured-json
// (T010/T011 FR003/FR008/FR009/FR019, D-014/D-015/D-016/D-050).
//
// A real JSON object value for the structured targets (vless.xhttpExtra,
// vless.finalMask, wireguard.finalMask) is a valid SHAPE (no false
// typeMismatch), but an ACTIVE opaque object with no real engine-compat checker
// must NEVER become apply-ready: it is reported honestly as
// StructuredCheckNotRun (structurally Valid, NOT applicable). The known
// wrong-xhttp mode gets exactly ONE static dependencyIncompatible@xhttpExtra +
// StructuredCheckFailed. The readiness/mode rules are hard protocol-scoped by
// the ACTUAL input protocol and never leak into socks5/http/custom protocols.

package contract_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// deepCopyJSON makes a genuine type-preserving recursive deep copy of a decoded
// JSON value (map/slice/scalar), independent of any snapshot aliasing.
func deepCopyJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = deepCopyJSON(e)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = deepCopyJSON(e)
		}
		return s
	default:
		return x
	}
}

// assertStructuredValidNotRun pins the canonical "correct shape, opaque content"
// outcome: Valid status, not applicable, StructuredCheckNotRun, zero issues.
func assertStructuredValidNotRun(t *testing.T, res nodes.Result, label string) {
	t.Helper()
	if res.Status != nodes.Valid {
		t.Fatalf("%s: want Valid status, got %v issues=%+v", label, res.Status, res.Issues)
	}
	if res.Applicable {
		t.Fatalf("%s: opaque ACTIVE object must NOT be applicable, got applicable", label)
	}
	if res.StructuredCheck != nodes.StructuredCheckNotRun {
		t.Fatalf("%s: want StructuredCheckNotRun, got %v", label, res.StructuredCheck)
	}
	if len(res.Issues) != 0 {
		t.Fatalf("%s: want zero issues, got %+v", label, res.Issues)
	}
}

// TestStructuredObjectShape: real non-nil objects (nonempty nested + empty {})
// are valid shape; typed-nil DIRECT and JSON null canonical / wrong top-level
// scalar/string/array/bool/number are generic typeMismatch only, and the
// eligible ACTIVE target's own-bad-shape aggregate is StructuredCheckFailed
// (generic-first: NO duplicate issue, Failed is NOT a second finding).
func TestStructuredObjectShape(t *testing.T) {
	p := loadProfile(t)
	pres := trustedPresenceFor("vless")

	// Nonempty nested map: valid shape, NotRun/notApplicable, no typeMismatch.
	a := minValid("vless")
	a["transport"] = "xhttp"
	a["xhttpExtra"] = map[string]any{"headers": map[string]any{"Host": "x.example"}, "extra": map[string]any{}}
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	assertStructuredValidNotRun(t, res, "nonempty nested xhttpExtra")

	// Real empty {}: valid shape (no len==0 rejection), NotRun.
	a = minValid("vless")
	a["finalMask"] = map[string]any{}
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	assertStructuredValidNotRun(t, res, "empty finalMask {}")

	// Typed-nil DIRECT map: NOT an object -> generic typeMismatch only (one
	// issue) + StructuredCheckFailed (eligible ACTIVE own-bad-shape).
	var nilMap map[string]any
	a = minValid("vless")
	a["xhttpExtra"] = nilMap
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	if !hasIssue(res, nodes.IssueTypeMismatch, "xhttpExtra") || len(res.Issues) != 1 {
		t.Fatalf("typed-nil: want one typeMismatch@xhttpExtra (no duplicate), got %+v", res.Issues)
	}
	if res.Status != nodes.Invalid || res.Applicable || res.StructuredCheck != nodes.StructuredCheckFailed {
		t.Fatalf("typed-nil: want Invalid+notApplicable+Failed, got %v/%v/%v", res.Status, res.Applicable, res.StructuredCheck)
	}

	// Wrong top-level scalar/string/array/bool/number: generic typeMismatch only
	// (one issue) + StructuredCheckFailed (eligible ACTIVE own-bad-shape).
	for _, bad := range []any{"text", []any{1.0}, true, 1.5} {
		a = minValid("vless")
		a["xhttpExtra"] = bad
		res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
		if !hasIssue(res, nodes.IssueTypeMismatch, "xhttpExtra") || len(res.Issues) != 1 {
			t.Fatalf("xhttpExtra=%v: want one typeMismatch@xhttpExtra, got %+v", bad, res.Issues)
		}
		if res.StructuredCheck != nodes.StructuredCheckFailed {
			t.Fatalf("xhttpExtra=%v: eligible ACTIVE own-bad-shape must be Failed (generic-first, no duplicate), got %v", bad, res.StructuredCheck)
		}
	}

	// JSON null (canonical, via the real adapter): generic typeMismatch only.
	body := []byte(`{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"xhttp","security":"tls","xhttpExtra":null},"inactive":{},"unknown":{}}}`)
	ar, err := nodes.ValidateDocument(p, body, pres)
	if err != nil {
		t.Fatalf("null envelope refused: %v", err)
	}
	if !hasIssue(ar.Result, nodes.IssueTypeMismatch, "xhttpExtra") || len(ar.Result.Issues) != 1 {
		t.Fatalf("JSON null xhttpExtra: want one typeMismatch@xhttpExtra, got %+v", ar.Result.Issues)
	}
	if ar.Result.StructuredCheck != nodes.StructuredCheckFailed {
		t.Fatalf("JSON null xhttpExtra: eligible ACTIVE own-bad-shape must be Failed, got %v", ar.Result.StructuredCheck)
	}
}

// TestStructuredXHTTPMode: eligible ACTIVE valid-shape vless.xhttpExtra requires
// a usable transport that is a real member of its OWN AllowedValues; if the
// authority offers xhttp but active usable transport != xhttp -> exactly ONE
// static dependencyIncompatible@xhttpExtra + Failed. Usable xhttp -> NotRun.
func TestStructuredXHTTPMode(t *testing.T) {
	p := loadProfile(t)
	pres := trustedPresenceFor("vless")
	obj := map[string]any{"h": map[string]any{"Host": "x"}}

	// Usable xhttp transport: no mode conflict, NotRun/notApplicable, Valid.
	a := minValid("vless")
	a["transport"] = "xhttp"
	a["xhttpExtra"] = obj
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	assertStructuredValidNotRun(t, res, "xhttp+xhttpExtra")

	// Usable ws transport (authority offers xhttp) + xhttpExtra: ONE depIncompat.
	a = minValid("vless")
	a["transport"] = "ws"
	a["xhttpExtra"] = obj
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	if res.Status != nodes.Invalid || res.Applicable || res.StructuredCheck != nodes.StructuredCheckFailed {
		t.Fatalf("ws+xhttpExtra: want Invalid+notApplicable+Failed, got %v/%v/%v", res.Status, res.Applicable, res.StructuredCheck)
	}
	if len(res.Issues) != 1 || res.Issues[0].Code != nodes.IssueDependencyIncompatible || res.Issues[0].Field != "xhttpExtra" {
		t.Fatalf("ws+xhttpExtra: want exactly one dependencyIncompatible@xhttpExtra, got %+v", res.Issues)
	}

	// xhttpExtra absent -> NotRequired, no mode demand.
	a = minValid("vless")
	a["transport"] = "ws"
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	if res.StructuredCheck != nodes.StructuredCheckNotRequired {
		t.Fatalf("absent xhttpExtra: want NotRequired, got %v", res.StructuredCheck)
	}

	// Inactive xhttpExtra is preserved, not promoted, not shape-gated -> NotRequired.
	a = minValid("vless")
	a["transport"] = "ws"
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, Inactive: map[string]any{"xhttpExtra": "syntax-free"}, SecretPresence: pres})
	if res.StructuredCheck != nodes.StructuredCheckNotRequired {
		t.Fatalf("inactive xhttpExtra: want NotRequired (no inactive promotion), got %v", res.StructuredCheck)
	}
}

// TestStructuredFinalMaskNoPairing: eligible ACTIVE valid-shape vless/wireguard
// finalMask -> no fabricated mode pairing, no issue, NotRun/notApplicable.
func TestStructuredFinalMaskNoPairing(t *testing.T) {
	p := loadProfile(t)

	a := minValid("vless")
	a["finalMask"] = map[string]any{"ipv4": "198.18.0.0/16"}
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
	assertStructuredValidNotRun(t, res, "vless finalMask")

	wa := minValid("wireguard")
	wa["finalMask"] = map[string]any{"ipv6": "fd00::/64"}
	res = nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wa, SecretPresence: trustedPresenceFor("wireguard")})
	assertStructuredValidNotRun(t, res, "wireguard finalMask")
}

// TestStructuredScopeNoLeak: a custom/socks5/http protocol that declares a
// same-named object field is NOT a readiness target (actual-protocol scope).
func TestStructuredScopeNoLeak(t *testing.T) {
	mk := func(proto, fields string) *capability.Profile {
		raw := []byte(`{"profileVersion":5,"protocols":{"` + proto + `":{"fields":{` + fields + `}}}}`)
		p, err := capability.Parse(raw)
		if err != nil {
			t.Fatalf("custom profile parse: %v\n%s", err, raw)
		}
		return p
	}
	fields := `"server":{"type":"string","classification":"known","required":true},"xhttpExtra":{"type":"object","classification":"known"},"finalMask":{"type":"object","classification":"known"}`

	// custom protocol "custom" with xhttpExtra + finalMask active -> these are NOT
	// structured targets; valid-shape object -> no NotRun, stays NotRequired, no issue.
	pc := mk("custom", fields)
	a := map[string]any{"server": "c.example", "xhttpExtra": map[string]any{"k": 1.0}, "finalMask": map[string]any{}}
	res := nodes.Validate(pc, nodes.Input{Protocol: "custom", Active: a, SecretPresence: map[string]bool{}})
	if res.Status != nodes.Valid || !res.Applicable || res.StructuredCheck != nodes.StructuredCheckNotRequired || len(res.Issues) != 0 {
		t.Fatalf("custom xhttpExtra/finalMask must not trigger readiness (actual-protocol scope): %v/%v/%v issues=%+v", res.Status, res.Applicable, res.StructuredCheck, res.Issues)
	}

	// socks5 declares no object fields: a submitted object is an ordinary unknown.
	p := loadProfile(t)
	s := minValid("socks5")
	s["xhttpExtra"] = map[string]any{"k": 1.0}
	res = nodes.Validate(p, nodes.Input{Protocol: "socks5", Active: s, SecretPresence: map[string]bool{}})
	if res.StructuredCheck != nodes.StructuredCheckNotRequired || !hasIssue(res, nodes.IssueUnknownField, "unknown") {
		t.Fatalf("socks5 xhttpExtra: want NotRequired + ordinary unknownField, got %v issues=%+v", res.StructuredCheck, res.Issues)
	}
}

// TestStructuredParseAuthorityVariants: real capability.Parse custom-authority
// variants — each independently ineligible (undeclared / secret / supported=
// false / wrong type) leaves ordinary generic diagnostics + NotRequired, no
// fabricated demand; own-AllowedValues subsets gate the xhttp mode decision.
func TestStructuredParseAuthorityVariants(t *testing.T) {
	mk := func(fields string) *capability.Profile {
		raw := []byte(`{"profileVersion":5,"protocols":{"vless":{"fields":{` + fields + `}}}}`)
		p, err := capability.Parse(raw)
		if err != nil {
			t.Fatalf("variant profile parse: %v\n%s", err, raw)
		}
		return p
	}
	vlessBase := `"server":{"type":"string","classification":"known","required":true},"serverPort":{"type":"integer","classification":"known","required":true},"transport":{"type":"enum","classification":"known","required":true,"allowedValues":["raw","ws","grpc","xhttp"]},"security":{"type":"enum","classification":"known","required":true,"allowedValues":["tls","reality"]}`
	va := func(extra map[string]any) map[string]any {
		a := map[string]any{"server": "v.example", "serverPort": 443, "transport": "ws", "security": "tls"}
		for k, v := range extra {
			a[k] = v
		}
		return a
	}

	// secret-classified xhttpExtra: ordinary secretPlaintextSubmitted, NotRequired.
	pSec := mk(vlessBase + `,"xhttpExtra":{"type":"object","classification":"secret","secret":true}`)
	res := nodes.Validate(pSec, nodes.Input{Protocol: "vless", Active: va(map[string]any{"xhttpExtra": map[string]any{}}), SecretPresence: map[string]bool{}})
	if !hasIssue(res, nodes.IssueSecretPlaintextSubmitted, "xhttpExtra") || res.StructuredCheck != nodes.StructuredCheckNotRequired {
		t.Fatalf("secret xhttpExtra: want secretPlaintextSubmitted + NotRequired, got %v issues=%+v", res.StructuredCheck, res.Issues)
	}

	// supported=false xhttpExtra: ordinary unsupportedField, NotRequired.
	pSup := mk(vlessBase + `,"xhttpExtra":{"type":"object","classification":"known","supported":false}`)
	res = nodes.Validate(pSup, nodes.Input{Protocol: "vless", Active: va(map[string]any{"xhttpExtra": map[string]any{}}), SecretPresence: map[string]bool{}})
	if !hasIssue(res, nodes.IssueUnsupportedField, "xhttpExtra") || res.StructuredCheck != nodes.StructuredCheckNotRequired {
		t.Fatalf("unsupported xhttpExtra: want unsupportedField + NotRequired, got %v issues=%+v", res.StructuredCheck, res.Issues)
	}

	// wrong type (string) xhttpExtra: ordinary typeMismatch, NotRequired.
	pStr := mk(vlessBase + `,"xhttpExtra":{"type":"string","classification":"known","maxLength":64}`)
	res = nodes.Validate(pStr, nodes.Input{Protocol: "vless", Active: va(map[string]any{"xhttpExtra": map[string]any{}}), SecretPresence: map[string]bool{}})
	if !hasIssue(res, nodes.IssueTypeMismatch, "xhttpExtra") || res.StructuredCheck != nodes.StructuredCheckNotRequired {
		t.Fatalf("string xhttpExtra: want typeMismatch + NotRequired, got %v issues=%+v", res.StructuredCheck, res.Issues)
	}

	// AllowedValues WITHOUT xhttp: no manufactured demand; active valid-shape
	// xhttpExtra -> NotRun (no conflict), no issue.
	pNoX := mk(vlessBase + `,"xhttpExtra":{"type":"object","classification":"known"}`)
	pNoX = rewriteTransport(t, pNoX, []string{"raw", "ws", "grpc"}) // drop xhttp from AllowedValues
	res = nodes.Validate(pNoX, nodes.Input{Protocol: "vless", Active: va(map[string]any{"xhttpExtra": map[string]any{"k": 1.0}}), SecretPresence: map[string]bool{}})
	if res.StructuredCheck == nodes.StructuredCheckFailed || hasIssue(res, nodes.IssueDependencyIncompatible, "xhttpExtra") {
		t.Fatalf("authority without xhttp must NOT demand the mode: %v issues=%+v", res.StructuredCheck, res.Issues)
	}

	// Out-of-enum transport selector + xhttpExtra: ordinary enumViolation, no
	// mode conflict (selector unusable), NotRun for the valid-shape object.
	res = nodes.Validate(pNoX, nodes.Input{Protocol: "vless", Active: va(map[string]any{"transport": "bogus", "xhttpExtra": map[string]any{"k": 1.0}}), SecretPresence: map[string]bool{}})
	if !hasIssue(res, nodes.IssueEnumViolation, "transport") {
		t.Fatalf("out-of-enum transport: want enumViolation@transport, got %+v", res.Issues)
	}
	if hasIssue(res, nodes.IssueDependencyIncompatible, "xhttpExtra") {
		t.Fatalf("out-of-enum transport must not manufacture a mode conflict: %+v", res.Issues)
	}

	// Non-string active transport (null) + xhttpExtra: typeMismatch@transport,
	// selector unusable, no mode conflict.
	res = nodes.Validate(pNoX, nodes.Input{Protocol: "vless", Active: va(map[string]any{"transport": nil, "xhttpExtra": map[string]any{"k": 1.0}}), SecretPresence: map[string]bool{}})
	if !hasIssue(res, nodes.IssueTypeMismatch, "transport") || hasIssue(res, nodes.IssueDependencyIncompatible, "xhttpExtra") {
		t.Fatalf("null transport: want typeMismatch@transport + no conflict, got %+v", res.Issues)
	}
}

// rewriteTransport rebuilds a profile with a specific transport AllowedValues
// via capability.Parse (a real parse, not an invented metadata mutation).
func rewriteTransport(t *testing.T, _ *capability.Profile, allowed []string) *capability.Profile {
	t.Helper()
	av := ""
	for i, a := range allowed {
		if i > 0 {
			av += ","
		}
		av += `"` + a + `"`
	}
	raw := []byte(`{"profileVersion":5,"protocols":{"vless":{"fields":{"server":{"type":"string","classification":"known","required":true},"serverPort":{"type":"integer","classification":"known","required":true},"transport":{"type":"enum","classification":"known","required":true,"allowedValues":[` + av + `]},"security":{"type":"enum","classification":"known","required":true,"allowedValues":["tls","reality"]},"xhttpExtra":{"type":"object","classification":"known"}}}}}`)
	p, err := capability.Parse(raw)
	if err != nil {
		t.Fatalf("rewriteTransport parse: %v", err)
	}
	return p
}

// TestStructuredAggregation: Failed dominates NotRun; NotRun/Failed only reduce
// Applicable (never reset Status to Valid when issues exist, never overwrite a
// prior ChainCheck); zero-issue + NotRun may be Valid while not applicable.
func TestStructuredAggregation(t *testing.T) {
	p := loadProfile(t)
	pres := trustedPresenceFor("vless")

	// Failed dominates NotRun: ws transport (conflict) + xhttpExtra + finalMask.
	a := minValid("vless")
	a["transport"] = "ws"
	a["xhttpExtra"] = map[string]any{"k": 1.0}
	a["finalMask"] = map[string]any{}
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	if res.StructuredCheck != nodes.StructuredCheckFailed {
		t.Fatalf("Failed must dominate NotRun, got %v", res.StructuredCheck)
	}
	// one conflict issue only (finalMask adds none)
	if len(res.Issues) != 1 || res.Issues[0].Field != "xhttpExtra" {
		t.Fatalf("want one xhttpExtra conflict issue, got %+v", res.Issues)
	}

	// NotRun + an unrelated ordinary issue keeps Status Invalid (not reset).
	a = minValid("vless")
	a["transport"] = "xhttp"
	a["xhttpExtra"] = map[string]any{"k": 1.0}
	a["serverPort"] = "not-a-number"
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	if res.Status != nodes.Invalid || res.StructuredCheck != nodes.StructuredCheckNotRun || res.Applicable {
		t.Fatalf("NotRun + ordinary issue: want Invalid + NotRun + notApplicable, got %v/%v/%v", res.Status, res.StructuredCheck, res.Applicable)
	}

	// No active eligible target -> NotRequired, fully applicable.
	a = minValid("vless")
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	if res.Status != nodes.Valid || !res.Applicable || res.StructuredCheck != nodes.StructuredCheckNotRequired {
		t.Fatalf("no target: want Valid+applicable+NotRequired, got %v/%v/%v", res.Status, res.Applicable, res.StructuredCheck)
	}
}

// TestStructuredBadShapeAggregate: each actual-protocol-scoped eligible ACTIVE
// target whose OWN shape failed is StructuredCheckFailed (generic-first: only
// its one existing typeMismatch, no duplicate), Failed dominates NotRun in
// BOTH mix directions, both-bad yields exactly two existing typeMismatch
// findings, and a wireguard finalMask bad shape is Failed.
func TestStructuredBadShapeAggregate(t *testing.T) {
	p := loadProfile(t)
	pres := trustedPresenceFor("vless")

	// bad xhttpExtra (wrong type) + valid finalMask object -> Failed dominates.
	a := minValid("vless")
	a["xhttpExtra"] = "not-an-object"
	a["finalMask"] = map[string]any{}
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	if res.StructuredCheck != nodes.StructuredCheckFailed || res.Status != nodes.Invalid || res.Applicable {
		t.Fatalf("badExtra+validMask: want Failed+Invalid+notApplicable, got %v/%v/%v", res.StructuredCheck, res.Status, res.Applicable)
	}
	if len(res.Issues) != 1 || !hasIssue(res, nodes.IssueTypeMismatch, "xhttpExtra") {
		t.Fatalf("badExtra+validMask: want one typeMismatch@xhttpExtra only, got %+v", res.Issues)
	}

	// valid xhttpExtra object + bad finalMask (typed-nil) -> Failed dominates.
	var nilMap map[string]any
	a = minValid("vless")
	a["transport"] = "xhttp"
	a["xhttpExtra"] = map[string]any{"k": 1.0}
	a["finalMask"] = nilMap
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	if res.StructuredCheck != nodes.StructuredCheckFailed || res.Status != nodes.Invalid {
		t.Fatalf("validExtra+badMask: want Failed+Invalid, got %v/%v", res.StructuredCheck, res.Status)
	}
	if len(res.Issues) != 1 || !hasIssue(res, nodes.IssueTypeMismatch, "finalMask") {
		t.Fatalf("validExtra+badMask: want one typeMismatch@finalMask only, got %+v", res.Issues)
	}

	// BOTH bad targets -> Failed with EXACTLY two existing typeMismatch findings.
	a = minValid("vless")
	a["xhttpExtra"] = "bad"
	a["finalMask"] = 123.0
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	if res.StructuredCheck != nodes.StructuredCheckFailed {
		t.Fatalf("bothBad: want Failed, got %v", res.StructuredCheck)
	}
	if len(res.Issues) != 2 || !hasIssue(res, nodes.IssueTypeMismatch, "xhttpExtra") || !hasIssue(res, nodes.IssueTypeMismatch, "finalMask") {
		t.Fatalf("bothBad: want exactly two typeMismatch findings, got %+v", res.Issues)
	}

	// wireguard finalMask bad shape -> Failed (one typeMismatch@finalMask).
	wa := minValid("wireguard")
	wa["finalMask"] = "not-an-object"
	res = nodes.Validate(p, nodes.Input{Protocol: "wireguard", Active: wa, SecretPresence: trustedPresenceFor("wireguard")})
	if res.StructuredCheck != nodes.StructuredCheckFailed || len(res.Issues) != 1 || !hasIssue(res, nodes.IssueTypeMismatch, "finalMask") {
		t.Fatalf("wg badMask: want Failed + one typeMismatch@finalMask, got %v issues=%+v", res.StructuredCheck, res.Issues)
	}

	// Missing/inactive targets remain NotRequired (no promotion into Failed).
	a = minValid("vless")
	res = nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: pres})
	if res.StructuredCheck != nodes.StructuredCheckNotRequired {
		t.Fatalf("no targets: want NotRequired, got %v", res.StructuredCheck)
	}
}

// TestStructuredStatusConventions: stable value-free String labels, unknown
// fallback, default-zero NotRequired, Ready unreachable.
func TestStructuredStatusConventions(t *testing.T) {
	cases := map[nodes.StructuredCheckStatus]string{
		nodes.StructuredCheckNotRequired: "not_required",
		nodes.StructuredCheckReady:       "ready",
		nodes.StructuredCheckFailed:      "failed",
		nodes.StructuredCheckNotRun:      "not_run",
	}
	for st, want := range cases {
		if got := st.String(); got != want {
			t.Fatalf("StructuredCheckStatus(%d).String() = %q, want %q", int(st), got, want)
		}
	}
	if got := nodes.StructuredCheckStatus(99).String(); got != "unknown" {
		t.Fatalf("unknown fallback = %q, want unknown", got)
	}
	// default zero value is NotRequired (envelope-refusal / zero Result).
	var zero nodes.Result
	if zero.StructuredCheck != nodes.StructuredCheckNotRequired {
		t.Fatalf("zero Result.StructuredCheck = %v, want NotRequired", zero.StructuredCheck)
	}
	// Ready is unreachable in this increment (no shipped path produces it).
	p := loadProfile(t)
	a := minValid("vless")
	a["transport"] = "xhttp"
	a["xhttpExtra"] = map[string]any{"k": 1.0}
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: a, SecretPresence: trustedPresenceFor("vless")})
	if res.StructuredCheck == nodes.StructuredCheckReady {
		t.Fatalf("Ready must be unreachable in this increment")
	}
}

// TestStructuredEnvelopeIntegration: the real canonical adapter with all three
// buckets; nested/empty object correct shape loses the false typeMismatch and
// becomes NotRun/notApplicable; exact raw preserved; activeByDefault=false
// finalMask default-off is not a ban on explicit ACTIVE intent.
func TestStructuredEnvelopeIntegration(t *testing.T) {
	p := loadProfile(t)
	pres := trustedPresenceFor("vless")
	body := []byte(`{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"xhttp","security":"tls","xhttpExtra":{"h":{"Host":"x"}},"finalMask":{}},"inactive":{"flow":"xtls-rprx-vision"},"unknown":{}}}`)
	ar, err := nodes.ValidateDocument(p, body, pres)
	if err != nil {
		t.Fatalf("canonical envelope refused: %v", err)
	}
	if ar.Validation != domain.ValidationValid || ar.Result.Applicable {
		t.Fatalf("opaque active objects: want Valid + not applicable, got %v/%v", ar.Validation, ar.Result.Applicable)
	}
	if ar.Result.StructuredCheck != nodes.StructuredCheckNotRun {
		t.Fatalf("want NotRun, got %v issues=%+v", ar.Result.StructuredCheck, ar.Result.Issues)
	}
	if len(ar.Result.Issues) != 0 {
		t.Fatalf("want zero issues, got %+v", ar.Result.Issues)
	}
	if !bytes.Equal(ar.Document.Raw, body) {
		t.Fatalf("exact canonical nested raw must be preserved")
	}
}

// TestStructuredDeepCopiesAndNoEcho: genuine recursive deep copies of ALL
// buckets + presence stay unchanged (INVALID and shapeValid-NotRun); serialized
// result has no value echo / nested canary; projection omits opaque objects.
func TestStructuredDeepCopiesAndNoEcho(t *testing.T) {
	p := loadProfile(t)
	pres := trustedPresenceFor("vless")
	secretVal := "https://user:STRUCT-SEED@host.example"

	build := func() (map[string]any, map[string]any, map[string]any, map[string]bool) {
		active := minValid("vless")
		active["transport"] = "xhttp"
		active["xhttpExtra"] = map[string]any{"headers": map[string]any{"Host": "x.example", "seed": secretVal}}
		inactive := map[string]any{"flow": "xtls-rprx-vision", "finalMask": "raw-string"}
		unknown := map[string]any{}
		return active, inactive, unknown, pres
	}

	for _, tc := range []struct {
		name     string
		mutate   func(map[string]any)
		wantSC   nodes.StructuredCheckStatus
		wantStat nodes.Validity
	}{
		{"shapeValid-NotRun", func(a map[string]any) {}, nodes.StructuredCheckNotRun, nodes.Valid},
		{"invalid-conflict", func(a map[string]any) { a["transport"] = "ws" }, nodes.StructuredCheckFailed, nodes.Invalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			active, inactive, unknown, pr := build()
			tc.mutate(active)
			activeC := deepCopyJSON(active).(map[string]any)
			inactiveC := deepCopyJSON(inactive).(map[string]any)
			unknownC := deepCopyJSON(unknown).(map[string]any)
			prC := map[string]bool{}
			for k, v := range pr {
				prC[k] = v
			}

			res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: active, Inactive: inactive, Unknown: unknown, SecretPresence: pr})
			if res.Status != tc.wantStat || res.StructuredCheck != tc.wantSC {
				t.Fatalf("%s: want status=%v sc=%v, got %v/%v issues=%+v", tc.name, tc.wantStat, tc.wantSC, res.Status, res.StructuredCheck, res.Issues)
			}
			if !reflect.DeepEqual(active, activeC) {
				t.Fatalf("%s: active mutated\nbefore=%+v\nafter=%+v", tc.name, activeC, active)
			}
			if !reflect.DeepEqual(inactive, inactiveC) {
				t.Fatalf("%s: inactive mutated\nbefore=%+v\nafter=%+v", tc.name, inactiveC, inactive)
			}
			if !reflect.DeepEqual(unknown, unknownC) {
				t.Fatalf("%s: unknown mutated", tc.name)
			}
			if !reflect.DeepEqual(pr, prC) {
				t.Fatalf("%s: presence mutated", tc.name)
			}

			// Serialized public result: no value echo / nested canary.
			pub, mErr := json.Marshal(res)
			if mErr != nil {
				t.Fatalf("%s: result Marshal error: %v", tc.name, mErr)
			}
			if bytes.Contains(pub, []byte(secretVal)) {
				t.Fatalf("%s: result echoes submitted seed value: %s", tc.name, pub)
			}
			for _, is := range res.Issues {
				if bytes.Contains([]byte(is.Reason), []byte(secretVal)) {
					t.Fatalf("%s: issue reason echoes value: %+v", tc.name, is)
				}
			}

			// Projection omits opaque objects (name-only unsupported), never copies
			// them to a safe bucket.
			proj, err := p.ProjectNodeFields("vless", active, pr, nil)
			if err != nil {
				t.Fatalf("%s: project: %v", tc.name, err)
			}
			if proj.Active["xhttpExtra"] != nil {
				t.Fatalf("%s: opaque object must not be copied into projection.Active", tc.name)
			}
			foundUnsupported := false
			for _, u := range proj.Unsupported {
				if u == "xhttpExtra" {
					foundUnsupported = true
				}
				if bytes.Contains([]byte(u), []byte(secretVal)) {
					t.Fatalf("%s: unsupported name echoes value", tc.name)
				}
			}
			if !foundUnsupported {
				t.Fatalf("%s: xhttpExtra should be listed name-only unsupported", tc.name)
			}
		})
	}
}
