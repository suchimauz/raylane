package contract_test

// Boundary-closure contract (correction 19b833c review round): the three
// consolidated blocking findings — V4-T011A-PLAINTEXT-SECRET-WITH-PRESENCE,
// V4-T011A-NODE-ENVELOPE-NOT-CLOSED and
// V4-T011A-UNKNOWN-BUCKET-PROMOTED-TO-ACTIVE — are closed by BEHAVIOR here:
// every case executes the real capability authority and the real
// nodes.Validate/ValidateDocument against the authored profile. Controls prove
// the sealed-only and canonical paths stay valid, so a failure names a real
// boundary break, not a fixture artifact.

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// TestSecretKeyRejectedRegardlessOfPresence closes
// V4-T011A-PLAINTEXT-SECRET-WITH-PRESENCE: a declared secret key in active OR
// inactive is invalid regardless of trusted sealed presence, required/optional
// status, and value kind (string/null/number/bool/array/object). Sealed-only
// presence keeps satisfying required/dependency presence (control).
func TestSecretKeyRejectedRegardlessOfPresence(t *testing.T) {
	p := loadProfile(t)
	clean := minValid("vless")
	kinds := []struct {
		name string
		val  any
	}{
		{"string", secretCanary},
		{"null", nil},
		{"number", float64(7)},
		{"bool", true},
		{"array", []any{secretCanary}},
		{"object", map[string]any{"k": secretCanary}},
	}
	presences := []map[string]bool{{"uuid": true}, {"uuid": false}, {}}
	for _, pres := range presences {
		for _, k := range kinds {
			active := copyMap(clean)
			active["uuid"] = k.val // required secret as plaintext key
			res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: active, SecretPresence: pres})
			if res.Status == nodes.Valid || res.Applicable {
				t.Errorf("active plaintext secret (value=%s, presence=%v) must be invalid/not applicable, got %v applicable=%v", k.name, pres, res.Status, res.Applicable)
			}
			if !hasIssue(res, nodes.IssueSecretPlaintextSubmitted, "uuid") {
				t.Errorf("active plaintext secret (value=%s) must carry secretPlaintextSubmitted on the declared name, got %+v", k.name, res.Issues)
			}
			assertNoCanary(t, "secret-key-active", res)

			inactive := map[string]any{"uuid": k.val} // inactive bucket
			res2 := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: clean, Inactive: inactive, SecretPresence: pres})
			if res2.Status == nodes.Valid || res2.Applicable {
				t.Errorf("inactive plaintext secret (value=%s, presence=%v) must be invalid/not applicable", k.name, pres)
			}
			if !hasIssue(res2, nodes.IssueSecretPlaintextSubmitted, "uuid") {
				t.Errorf("inactive plaintext secret (value=%s) must carry secretPlaintextSubmitted, got %+v", k.name, res2.Issues)
			}
			assertNoCanary(t, "secret-key-inactive", res2)
		}
	}
	// Optional (non-required) declared secret key must also be refused.
	optActive := copyMap(clean)
	optActive["mldsa65Seed"] = secretCanary
	res := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: optActive, SecretPresence: map[string]bool{"uuid": true, "security_dep": true}})
	if res.Status == nodes.Valid || !hasIssue(res, nodes.IssueSecretPlaintextSubmitted, "mldsa65Seed") {
		t.Errorf("optional plaintext secret key must be refused: %+v", res.Issues)
	}
	// CONTROL: sealed-only minimal node stays Valid+Applicable (presence
	// semantics unchanged; the fix must not break correct submissions).
	rc := nodes.Validate(p, nodes.Input{Protocol: "vless", Active: clean, SecretPresence: trustedPresenceFor("vless")})
	if rc.Status != nodes.Valid || !rc.Applicable {
		t.Fatalf("control broken: sealed-only vless must stay valid: %+v", rc.Issues)
	}
}

// TestEnvelopeIsClosedAndExact closes V4-T011A-NODE-ENVELOPE-NOT-CLOSED:
// every non-canonical envelope maps to errors.Is(err, ErrNotANodeEnvelope)
// with ValidationInvalid, EXACT raw preserved, and a fixed value-free issue;
// malformed/trailing JSON stays domain.ErrMalformedJSON with no Document.
func TestEnvelopeIsClosedAndExact(t *testing.T) {
	p := loadProfile(t)
	cases := map[string]string{
		"missing-inactive-unknown": `{"protocol":"socks5","fields":{"active":{"server":"s.example","serverPort":1080}}}`,
		"missing-unknown":          `{"protocol":"socks5","fields":{"active":{},"inactive":{}}}`,
		"null-fields":              `{"protocol":"socks5","fields":null}`,
		"null-active":              `{"protocol":"socks5","fields":{"active":null,"inactive":{},"unknown":{}}}`,
		"active-string":            `{"protocol":"socks5","fields":{"active":"s","inactive":{},"unknown":{}}}`,
		"fields-array":             `{"protocol":"socks5","fields":[]}`,
		"protocol-number":          `{"protocol":5,"fields":{"active":{},"inactive":{},"unknown":{}}}`,
		"protocol-empty":           `{"protocol":"","fields":{"active":{},"inactive":{},"unknown":{}}}`,
		"protocol-null":            `{"protocol":null,"fields":{"active":{},"inactive":{},"unknown":{}}}`,
		"fields-null-bucket":       `{"protocol":"socks5","fields":{"active":{},"inactive":null,"unknown":{}}}`,
		"root-unknown-member":      `{"protocol":"socks5","clientSecretPresence":{"uuid":true},"fields":{"active":{},"inactive":{},"unknown":{}}}`,
		"fields-unknown-member":    `{"protocol":"socks5","fields":{"active":{"server":"s.example","serverPort":1080},"inactive":{},"unknown":{},"extra":{"sneaky":"` + secretCanary + `"}}}`,
		"profile-smuggle":          `{"protocol":"socks5","profile":{"protocols":{"evil":{}}},"fields":{"active":{"server":"s.example","serverPort":1080},"inactive":{},"unknown":{}}}`,
		"dup-root-protocol":        `{"protocol":"vless","protocol":"socks5","fields":{"active":{"server":"s.example","serverPort":1080},"inactive":{},"unknown":{}}}`,
		"dup-fields-member":        `{"protocol":"socks5","fields":{"active":{"server":"s.example","serverPort":1080},"active":{},"inactive":{},"unknown":{}}}`,
		"dup-bucket-key":           `{"protocol":"vless","fields":{"active":{"server":"safe.example","serverPort":443,"transport":"ws","security":"tls","server":"evil.example"},"inactive":{},"unknown":{}}}`,
		"dup-order-flip-valid":     `{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":"NOT-A-PORT","transport":"ws","security":"tls","serverPort":443},"inactive":{},"unknown":{}}}`,
		"dup-order-flip-invalid":   `{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"ws","security":"tls","serverPort":"NOT-A-PORT"},"inactive":{},"unknown":{}}}`,
		"dup-nested-array-obj":     `{"protocol":"wireguard","fields":{"active":{"endpoint":"w.example","endpointPort":51820,"publicKey":"p","localAddresses":[{"a":1,"a":2}]},"inactive":{},"unknown":{}}}`,
		"dup-escaped-equivalence":  `{"protocol":"socks5","fields":{"active":{"server":"s.example","\u0073erverPort":1081,"serverPort":1080},"inactive":{},"unknown":{}}}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := nodes.ValidateDocument(p, []byte(doc), map[string]bool{"uuid": true})
			if !errors.Is(err, nodes.ErrNotANodeEnvelope) {
				t.Fatalf("non-canonical envelope %q must map to ErrNotANodeEnvelope, got err=%v status=%v applicable=%v", name, err, res.Result.Status, res.Result.Applicable)
			}
			if res.Validation != domain.ValidationInvalid {
				t.Fatalf("envelope failure must be ValidationInvalid, got %v", res.Validation)
			}
			if !bytes.Equal(res.Document.Raw, []byte(doc)) {
				t.Fatalf("exact original raw must be preserved for honest draft storage")
			}
			if !hasIssue(res.Result, nodes.IssueMalformedEnvelope, "envelope") {
				t.Fatalf("fixed value-free envelope issue required, got %+v", res.Result.Issues)
			}
			assertNoCanary(t, "envelope-"+name, res.Result)
			// The ISSUES view is value-free: a smuggled member name/value can
			// only ever appear in the caller's own preserved raw bytes, never
			// in the verdict itself.
			out, _ := json.Marshal(res.Result)
			for _, smug := range []string{"sneaky", "evil.example", "clientSecretPresence"} {
				if bytes.Contains(out, []byte(smug)) {
					t.Fatalf("envelope member name/value echoed into issues (%s): %s", smug, out)
				}
			}
		})
	}
	// Malformed / trailing JSON stays a parse failure with NO Document.
	for _, bad := range []string{`{not json`, `{"protocol":"socks5"} trailing`, `{"protocol":"socks5","fields":{"active":{},"inactive":{},"unknown":{}}} {}`} {
		res, err := nodes.ValidateDocument(p, []byte(bad), nil)
		if !errors.Is(err, domain.ErrMalformedJSON) {
			t.Fatalf("malformed/trailing must stay ErrMalformedJSON, got %v", err)
		}
		if len(res.Document.Raw) != 0 {
			t.Fatalf("malformed payload must produce no Document bytes")
		}
	}
	// CONTROL: the canonical envelope with explicit EMPTY buckets validates.
	good := `{"protocol":"socks5","fields":{"active":{"server":"s.example","serverPort":1080},"inactive":{},"unknown":{}}}`
	res, err := nodes.ValidateDocument(p, []byte(good), nil)
	if err != nil || res.Result.Status != nodes.Valid || !res.Result.Applicable {
		t.Fatalf("control broken: canonical minimal envelope must validate (err=%v issues=%+v)", err, res.Result.Issues)
	}
	// CONTROL: whitespace-formatted canonical envelope keeps exact raw and
	// validates (whitespace-only formatting is not a canonicality break).
	ws := `{ "protocol" : "socks5", "fields" : { "active" : { "server":"s.example", "serverPort":1080 } , "inactive" : { }, "unknown" : { } } }`
	res2, err := nodes.ValidateDocument(p, []byte(ws), nil)
	if err != nil || res2.Result.Status != nodes.Valid {
		t.Fatalf("control broken: whitespace canonical envelope must validate (err=%v)", err)
	}
	if !bytes.Equal(res2.Document.Raw, []byte(ws)) {
		t.Fatalf("control broken: exact bytes of a valid envelope must be preserved")
	}
}

// TestQuarantineBucketNeverPromoted closes
// V4-T011A-UNKNOWN-BUCKET-PROMOTED-TO-ACTIVE: the explicit unknown bucket is
// quarantine. Its entries never satisfy required/dependency/secret presence
// and ANY nonempty bucket — unknown name, declared name, secret name, or a
// name colliding with active — makes the node Invalid and not applicable with
// a generic value-free issue, while the exact raw is retained. An empty {}
// bucket keeps an otherwise valid node valid (control pair).
func TestQuarantineBucketNeverPromoted(t *testing.T) {
	p := loadProfile(t)
	pres := map[string]bool{"uuid": true}
	base := `{"protocol":"vless","fields":{"active":{"serverPort":443,"transport":"ws","security":"tls"},"inactive":{},"unknown":%s}}`

	// Control pair (isolates the bucket as the cause): missing server is
	// Invalid; moving it into the bucket must NOT rescue the node.
	resA, err := nodes.ValidateDocument(p, []byte(bucketDoc(base, `{}`)), pres)
	if err != nil {
		t.Fatalf("control envelope must decode: %v", err)
	}
	if resA.Result.Status != nodes.Invalid {
		t.Fatalf("control broken: missing required server must be Invalid")
	}
	resB, err := nodes.ValidateDocument(p, []byte(bucketDoc(base, `{"server":"promoted.example"}`)), pres)
	if err != nil {
		t.Fatalf("probe envelope must decode: %v", err)
	}
	if resB.Result.Status == nodes.Valid || resB.Result.Applicable {
		t.Errorf("required field satisfied purely via the quarantine bucket")
	}
	if !hasIssue(resB.Result, nodes.IssueQuarantineBucketNotEmpty, "unknown") {
		t.Errorf("quarantine entry must produce the generic bucket issue, got %+v", resB.Result.Issues)
	}

	// An otherwise VALID node with one quarantine entry becomes Invalid/not
	// applicable (also covers declared-name and secret-name placements).
	valid := `{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"ws","security":"tls"},"inactive":{},"unknown":%s}}`
	for _, bucket := range []string{
		`{"` + unknownCanary + `":1}`,
		`{"cookieSeconds":60}`,
		`{"uuid":"` + secretCanary + `"}`,
		`{"server":"v.example"}`,
		`{"a":1,"b":2}`,
	} {
		res, err := nodes.ValidateDocument(p, []byte(bucketDoc(valid, bucket)), pres)
		if err != nil {
			t.Fatalf("canonical envelope must decode (bucket=%s): %v", bucket, err)
		}
		if res.Result.Status == nodes.Valid || res.Result.Applicable {
			t.Errorf("nonempty quarantine bucket (%s) must invalidate the node", bucket)
		}
		if !hasIssue(res.Result, nodes.IssueQuarantineBucketNotEmpty, "unknown") {
			t.Errorf("bucket %s must produce the generic quarantine issue, got %+v", bucket, res.Result.Issues)
		}
		assertNoCanary(t, "quarantine", res.Result)
		if !bytes.Equal(res.Document.Raw, []byte(bucketDoc(valid, bucket))) {
			t.Errorf("quarantine verdict must still preserve exact raw for honest draft storage")
		}
	}
	// CONTROL: the same valid node with an explicit EMPTY bucket stays Valid.
	resC, err := nodes.ValidateDocument(p, []byte(bucketDoc(valid, `{}`)), pres)
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	if resC.Result.Status != nodes.Valid || !resC.Result.Applicable {
		t.Fatalf("control broken: empty quarantine bucket must not invalidate a valid node: %+v", resC.Result.Issues)
	}

	// Buckets must be DISJOINT: a name submitted in active AND in the
	// quarantine at once is ambiguous and is refused under a fixed generic
	// path — the colliding name never echoes.
	clash := `{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"ws","security":"tls"},"inactive":{},"unknown":{"server":"v.example"}}}`
	resD, err := nodes.ValidateDocument(p, []byte(clash), pres)
	if err != nil {
		t.Fatalf("canonical collision envelope must decode: %v", err)
	}
	if resD.Result.Status == nodes.Valid || !hasIssue(resD.Result, nodes.IssueEnvelopeMemberConflict, "fields") {
		t.Errorf("bucket collision must produce the generic member-conflict issue, got %+v", resD.Result.Issues)
	}
	out, _ := json.Marshal(resD.Result)
	if bytes.Contains(out, []byte("v.example\"}]")) && !bytes.Contains(out, []byte("server")) {
		t.Errorf("collision path must be generic: %s", out)
	}
	// Active-vs-inactive duplication is the same ambiguity.
	resE := nodes.Validate(p, nodes.Input{Protocol: "vless",
		Active:         copyMapWith(minValid("vless"), "cookieSeconds", float64(60)),
		Inactive:       map[string]any{"cookieSeconds": float64(60)},
		SecretPresence: trustedPresenceFor("vless")})
	if !hasIssue(resE, nodes.IssueEnvelopeMemberConflict, "fields") {
		t.Errorf("active/inactive duplication must be refused as ambiguous, got %+v", resE.Issues)
	}
}

// bucketDoc fills the "unknown":%s slot of a canonical envelope template.
func bucketDoc(tmpl, bucket string) string {
	return strings.Replace(tmpl, "%s", bucket, 1)
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyMapWith(m map[string]any, k string, v any) map[string]any {
	out := copyMap(m)
	out[k] = v
	return out
}
