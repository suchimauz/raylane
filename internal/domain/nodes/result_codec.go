package nodes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/jsonscan"
)

// nextTokenType returns the JSON token type of one complete raw JSON value
// (null, bool, number, string, array, object) using the stdlib streaming
// decoder. It refuses anything that is not exactly one well-formed value.
func nextTokenType(raw json.RawMessage) (json.Token, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, errResultFormat()
	}
	if dec.More() {
		return nil, errResultFormat()
	}
	return tok, nil
}

// tokenIsNumber reports whether tok is a bare JSON number (never a quoted
// string, null, bool, array or object). json.Decoder yields float64 for a
// bare number token.
func tokenIsNumber(tok json.Token) bool {
	_, ok := tok.(float64)
	return ok
}

func tokenIsBool(tok json.Token) bool {
	_, ok := tok.(bool)
	return ok
}

func tokenIsString(tok json.Token) bool {
	_, ok := tok.(string)
	return ok
}

func tokenIsArrayStart(tok json.Token) (bool, bool) {
	d, ok := tok.(json.Delim)
	if !ok {
		return false, false
	}
	return d == '[', true
}

// DecodeResultStrict decodes a persisted, previously encoded nodes.Result from
// JSON with a CLOSED, fail-closed contract. It is the nodes-owned counterpart
// of MarshalResultJSON: it reuses the exact issueReason vocabulary and the
// closed IssueCode/field-path rules, so a stored historical verdict is
// validated against the SAME authority that produced it — no second reason
// registry, no custom analyzer, and no promotion or recomputation of the
// verdict from safe metadata.
//
// Guarantees:
//   - strict full-consumption: any trailing bytes or a non-object top level
//     refuse;
//   - duplicate keys at ANY level refuse (enforced by the shared scanner);
//   - every object carries EXACTLY the closed key set expected at that level —
//     unknown or missing members refuse;
//   - Status/Applicable are the exact closed values; ChainCheck/StructuredCheck
//     are the exact closed enumerations (StructuredCheckReady is reserved and
//     must never appear in a persisted verdict);
//   - every Issue.Code is a closed IssueCode, every Issue.Field is structural
//     vocabulary or a profile-authorized declared-field path, and every
//     Issue.Reason equals the canonical issueReason[code] text;
//   - every name in Secrets/Unknown/Unsupported is a nonempty string; no value
//     from the original submission is ever decoded here (Results are value-free).
//
// The returned Result owns its copies. Any structural violation yields a
// plain, value-free error (never echoing persisted bytes).
func DecodeResultStrict(raw []byte, profile *capability.Profile) (Result, error) {
	if err := jsonscan.FullValue(raw); err != nil {
		return Result{}, errResultFormat()
	}
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return Result{}, errResultFormat()
	}
	if dec.More() {
		return Result{}, errResultFormat()
	}
	wantKeys := []string{"status", "applicable", "issues", "secrets", "unknown", "chainCheck", "structuredCheck"}
	if err := requireExactKeys(top, wantKeys); err != nil {
		return Result{}, err
	}

	var res Result
	st, err := decodeIntStrict(top["status"])
	if err != nil {
		return Result{}, err
	}
	switch Validity(st) {
	case Valid, Invalid:
		res.Status = Validity(st)
	default:
		return Result{}, errResultFormat()
	}
	if res.Applicable, err = decodeBoolStrict(top["applicable"]); err != nil {
		return Result{}, err
	}
	if res.Issues, err = decodeIssueArray(top["issues"], profile); err != nil {
		return Result{}, err
	}
	if res.Secrets, err = decodeStringArrayStrict(top["secrets"]); err != nil {
		return Result{}, err
	}
	if res.Unknown, err = decodeStringArrayStrict(top["unknown"]); err != nil {
		return Result{}, err
	}
	cc, err := decodeIntStrict(top["chainCheck"])
	if err != nil {
		return Result{}, err
	}
	switch ChainCheckStatus(cc) {
	case ChainCheckNotRequired, ChainCheckNotRun, ChainCheckFailed:
		res.ChainCheck = ChainCheckStatus(cc)
	default:
		return Result{}, errResultFormat()
	}
	sc, err := decodeIntStrict(top["structuredCheck"])
	if err != nil {
		return Result{}, err
	}
	switch StructuredCheckStatus(sc) {
	case StructuredCheckNotRequired, StructuredCheckFailed, StructuredCheckNotRun:
		res.StructuredCheck = StructuredCheckStatus(sc)
	default:
		return Result{}, errResultFormat()
	}
	// Semantic name vocabulary (no echo): persisted names must be genuine
	// authority facts, never arbitrary caller strings. Unknown entries are ONLY
	// the validator's generic "unknown" bucket marker (repeated markers are
	// legitimate and kept); Secrets entries must be declared fields classified
	// secret (no nonsecret/undeclared/wrong-protocol claims). No value is ever
	// decoded here.
	if err := validateUnknownNames(res.Unknown); err != nil {
		return Result{}, err
	}
	if err := validateSecretNames(profile, "", res.Secrets, false); err != nil {
		return Result{}, err
	}
	return res, nil
}

// errResultFormat is the single static, value-free refusal for any structural
// violation of a persisted result.
func errResultFormat() error { return errors.New("nodes: malformed persisted validation result") }

// validateUnknownNames enforces that every persisted Unknown entry is exactly
// the validator's generic "unknown" bucket marker — never a raw submitted
// name or value. Repeated generic markers are legitimate historical facts and
// are kept (NOT deduplicated); only a non-"unknown" entry refuses.
func validateUnknownNames(names []string) error {
	for _, n := range names {
		if n != "unknown" {
			return errResultFormat()
		}
	}
	return nil
}

// validateSecretNames enforces that every persisted Secrets entry names a
// declared authority field classified secret — never a nonsecret/undeclared
// name, and never a field that does not belong to the given protocol when a
// protocol context is supplied. Names are the closed authority vocabulary,
// not arbitrary caller strings; no secret value is involved. A field whose
// sealed row was later deleted still keeps its historical declared-secret
// name (absence is a presence fact, not a name fact), so this does not reject
// valid historical secret names on current-row absence.
func validateSecretNames(profile *capability.Profile, protocol string, names []string, requireProtocol bool) error {
	if profile == nil {
		// No authority available to settle names: fail closed rather than
		// accept arbitrary caller strings.
		if len(names) == 0 {
			return nil
		}
		return errResultFormat()
	}
	for _, n := range names {
		if !isDeclaredSecretName(profile, protocol, n, requireProtocol) {
			return errResultFormat() // undeclared / nonsecret / wrong-protocol name
		}
	}
	return nil
}

// isDeclaredSecretName reports whether n names a declared authority field
// classified secret, optionally pinned to the given protocol.
func isDeclaredSecretName(profile *capability.Profile, protocol, n string, requireProtocol bool) bool {
	for _, proto := range profile.Protocols() {
		f, ok := profile.Field(proto, n)
		if !ok || f.Classification != "secret" {
			continue
		}
		if requireProtocol && proto != protocol {
			return false // wrong-protocol secret claim
		}
		return true
	}
	return false
}

// EnforceSecretProtocol re-validates a persisted Secrets name list against the
// node's protocol context. DecodeResultStrict already guarantees each name is
// a declared secret field of SOME protocol; the reader (which holds the node
// protocol) uses this to refuse a wrong-protocol secret claim. It never reads
// or echoes a value.
func EnforceSecretProtocol(profile *capability.Profile, protocol string, names []string) error {
	return validateSecretNames(profile, protocol, names, true)
}

// requireExactKeys enforces that m has EXACTLY the given keys (none missing,
// none extra). Duplicate keys are rejected earlier by the strict scanner.
func requireExactKeys(m map[string]json.RawMessage, want []string) error {
	if len(m) != len(want) {
		return errResultFormat()
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return errResultFormat()
		}
	}
	return nil
}

// decodeIntStrict decodes a persisted enum token that MUST be a bare JSON
// integer in int64 range. A quoted/non-integer number ("1"), a fractional
// value, an out-of-range integer, or null/wrong container are ALL refused — no
// JSON type coercion. Valid whole-integer spellings (0, 1, 2, …) are accepted.
func decodeIntStrict(raw json.RawMessage) (int64, error) {
	tok, err := nextTokenType(raw)
	if err != nil || !tokenIsNumber(tok) {
		return 0, errResultFormat()
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var n json.Number
	if err := dec.Decode(&n); err != nil {
		return 0, errResultFormat()
	}
	// Whole-integer, in-int64-range only: reject fractional lexemes (1.5),
	// exponent forms that are not whole (1e-1), and out-of-range (1e400).
	f, ok := new(big.Float).SetString(n.String())
	if !ok || !f.IsInt() {
		return 0, errResultFormat()
	}
	i, err := n.Int64()
	if err != nil {
		return 0, errResultFormat()
	}
	return i, nil
}

// decodeBoolStrict decodes a persisted boolean token that MUST be a bare JSON
// true/false; null and any quoted/wrong type refuse.
func decodeBoolStrict(raw json.RawMessage) (bool, error) {
	tok, err := nextTokenType(raw)
	if err != nil || !tokenIsBool(tok) {
		return false, errResultFormat()
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false, errResultFormat()
	}
	return b, nil
}

// decodeStringArrayStrict decodes a persisted name array that MUST be a JSON
// array (never null) whose every item is a string. A null array, a non-array
// container, or a non-string item refuses. Items are returned verbatim; the
// caller applies the semantic name-vocabulary check. Uses a single streaming
// decoder (not Unmarshal) so quoted strings, nested arrays/objects and wrong
// item types are all refused without ever materializing an attacker-supplied
// value into a Go string that could be echoed.
func decodeStringArrayStrict(raw json.RawMessage) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, errResultFormat()
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '[' {
		return nil, errResultFormat() // null / scalar / object: not an array
	}
	out := []string{}
	for dec.More() {
		it, err := dec.Token()
		if err != nil {
			return nil, errResultFormat()
		}
		s, ok := it.(string)
		if !ok || s == "" {
			return nil, errResultFormat() // non-string or empty item
		}
		out = append(out, s)
	}
	// Consume the closing ']' and confirm nothing trails the array.
	if _, err := dec.Token(); err != nil {
		return nil, errResultFormat()
	}
	if dec.More() {
		return nil, errResultFormat()
	}
	return out, nil
}

// decodeIssueArray decodes the closed issue list. Each entry has exactly
// {code,field,reason}; the code is a closed IssueCode, the field is structural
// vocabulary or a profile-authorized declared-field path, and the reason is the
// canonical issueReason[code] text.
func decodeIssueArray(raw json.RawMessage, profile *capability.Profile) ([]Issue, error) {
	// The issues array MUST be a JSON array (never null). A streaming decoder
	// (not Unmarshal) is used so null / wrong containers and non-object items
	// are refused without materializing attacker bytes.
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, errResultFormat()
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '[' {
		return nil, errResultFormat() // null / scalar / object: not an array
	}
	out := []Issue{}
	for dec.More() {
		it, err := dec.Token()
		if err != nil {
			return nil, errResultFormat()
		}
		di, ok := it.(json.Delim)
		if !ok || di != '{' {
			return nil, errResultFormat() // non-object item
		}
		m := map[string]json.RawMessage{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, errResultFormat()
			}
			ks, ok := kt.(string)
			if !ok {
				return nil, errResultFormat()
			}
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return nil, errResultFormat()
			}
			m[ks] = v
		}
		if _, err := dec.Token(); err != nil { // consume '}'
			return nil, errResultFormat()
		}
		if err := requireExactKeys(m, []string{"code", "field", "reason"}); err != nil {
			return nil, err
		}
		var code, field, reason string
		for k, v := range m {
			tk, terr := nextTokenType(v)
			if terr != nil || !tokenIsString(tk) {
				return nil, errResultFormat() // non-string member
			}
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return nil, errResultFormat()
			}
			switch k {
			case "code":
				code = s
			case "field":
				field = s
			case "reason":
				reason = s
			}
		}
		ic := IssueCode(code)
		if !ic.valid() {
			return nil, errResultFormat()
		}
		if !issueFieldAuthorized(ic, field, profile) {
			return nil, errResultFormat()
		}
		if reason != issueReason[ic] {
			return nil, errResultFormat()
		}
		out = append(out, Issue{Code: ic, Field: field, Reason: reason})
	}
	if _, err := dec.Token(); err != nil { // consume ']'
		return nil, errResultFormat()
	}
	if dec.More() {
		return nil, errResultFormat() // trailing content
	}
	return out, nil
}

// issueFieldAuthorized reports whether a persisted issue path is valid for its
// code: closed structural vocabulary, or a path the code scopes to a declared
// profile field (mirrors bucketIssueField's production invariant without
// echoing attacker names).
func issueFieldAuthorized(code IssueCode, field string, profile *capability.Profile) bool {
	if fixedIssuePath(code) {
		return isStructuralPath(field)
	}
	if profile == nil {
		return false
	}
	for _, proto := range []string{"vless", "socks5", "http", "wireguard"} {
		if !profile.HasProtocol(proto) {
			continue
		}
		if _, ok := profile.Field(proto, field); ok {
			return true
		}
	}
	return false
}

// MarshalResultJSON encodes a Result with the closed, versioned schema the
// strict decoder round-trips. Only value-free, authority-derived content is
// emitted: statuses, booleans, closed issue {code,field,reason}, and string
// NAME lists (secrets/unknown/unsupported) — never a submitted value.
func MarshalResultJSON(res Result) ([]byte, error) {
	issues := make([]Issue, 0, len(res.Issues))
	for _, is := range res.Issues {
		issues = append(issues, is)
	}
	if issues == nil {
		issues = []Issue{}
	}
	secrets := res.Secrets
	if secrets == nil {
		secrets = []string{}
	}
	unknown := res.Unknown
	if unknown == nil {
		unknown = []string{}
	}
	doc := struct {
		Status          int      `json:"status"`
		Applicable      bool     `json:"applicable"`
		Issues          []Issue  `json:"issues"`
		Secrets         []string `json:"secrets"`
		Unknown         []string `json:"unknown"`
		ChainCheck      int      `json:"chainCheck"`
		StructuredCheck int      `json:"structuredCheck"`
	}{
		Status:          int(res.Status),
		Applicable:      res.Applicable,
		Issues:          issues,
		Secrets:         secrets,
		Unknown:         unknown,
		ChainCheck:      int(res.ChainCheck),
		StructuredCheck: int(res.StructuredCheck),
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("nodes: encode result: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
