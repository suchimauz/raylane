package nodes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/jsonscan"
)

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
	st, err := decodeInt(top["status"])
	if err != nil {
		return Result{}, err
	}
	switch Validity(st) {
	case Valid, Invalid:
		res.Status = Validity(st)
	default:
		return Result{}, errResultFormat()
	}
	if res.Applicable, err = decodeBool(top["applicable"]); err != nil {
		return Result{}, err
	}
	if res.Issues, err = decodeIssueArray(top["issues"], profile); err != nil {
		return Result{}, err
	}
	if res.Secrets, err = decodeStringArray(top["secrets"]); err != nil {
		return Result{}, err
	}
	if res.Unknown, err = decodeStringArray(top["unknown"]); err != nil {
		return Result{}, err
	}
	cc, err := decodeInt(top["chainCheck"])
	if err != nil {
		return Result{}, err
	}
	switch ChainCheckStatus(cc) {
	case ChainCheckNotRequired, ChainCheckNotRun, ChainCheckFailed:
		res.ChainCheck = ChainCheckStatus(cc)
	default:
		return Result{}, errResultFormat()
	}
	sc, err := decodeInt(top["structuredCheck"])
	if err != nil {
		return Result{}, err
	}
	switch StructuredCheckStatus(sc) {
	case StructuredCheckNotRequired, StructuredCheckFailed, StructuredCheckNotRun:
		res.StructuredCheck = StructuredCheckStatus(sc)
	default:
		return Result{}, errResultFormat()
	}
	return res, nil
}

// errResultFormat is the single static, value-free refusal for any structural
// violation of a persisted result.
func errResultFormat() error { return errors.New("nodes: malformed persisted validation result") }

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

func decodeInt(raw json.RawMessage) (int64, error) {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, errResultFormat()
	}
	i, err := n.Int64()
	if err != nil {
		return 0, errResultFormat()
	}
	return i, nil
}

func decodeBool(raw json.RawMessage) (bool, error) {
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false, errResultFormat()
	}
	return b, nil
}

func decodeStringArray(raw json.RawMessage) ([]string, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, errResultFormat()
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		var s string
		if err := json.Unmarshal(e, &s); err != nil || s == "" {
			return nil, errResultFormat()
		}
		out = append(out, s)
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// decodeIssueArray decodes the closed issue list. Each entry has exactly
// {code,field,reason}; the code is a closed IssueCode, the field is structural
// vocabulary or a profile-authorized declared-field path, and the reason is the
// canonical issueReason[code] text.
func decodeIssueArray(raw json.RawMessage, profile *capability.Profile) ([]Issue, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, errResultFormat()
	}
	out := make([]Issue, 0, len(arr))
	for _, e := range arr {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(e, &m); err != nil {
			return nil, errResultFormat()
		}
		if err := requireExactKeys(m, []string{"code", "field", "reason"}); err != nil {
			return nil, err
		}
		var code, field, reason string
		for k, v := range m {
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
	if out == nil {
		out = []Issue{}
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
