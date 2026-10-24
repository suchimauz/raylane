// Package api hosts the API-side boundaries that are testable without a
// server: the allowlisted read/diagnostic projection described by D1. It is
// deliberately NOT HTTP wiring — no handlers, routes or sockets live here in
// T007. Unit-level projection safety is not an end-to-end API leak test until
// real handlers are later wired and tested.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Errors of this package are generic and secret-free: they never echo field
// values, configuration bytes or key material.
var (
	// ErrProfileRejected reports malformed, missing or unsupported profile
	// metadata. Initialization fails closed; there is no default profile and
	// no fallback classification.
	ErrProfileRejected = errors.New("api: capability profile rejected")
	// ErrProtocolUnknown reports a projection request for a protocol the
	// authored profile does not declare. Unknown means "project nothing",
	// never "pass everything".
	ErrProtocolUnknown = errors.New("api: protocol not declared by profile")
)

// SecretUnchangedSentinel is the exact reserved string refused on a
// SecretUpdate replace operation (contracts/openapi.yaml SecretUpdate). Only
// an exact match is refused; mask-lookalikes are legitimate secret values.
// This package preserves that semantic for consumers; it does not implement
// node CRUD or reinterpret mask-looking values as unchanged.
const SecretUnchangedSentinel = "__RAYLANE_SECRET_UNCHANGED_V1__"

// SecretRefIdentifies whether a candidate SecretUpdate replace value is the
// reserved sentinel. Exact match only, per the contract: strings that merely
// look like masks (••••, ****, «hidden») are legitimate values.
func SecretUpdateIsReservedSentinel(candidate string) bool {
	return candidate == SecretUnchangedSentinel
}

type fieldSpec struct {
	Type            string   `json:"type"`
	Classification  string   `json:"classification"`
	Secret          *bool    `json:"secret"`
	AllowedValues   []string `json:"allowedValues"`
	ItemType        string   `json:"itemType"`
	MaxItems        *int     `json:"maxItems"`
	MinItems        *int     `json:"minItems"`
	MinLength       *int     `json:"minLength"`
	MaxLength       *int     `json:"maxLength"`
	Minimum         *int64   `json:"minimum"`
	Maximum         *int64   `json:"maximum"`
	Pattern         string   `json:"pattern"`
	Supported       *bool    `json:"supported"`
	ActiveByDefault *bool    `json:"activeByDefault"`

	patternRe *regexp.Regexp // compiled at parse time when Pattern is set
}

type protocolProfile struct {
	Fields map[string]fieldSpec `json:"fields"`
}

type profileDoc struct {
	ProfileVersion int                        `json:"profileVersion"`
	Protocols      map[string]protocolProfile `json:"protocols"`
}

// Profile is the validated classification authority. Obtain it only through
// ParseCapabilityProfile from bytes the trusted service initialization
// supplied explicitly — never client-supplied classification, never a file
// found via the process cwd.
type Profile struct {
	version   int
	protocols map[string]map[string]fieldSpec
}

var (
	fieldNameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.]{0,63}$`)
	protoNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	fieldTypes  = map[string]bool{"string": true, "integer": true, "boolean": true, "enum": true, "array": true, "object": true}
)

// ParseCapabilityProfile validates the authored capability-profile bytes and
// indexes them for projection. It verifies exactly the metadata this boundary
// consumes — version, protocol/field key shapes, type and classification
// enums, secret-flag consistency, enum value sets, array item types, integer
// and length bound sanity, and regex compiles — and fails closed on anything
// else. It is not a JSON-schema engine or compiler; full T011 validation
// stays out of scope.
func ParseCapabilityProfile(raw []byte) (*Profile, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty profile", ErrProfileRejected)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var doc profileDoc
	if err := dec.Decode(&doc); err != nil {
		// The parse error is examined nowhere and echoed to no one: the
		// caller only receives the generic typed condition.
		return nil, fmt.Errorf("%w: malformed json", ErrProfileRejected)
	}
	return buildProfile(doc)
}

// buildProfile validates the parsed metadata and indexes it. Every rule here
// exists so that a malformed or unsupported profile cannot silently downgrade
// a field's classification; failure is always ErrProfileRejected.
func buildProfile(doc profileDoc) (*Profile, error) {
	if doc.ProfileVersion < 1 {
		return nil, fmt.Errorf("%w: profileVersion", ErrProfileRejected)
	}
	if len(doc.Protocols) == 0 {
		return nil, fmt.Errorf("%w: no protocols", ErrProfileRejected)
	}
	out := make(map[string]map[string]fieldSpec, len(doc.Protocols))
	for pname, p := range doc.Protocols {
		if !protoNameRe.MatchString(pname) {
			return nil, fmt.Errorf("%w: protocol key", ErrProfileRejected)
		}
		if len(p.Fields) == 0 {
			return nil, fmt.Errorf("%w: protocol %s has no fields", ErrProfileRejected, "fields")
		}
		fields := make(map[string]fieldSpec, len(p.Fields))
		for fname, fs := range p.Fields {
			if !fieldNameRe.MatchString(fname) {
				return nil, fmt.Errorf("%w: field key", ErrProfileRejected)
			}
			if !fieldTypes[fs.Type] {
				return nil, fmt.Errorf("%w: field type", ErrProfileRejected)
			}
			switch fs.Classification {
			case "known":
				if fs.Secret != nil {
					return nil, fmt.Errorf("%w: secret flag on known field", ErrProfileRejected)
				}
			case "secret":
				if fs.Secret == nil || !*fs.Secret {
					return nil, fmt.Errorf("%w: secret flag required", ErrProfileRejected)
				}
			default:
				return nil, fmt.Errorf("%w: classification", ErrProfileRejected)
			}
			if fs.Type == "enum" && len(fs.AllowedValues) == 0 {
				return nil, fmt.Errorf("%w: enum without values", ErrProfileRejected)
			}
			if fs.Type == "array" {
				if fs.ItemType != "string" && fs.ItemType != "integer" {
					return nil, fmt.Errorf("%w: array itemType", ErrProfileRejected)
				}
				if fs.MaxItems != nil && *fs.MaxItems < 1 {
					return nil, fmt.Errorf("%w: array maxItems", ErrProfileRejected)
				}
				if fs.MinItems != nil && *fs.MinItems < 0 {
					return nil, fmt.Errorf("%w: array minItems", ErrProfileRejected)
				}
				if fs.MinItems != nil && fs.MaxItems != nil && *fs.MinItems > *fs.MaxItems {
					return nil, fmt.Errorf("%w: array bounds", ErrProfileRejected)
				}
			} else if fs.ItemType != "" || fs.MaxItems != nil || fs.MinItems != nil {
				return nil, fmt.Errorf("%w: array metadata on non-array", ErrProfileRejected)
			}
			if fs.Type == "string" || fs.Type == "enum" {
				if fs.MinLength != nil && *fs.MinLength < 0 {
					return nil, fmt.Errorf("%w: minLength", ErrProfileRejected)
				}
				if fs.MaxLength != nil && *fs.MaxLength < 1 {
					return nil, fmt.Errorf("%w: maxLength", ErrProfileRejected)
				}
				if fs.MinLength != nil && fs.MaxLength != nil && *fs.MinLength > *fs.MaxLength {
					return nil, fmt.Errorf("%w: string bounds", ErrProfileRejected)
				}
				if fs.Pattern != "" {
					re, err := regexp.Compile(fs.Pattern)
					if err != nil {
						return nil, fmt.Errorf("%w: pattern", ErrProfileRejected)
					}
					fs.patternRe = re
				}
			}
			if fs.Type == "integer" {
				if fs.Minimum != nil && fs.Maximum != nil && *fs.Minimum > *fs.Maximum {
					return nil, fmt.Errorf("%w: integer bounds", ErrProfileRejected)
				}
			}
			fields[fname] = fs
		}
		out[pname] = fields
	}
	return &Profile{version: doc.ProfileVersion, protocols: out}, nil
}

// Version reports the validated profileVersion of the loaded authority.
func (p *Profile) Version() int {
	if p == nil {
		return 0
	}
	return p.version
}

// ProjectedNode is the safe public projection of one node's fields.
type ProjectedNode struct {
	Active   map[string]any  `json:"active"`
	Inactive map[string]any  `json:"inactive"`
	Secrets  map[string]bool `json:"secrets"`
	// Unsupported lists declared fields the projection refused to render
	// for the documented fail-closed reason (opaque objects without a leaf
	// allowlist). Names only — never values.
	Unsupported []string `json:"unsupported"`
}

// ProjectNodeFields is the allowlisted read projection. Inputs:
//   - fields: the stored field map (decoded JSON object);
//   - presence: for each declared secret FIELD NAME, whether a sealed value
//     exists (from the store's HasValue, not from this map being consulted
//     for values);
//   - inactive: field names the caller explicitly marks inactive (e.g. an
//     option switched off); declared fields with activeByDefault=false or
//     supported=false are inactive automatically.
//
// Guarantees, in order of precedence:
//   - a field is emitted only if the authored profile declares it; unknown
//     and quarantined fields NEVER pass through, and active/inactive are both
//     filtered;
//   - secret fields are emitted only as presence booleans — never the
//     SecretRef, plaintext, ciphertext or a secret-shaped sentinel;
//   - known scalars (string/integer/boolean/enum) pass with an exact type and
//     bound check; arrays pass only as arrays of declared scalars within
//     bounds — a nested object/array anywhere inside fails the value closed;
//   - declared object fields without a nested leaf allowlist (xhttpExtra,
//     finalMask) are NOT projected: they are reported by name in Unsupported.
//     Copying arbitrary nested children would defeat the projection; fully
//     exposing them needs a profile/contract decision, which is out of scope
//     and not claimed here.
//
// A rejected field is omitted silently except for the opaque-object names;
// omission is safer than echoing. Values are copied, never aliased.
func ProjectNodeFields(p *Profile, protocol string, fields map[string]any, presence map[string]bool, inactive map[string]bool) (ProjectedNode, error) {
	out := ProjectedNode{
		Active:   map[string]any{},
		Inactive: map[string]any{},
		Secrets:  map[string]bool{},
	}
	if p == nil {
		return out, ErrProfileRejected
	}
	decl, ok := p.protocols[protocol]
	if !ok {
		return out, ErrProtocolUnknown
	}
	for name, val := range fields {
		fs, declared := decl[name]
		if !declared {
			continue // unknown/quarantined: never rendered
		}
		dest := out.Active
		if inactive[name] || (fs.ActiveByDefault != nil && !*fs.ActiveByDefault) ||
			(fs.Supported != nil && !*fs.Supported) {
			dest = out.Inactive
		}
		switch fs.Classification {
		case "secret":
			// Presence only. Even a client-supplied presence of "false"
			// is echoed as false, never as a value.
			out.Secrets[name] = presence[name]
		case "known":
			switch fs.Type {
			case "object":
				// Documented fail-closed boundary: no nested leaf allowlist
				// exists for this field, so nothing is copied. Name only.
				out.Unsupported = append(out.Unsupported, name)
			default:
				if safe, ok := safeCopy(val, fs); ok {
					dest[name] = safe
				}
			}
		}
	}
	return out, nil
}

// safeCopy projects one known non-object value. Anything that does not match
// the declared type exactly — including any object or unexpected type nested
// inside an array — is refused (returns ok=false → omitted).
func safeCopy(val any, fs fieldSpec) (any, bool) {
	switch fs.Type {
	case "string":
		s, ok := val.(string)
		if !ok {
			return nil, false
		}
		if fs.MinLength != nil && len(s) < *fs.MinLength {
			return nil, false
		}
		if fs.MaxLength != nil && len(s) > *fs.MaxLength {
			return nil, false
		}
		if fs.patternRe != nil && !fs.patternRe.MatchString(s) {
			return nil, false
		}
		return s, true
	case "integer":
		n, ok := jsonNumber(val)
		if !ok {
			return nil, false
		}
		if fs.Minimum != nil && n < *fs.Minimum {
			return nil, false
		}
		if fs.Maximum != nil && n > *fs.Maximum {
			return nil, false
		}
		return n, true
	case "boolean":
		b, ok := val.(bool)
		return b, ok
	case "enum":
		s, ok := val.(string)
		if !ok {
			return nil, false
		}
		for _, a := range fs.AllowedValues {
			if s == a {
				return s, true
			}
		}
		return nil, false
	case "array":
		arr, ok := val.([]any)
		if !ok {
			return nil, false
		}
		if fs.MaxItems != nil && len(arr) > *fs.MaxItems {
			return nil, false
		}
		if fs.MinItems != nil && len(arr) < *fs.MinItems {
			return nil, false
		}
		item := fieldSpec{Type: fs.ItemType, Classification: "known"}
		outArr := make([]any, 0, len(arr))
		for _, el := range arr {
			if _, isObj := el.(map[string]any); isObj {
				return nil, false // nested object cannot bypass the leaf rules
			}
			sv, ok := safeCopy(el, item)
			if !ok {
				return nil, false
			}
			outArr = append(outArr, sv)
		}
		return outArr, true
	}
	return nil, false
}

// jsonNumber accepts only integral JSON numbers. When the caller decoded with
// encoding/json, numbers arrive as float64; a non-integer or out-of-int64
// value is refused rather than approximated.
func jsonNumber(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		if n != float64(int64(n)) {
			return 0, false
		}
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

// DiagnosticField names one allowlisted diagnostic entry. Diagnostics are
// BUILT from explicitly allowed metadata — never by filtering serialized
// arbitrary source configs and never by regex secret detection. Raw imported
// URL credentials, unknown strings, free-form validation messages and
// arbitrary nested objects must not be routed through this type by callers;
// they are potentially sensitive and omission is safer than echoing.
type DiagnosticField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// BuildDiagnostic projects only the provided allowlisted fields under a
// caller-fixed protocol; each value must already be a safe, nonsecret
// constant the caller owns. Free-form error text and arbitrary config values
// have no path through this function.
func BuildDiagnostic(p *Profile, protocol string, allowed []DiagnosticField) map[string]any {
	out := map[string]any{}
	if p == nil {
		return out
	}
	decl, ok := p.protocols[protocol]
	if !ok {
		return out
	}
	for _, f := range allowed {
		fs, declared := decl[f.Name]
		if !declared || fs.Classification != "known" || fs.Type != "string" {
			continue
		}
		if fs.MaxLength != nil && len(f.Value) > *fs.MaxLength {
			continue
		}
		out[f.Name] = f.Value
	}
	return out
}
