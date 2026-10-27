// Package capability is the single maintained capability authority for node
// field metadata. It was extracted from internal/api (T007 projection) and
// enriched for T011: the authored profile's required/default/dependencies
// metadata is now genuinely parsed, validated and enforced, not merely stored.
//
// The model is private and immutable after Parse. Callers read precise
// metadata through the accessor methods; nothing exposes the internal maps, so
// no caller can mutate the loaded authority. The api package keeps
// compatibility aliases/wrappers (api.Profile, api.ParseCapabilityProfile,
// api.ProjectNodeFields, api.BuildDiagnostic) so existing consumers and tests
// continue to work against ONE parser — there is deliberately no second copy.
//
// Normative basis: contracts/capability-profile.json (+ .schema.json) and the
// field inventory; decision D1/D3 in docs/discovery/DECISIONS.md.
package capability

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/suchimauz/raylane/internal/jsonscan"
)

// ErrProfileRejected reports malformed, missing or unsupported profile
// metadata. Initialization fails closed; there is no default profile and no
// fallback classification. The message is reason-only — it never echoes raw
// decoder errors, field values or configuration bytes.
var ErrProfileRejected = errors.New("capability: capability profile rejected")

// Dependencies is the validated field-level dependency metadata. Requires
// lists fields that must be present when this field is present;
// IncompatibleWith lists fields that must NOT be present.
type Dependencies struct {
	Requires         []string
	IncompatibleWith []string
}

// Field is the validated, immutable metadata for one declared field. It is a
// read-only snapshot; the caller cannot reach back into the authority's maps.
type Field struct {
	Name            string
	Type            string
	Classification  string // "known" | "secret"
	Secret          bool
	Required        bool
	HasDefault      bool
	Default         any // typed value; meaningful only when HasDefault
	AllowedValues   []string
	ItemType        string
	HasMinItems     bool
	MinItems        int
	HasMaxItems     bool
	MaxItems        int
	HasMinLength    bool
	MinLength       int
	HasMaxLength    bool
	MaxLength       int
	HasMinimum      bool
	Minimum         int64
	HasMaximum      bool
	Maximum         int64
	Pattern         string
	HasSupported    bool
	Supported       bool
	HasActiveByDef  bool
	ActiveByDefault bool
	Dependencies    *Dependencies
}

// patternRe is compiled at parse time; kept private so callers cannot match
// attacker text against an unexported regexp with attacker flags.
type fieldInternal struct {
	Field
	patternRe *regexp.Regexp
}

type protocolInternal struct {
	fields   map[string]fieldInternal
	ordering []string // stable declaration order for deterministic issues
}

// Profile is the validated classification + validation authority.
type Profile struct {
	version   int
	protocols map[string]*protocolInternal
}

var (
	fieldNameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.]{0,63}$`)
	protoNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	fieldTypes  = map[string]bool{"string": true, "integer": true, "boolean": true, "enum": true, "array": true, "object": true}

	// fieldSpecKeys is the closed set of metadata keys the parser accepts. Any
	// unknown key fails closed (strict metadata) instead of being silently
	// ignored — the T011 enrichment turns previously-ignored metadata into
	// enforced, and refuses metadata it does not understand.
	fieldSpecKeys = map[string]bool{
		"type": true, "classification": true, "secret": true, "required": true,
		"default": true, "allowedValues": true, "itemType": true,
		"minItems": true, "maxItems": true, "minLength": true, "maxLength": true,
		"minimum": true, "maximum": true, "pattern": true, "dependencies": true,
		"supported": true, "activeByDefault": true,
	}
)

// rawFieldSpec mirrors the authored JSON for ONE field during decode. Decoding
// into a struct with DisallowUnknownFields gives strict unknown-key rejection.
type rawFieldSpec struct {
	Type            string           `json:"type"`
	Classification  string           `json:"classification"`
	Secret          *bool            `json:"secret"`
	Required        *bool            `json:"required"`
	Default         json.RawMessage  `json:"default"`
	AllowedValues   []string         `json:"allowedValues"`
	ItemType        string           `json:"itemType"`
	MinItems        *int             `json:"minItems"`
	MaxItems        *int             `json:"maxItems"`
	MinLength       *int             `json:"minLength"`
	MaxLength       *int             `json:"maxLength"`
	Minimum         *int64           `json:"minimum"`
	Maximum         *int64           `json:"maximum"`
	Pattern         string           `json:"pattern"`
	Supported       *bool            `json:"supported"`
	ActiveByDefault *bool            `json:"activeByDefault"`
	Dependencies    *rawDependencies `json:"dependencies"`
}

type rawDependencies struct {
	Requires         []string `json:"requires"`
	IncompatibleWith []string `json:"incompatibleWith"`
}

type rawProtocolProfile struct {
	Fields map[string]rawFieldSpec `json:"fields"`
}

// rawProfileDoc is the top-level authored document. profileVersion and
// protocols are required; DisallowUnknownFields makes any stray top-level key
// fail closed.
type rawProfileDoc struct {
	ProfileVersion int                           `json:"profileVersion"`
	Protocols      map[string]rawProtocolProfile `json:"protocols"`
}

// rejectDuplicateKeys re-scans the raw profile bytes with the neutral
// structural scanner (internal/jsonscan) and rejects any JSON object whose
// keys repeat, at every nesting level, plus anything that is not exactly one
// JSON value. The scanner yields only a structural verdict — key and value
// bytes are never retained or echoed — which this boundary maps to its own
// static sentinel. This is the strict-authority rule behind "duplicate keys"
// in Parse, and it is the SAME scanner the node envelope adapter uses: one
// mechanism, no second copy.
func rejectDuplicateKeys(raw []byte) error {
	serr := jsonscan.FullValue(raw)
	switch {
	case serr == nil:
		return nil
	case errors.Is(serr, jsonscan.ErrDuplicateKey):
		return fmt.Errorf("%w: duplicate json key", ErrProfileRejected)
	default:
		return fmt.Errorf("%w: malformed json", ErrProfileRejected)
	}
}

// Parse validates the authored capability-profile bytes and indexes them for
// projection and node validation. It verifies version, protocol/field key
// shapes, the full metadata vocabulary (type, classification, secret flag,
// required, default presence and default validity, enum value sets, array
// item/bounds, integer/length bounds, regex compiles, supported/activeByDefault
// and dependency target membership) and fails closed on anything else,
// including unknown metadata keys, duplicate keys and trailing JSON.
func Parse(raw []byte) (*Profile, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("%w: empty profile", ErrProfileRejected)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber() // preserve integer defaults without float64 rounding
	var doc rawProfileDoc
	if err := dec.Decode(&doc); err != nil {
		// Reason-only: the decoder message (which may quote bytes) goes nowhere.
		return nil, fmt.Errorf("%w: malformed json", ErrProfileRejected)
	}
	// Trailing content after the top-level value is a malformed profile.
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrProfileRejected)
	}
	// Strict duplicate-key rejection. encoding/json silently keeps the LAST
	// duplicate when decoding into structs/maps of concrete types, so the raw
	// bytes are re-scanned structurally: every object at the document,
	// protocol and field levels must have unique keys. A duplicate means the
	// authority would be ambiguous about which definition wins — fail closed
	// with the static reason only; the conflicting bytes are never echoed.
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, err
	}
	return build(doc)
}

// build validates the parsed metadata and indexes it. Duplicate keys are
// rejected earlier by rejectDuplicateKeys over the raw bytes (struct decode
// silently collapses them), so by here the document is unambiguous.
func build(doc rawProfileDoc) (*Profile, error) {
	if doc.ProfileVersion < 1 {
		return nil, fmt.Errorf("%w: profileVersion", ErrProfileRejected)
	}
	if len(doc.Protocols) == 0 {
		return nil, fmt.Errorf("%w: no protocols", ErrProfileRejected)
	}
	out := make(map[string]*protocolInternal, len(doc.Protocols))
	for pname, p := range doc.Protocols {
		if !protoNameRe.MatchString(pname) {
			return nil, fmt.Errorf("%w: protocol key", ErrProfileRejected)
		}
		if len(p.Fields) == 0 {
			return nil, fmt.Errorf("%w: protocol has no fields", ErrProfileRejected)
		}
		proto := &protocolInternal{fields: make(map[string]fieldInternal, len(p.Fields))}
		for fname, rfs := range p.Fields {
			fi, err := buildField(fname, rfs, p.Fields)
			if err != nil {
				return nil, err
			}
			proto.fields[fname] = fi
		}
		out[pname] = proto
	}
	return &Profile{version: doc.ProfileVersion, protocols: out}, nil
}

// buildField validates one field's metadata. siblingFields is the protocol's
// full field map, used to resolve dependency targets within the same protocol.
func buildField(fname string, rfs rawFieldSpec, siblingFields map[string]rawFieldSpec) (fieldInternal, error) {
	if !fieldNameRe.MatchString(fname) {
		return fieldInternal{}, fmt.Errorf("%w: field key", ErrProfileRejected)
	}
	if !fieldTypes[rfs.Type] {
		return fieldInternal{}, fmt.Errorf("%w: field type", ErrProfileRejected)
	}
	fi := fieldInternal{Field: Field{Name: fname, Type: rfs.Type, Classification: rfs.Classification}}
	switch rfs.Classification {
	case "known":
		if rfs.Secret != nil {
			return fieldInternal{}, fmt.Errorf("%w: secret flag on known field", ErrProfileRejected)
		}
	case "secret":
		if rfs.Secret == nil || !*rfs.Secret {
			return fieldInternal{}, fmt.Errorf("%w: secret flag required", ErrProfileRejected)
		}
		fi.Secret = true
		if rfs.Default != nil {
			// A secret must never carry a default (plaintext-by-default).
			return fieldInternal{}, fmt.Errorf("%w: default on secret field", ErrProfileRejected)
		}
	default:
		return fieldInternal{}, fmt.Errorf("%w: classification", ErrProfileRejected)
	}
	if rfs.Required != nil {
		fi.Required = *rfs.Required
		fi.Field.Required = *rfs.Required
	}
	// Default presence: absent != explicit false/0/"". A default must type-check
	// against the declared constraints; presence is recorded, not materialized.
	if rfs.Default != nil {
		dv, err := checkDefault(rfs)
		if err != nil {
			return fieldInternal{}, err
		}
		fi.HasDefault = true
		fi.Default = dv
	}
	if rfs.Type == "enum" {
		if len(rfs.AllowedValues) == 0 {
			return fieldInternal{}, fmt.Errorf("%w: enum without values", ErrProfileRejected)
		}
		fi.AllowedValues = append([]string(nil), rfs.AllowedValues...)
	}
	if rfs.Type == "array" {
		if rfs.ItemType != "string" && rfs.ItemType != "integer" {
			return fieldInternal{}, fmt.Errorf("%w: array itemType", ErrProfileRejected)
		}
		fi.ItemType = rfs.ItemType
		if rfs.MaxItems != nil {
			if *rfs.MaxItems < 0 {
				return fieldInternal{}, fmt.Errorf("%w: array maxItems", ErrProfileRejected)
			}
			fi.HasMaxItems = true
			fi.MaxItems = *rfs.MaxItems
		}
		if rfs.MinItems != nil {
			if *rfs.MinItems < 0 {
				return fieldInternal{}, fmt.Errorf("%w: array minItems", ErrProfileRejected)
			}
			fi.HasMinItems = true
			fi.MinItems = *rfs.MinItems
		}
		if fi.HasMinItems && fi.HasMaxItems && fi.MinItems > fi.MaxItems {
			return fieldInternal{}, fmt.Errorf("%w: array bounds", ErrProfileRejected)
		}
	} else if rfs.ItemType != "" || rfs.MaxItems != nil || rfs.MinItems != nil {
		return fieldInternal{}, fmt.Errorf("%w: array metadata on non-array", ErrProfileRejected)
	}
	if rfs.Type == "string" || rfs.Type == "enum" {
		if rfs.MinLength != nil {
			if *rfs.MinLength < 0 {
				return fieldInternal{}, fmt.Errorf("%w: minLength", ErrProfileRejected)
			}
			fi.HasMinLength = true
			fi.MinLength = *rfs.MinLength
		}
		if rfs.MaxLength != nil {
			if *rfs.MaxLength < 0 {
				return fieldInternal{}, fmt.Errorf("%w: maxLength", ErrProfileRejected)
			}
			fi.HasMaxLength = true
			fi.MaxLength = *rfs.MaxLength
		}
		if fi.HasMinLength && fi.HasMaxLength && fi.MinLength > fi.MaxLength {
			return fieldInternal{}, fmt.Errorf("%w: string bounds", ErrProfileRejected)
		}
		if rfs.Pattern != "" {
			re, err := regexp.Compile(rfs.Pattern)
			if err != nil {
				return fieldInternal{}, fmt.Errorf("%w: pattern", ErrProfileRejected)
			}
			fi.Pattern = rfs.Pattern
			fi.patternRe = re
		}
	} else if rfs.Pattern != "" {
		return fieldInternal{}, fmt.Errorf("%w: pattern on non-string", ErrProfileRejected)
	}
	if rfs.Type == "integer" {
		if rfs.Minimum != nil {
			fi.HasMinimum = true
			fi.Minimum = *rfs.Minimum
		}
		if rfs.Maximum != nil {
			fi.HasMaximum = true
			fi.Maximum = *rfs.Maximum
		}
		if fi.HasMinimum && fi.HasMaximum && fi.Minimum > fi.Maximum {
			return fieldInternal{}, fmt.Errorf("%w: integer bounds", ErrProfileRejected)
		}
	}
	if rfs.Supported != nil {
		fi.HasSupported = true
		fi.Supported = *rfs.Supported
	}
	if rfs.ActiveByDefault != nil {
		fi.HasActiveByDef = true
		fi.ActiveByDefault = *rfs.ActiveByDefault
	}
	if rfs.Dependencies != nil {
		deps, err := buildDependencies(fname, rfs.Dependencies, siblingFields)
		if err != nil {
			return fieldInternal{}, err
		}
		fi.Dependencies = deps
	}
	return fi, nil
}

// buildDependencies validates dependency target membership within the same
// protocol and copies the slices so callers cannot alias the authority.
func buildDependencies(fname string, rd *rawDependencies, siblingFields map[string]rawFieldSpec) (*Dependencies, error) {
	d := &Dependencies{}
	if rd.Requires != nil {
		d.Requires = make([]string, 0, len(rd.Requires))
		for _, t := range rd.Requires {
			if _, ok := siblingFields[t]; !ok {
				return nil, fmt.Errorf("%w: dependency target", ErrProfileRejected)
			}
			if t == fname {
				// A field that requires itself is an unsatisfiable authored rule
				// (presence would always resolve it) — an authoring error that
				// must fail closed, not silently pass.
				return nil, fmt.Errorf("%w: dependency self-reference", ErrProfileRejected)
			}
			d.Requires = append(d.Requires, t)
		}
	}
	if rd.IncompatibleWith != nil {
		d.IncompatibleWith = make([]string, 0, len(rd.IncompatibleWith))
		for _, t := range rd.IncompatibleWith {
			if _, ok := siblingFields[t]; !ok {
				return nil, fmt.Errorf("%w: dependency target", ErrProfileRejected)
			}
			if t == fname {
				// Incompatible with itself means never present — also an
				// authoring error, rejected rather than silently accepted.
				return nil, fmt.Errorf("%w: dependency self-reference", ErrProfileRejected)
			}
			d.IncompatibleWith = append(d.IncompatibleWith, t)
		}
	}
	return d, nil
}

// checkDefault validates an authored default against the field's own declared
// constraints and returns it as a typed Go value. UseNumber keeps integers
// exact. The default must satisfy type, bounds and enum membership.
func checkDefault(rfs rawFieldSpec) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(rfs.Default))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: default not a value", ErrProfileRejected)
	}
	item := fieldInternal{Field: Field{
		Type: rfs.Type, Classification: "known",
		AllowedValues: rfs.AllowedValues, ItemType: rfs.ItemType,
		HasMinItems: rfs.MinItems != nil, MinItems: derefInt(rfs.MinItems),
		HasMaxItems: rfs.MaxItems != nil, MaxItems: derefInt(rfs.MaxItems),
		HasMinLength: rfs.MinLength != nil, MinLength: derefInt(rfs.MinLength),
		HasMaxLength: rfs.MaxLength != nil, MaxLength: derefInt(rfs.MaxLength),
		HasMinimum: rfs.Minimum != nil, Minimum: derefInt64(rfs.Minimum),
		HasMaximum: rfs.Maximum != nil, Maximum: derefInt64(rfs.Maximum),
	}}
	if rfs.Pattern != "" {
		re, err := regexp.Compile(rfs.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%w: pattern", ErrProfileRejected)
		}
		item.Pattern = rfs.Pattern
		item.patternRe = re
	}
	if _, ok := checkValue(v, item); !ok {
		return nil, fmt.Errorf("%w: default violates constraints", ErrProfileRejected)
	}
	// Normalize json.Number to int64 for integer defaults so callers see a
	// stable typed value, not a decoder-specific json.Number.
	if rfs.Type == "integer" {
		if n, ok := v.(json.Number); ok {
			i, err := n.Int64()
			if err != nil {
				return nil, fmt.Errorf("%w: default integer", ErrProfileRejected)
			}
			return i, nil
		}
	}
	return v, nil
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// Version reports the validated profileVersion of the loaded authority.
func (p *Profile) Version() int {
	if p == nil {
		return 0
	}
	return p.version
}

// HasProtocol reports whether the profile declares the protocol.
func (p *Profile) HasProtocol(protocol string) bool {
	if p == nil {
		return false
	}
	_, ok := p.protocols[protocol]
	return ok
}

// Protocols returns the sorted declared protocol names (copy).
func (p *Profile) Protocols() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.protocols))
	for name := range p.protocols {
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

// Field returns the metadata for one declared field and whether it is declared.
// The returned Field is a value snapshot; mutating it does not affect the
// authority.
func (p *Profile) Field(protocol, name string) (Field, bool) {
	if p == nil {
		return Field{}, false
	}
	proto, ok := p.protocols[protocol]
	if !ok {
		return Field{}, false
	}
	fi, ok := proto.fields[name]
	if !ok {
		return Field{}, false
	}
	// Deep-copy slices so the caller cannot alias the authority's arrays.
	f := fi.Field
	if fi.AllowedValues != nil {
		f.AllowedValues = append([]string(nil), fi.AllowedValues...)
	}
	if fi.Dependencies != nil {
		d := &Dependencies{}
		if fi.Dependencies.Requires != nil {
			d.Requires = append([]string(nil), fi.Dependencies.Requires...)
		}
		if fi.Dependencies.IncompatibleWith != nil {
			d.IncompatibleWith = append([]string(nil), fi.Dependencies.IncompatibleWith...)
		}
		f.Dependencies = d
	}
	return f, true
}

// FieldNames returns the declared field names for a protocol in stable order.
func (p *Profile) FieldNames(protocol string) []string {
	if p == nil {
		return nil
	}
	proto, ok := p.protocols[protocol]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(proto.fields))
	for name := range proto.fields {
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

// MatchPattern reports whether value matches a declared string field's
// compiled pattern. The field snapshot does not carry the compiled regexp (it
// stays on the private internal spec), so this package-level helper is the one
// narrow way to evaluate a pattern. A field with no pattern matches anything.
func MatchPattern(f Field, value string) bool {
	if f.Pattern == "" {
		return true
	}
	// Recompile is avoided in the hot path by the profile; this helper exists
	// for the standalone Field snapshot used by the validator. Patterns are
	// authored (trusted), not attacker-supplied, so compiling here is safe.
	re, err := regexp.Compile(f.Pattern)
	if err != nil {
		return false // a pattern that fails to compile fails closed
	}
	return re.MatchString(value)
}
