package capability

import "errors"

// This file carries the allowlist projection and closed-vocabulary diagnostics
// that were originally authored in internal/api (T007) and are now owned by the
// capability authority. The api package keeps thin wrappers for compatibility.

// ProjectedNode is the safe public projection of one node's fields.
type ProjectedNode struct {
	Active   map[string]any  `json:"active"`
	Inactive map[string]any  `json:"inactive"`
	Secrets  map[string]bool `json:"secrets"`
	// Unsupported lists declared fields the projection refused to render for
	// the documented fail-closed reason (opaque objects without a leaf
	// allowlist). Names only — never values.
	Unsupported []string `json:"unsupported"`
}

// ErrProtocolUnknown reports a projection or validation request for a protocol
// the authored profile does not declare. Unknown means "project/validate
// nothing", never "pass everything".
var ErrProtocolUnknown = errors.New("capability: protocol not declared by profile")

// ProjectNodeFields is the allowlisted read projection. Inputs:
//   - fields: the stored field map (decoded JSON object);
//   - presence: for each declared secret FIELD NAME, whether a sealed value
//     exists (from the store's trusted HasValue — never from this map);
//   - inactive: field names the caller explicitly marks inactive; declared
//     fields with activeByDefault=false or supported=false are inactive
//     automatically.
//
// Guarantees, in order of precedence:
//   - a field is emitted only if the authored profile declares it; unknown and
//     quarantined fields NEVER pass through;
//   - secret fields are emitted only as presence booleans — never a value;
//   - known scalars pass with an exact type/bound check; arrays pass only as
//     arrays of declared scalars within bounds (a nested object/array anywhere
//     inside fails the value closed);
//   - declared object fields without a nested leaf allowlist are NOT projected;
//     they are reported by name in Unsupported.
//
// Values are copied, never aliased.
// InactiveNames returns the names of DECLARED fields for a protocol that
// are allowlisted to surface in Projection.Inactive: inactive by default
// (HasActiveByDef && !ActiveByDefault) or unsupported (HasSupported &&
// !Supported). Secret, nested-object and unknown/quarantined names are
// NEVER returned, so a caller can mark exactly the readable inactive subset
// as inactive without leaking a secret/nested/unknown value into the
// projection. Safe for concurrent use.
func (p *Profile) InactiveNames(protocol string) []string {
	if p == nil {
		return nil
	}
	proto, ok := p.protocols[protocol]
	if !ok {
		return nil
	}
	out := []string{}
	for name, fi := range proto.fields {
		f := fi.Field
		if f.Classification != "known" || f.Type == "object" {
			continue // secrets presence-only, nested never surfaced
		}
		// Any readable known non-object field may surface as inactive when the
		// caller explicitly places it in the inactive bucket: an active-by-default
		// field so marked is preserved in Inactive (not dropped, not promoted into
		// Active); an unsupported/default-inactive field stays inactive.
		out = append(out, name)
	}
	return out
}

func (p *Profile) ProjectNodeFields(protocol string, fields map[string]any, presence map[string]bool, inactive map[string]bool) (ProjectedNode, error) {
	out := ProjectedNode{
		Active:   map[string]any{},
		Inactive: map[string]any{},
		Secrets:  map[string]bool{},
	}
	if p == nil {
		return out, ErrProfileRejected
	}
	proto, ok := p.protocols[protocol]
	if !ok {
		return out, ErrProtocolUnknown
	}
	for name, val := range fields {
		fi, declared := proto.fields[name]
		if !declared {
			continue // unknown/quarantined: never rendered
		}
		f := fi.Field
		dest := out.Active
		if inactive[name] || (f.HasActiveByDef && !f.ActiveByDefault) ||
			(f.HasSupported && !f.Supported) {
			dest = out.Inactive
		}
		switch f.Classification {
		case "secret":
			// Presence only. Even a client-supplied presence of false is echoed
			// as false, never as a value.
			out.Secrets[name] = presence[name]
		case "known":
			if f.Type == "object" {
				// Documented fail-closed boundary: no nested leaf allowlist, so
				// nothing is copied. Name only.
				out.Unsupported = append(out.Unsupported, name)
				continue
			}
			if safe, ok := checkValue(val, fi); ok {
				dest[name] = safe
			}
		}
	}
	return out, nil
}

// DiagnosticCode is the CLOSED vocabulary of diagnostic facts a caller may
// report. Its set of valid members is fixed; any other value is rejected
// fail-closed at construction. There is intentionally NO surface that accepts
// a caller-supplied string VALUE: outward text can only be a fixed constant.
type DiagnosticCode string

const (
	DiagConfigParseFailed DiagnosticCode = "configParseFailed"
	DiagApplyPending      DiagnosticCode = "applyPending"
	DiagSecretMissing     DiagnosticCode = "secretMissing"
)

var diagnosticText = map[DiagnosticCode]string{
	DiagConfigParseFailed: "configuration could not be parsed",
	DiagApplyPending:      "configuration change is pending apply",
	DiagSecretMissing:     "referenced secret is missing",
}

// diagnosticFieldNames maps a code to the allowlisted declared known-string
// field that authorizes carrying this fact (carrier-availability gate only; no
// caller value ever flows through).
var diagnosticFieldNames = map[DiagnosticCode]string{
	DiagConfigParseFailed: "sni",
	DiagApplyPending:      "sni",
	DiagSecretMissing:     "sni",
}

func (c DiagnosticCode) isValid() bool {
	_, ok := diagnosticText[c]
	return ok
}

// Diagnostic is one projected diagnostic entry: a fixed package constant, never
// caller bytes.
type Diagnostic struct {
	Code  DiagnosticCode `json:"code"`
	Value string         `json:"value"`
}

// BuildDiagnostic projects the supplied closed-vocabulary codes under the
// caller-fixed protocol. Rules, all fail-closed: nil profile or undeclared
// protocol → empty; unknown codes skipped; a code is emitted only where the
// profile declares its mapped field as a known string within bounds.
func (p *Profile) BuildDiagnostic(protocol string, codes []DiagnosticCode) map[string]Diagnostic {
	out := map[string]Diagnostic{}
	if p == nil {
		return out
	}
	proto, ok := p.protocols[protocol]
	if !ok {
		return out
	}
	for _, code := range codes {
		if !code.isValid() {
			continue
		}
		fname, mapped := diagnosticFieldNames[code]
		fi, declared := proto.fields[fname]
		if !mapped || !declared || fi.Classification != "known" || fi.Type != "string" {
			continue
		}
		text := diagnosticText[code]
		if fi.HasMaxLength && len(text) > fi.MaxLength {
			continue
		}
		out[string(code)] = Diagnostic{Code: code, Value: text}
	}
	return out
}
