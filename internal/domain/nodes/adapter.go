package nodes

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/jsonscan"
)

// AdapterResult is the outcome of validating an original submitted node
// document. It preserves the EXACT original bytes for honest draft storage
// and reports the syntax/semantic outcome without mutating anything.
type AdapterResult struct {
	// Document is the syntax-gated original document. Raw is the exact
	// submitted bytes (preserved verbatim, never rewritten or defaulted).
	Document domain.Document
	// Validation is the explicit semantic verdict (Valid or Invalid). It is
	// ValidationNotRun only when validation did not run (never for a decoded
	// envelope); a malformed payload is rejected before a Document exists.
	Validation domain.ValidationStatus
	// Result is the detailed value-free validation result when validation ran.
	Result Result
}

// ErrNotANodeEnvelope reports that syntactically valid JSON does not match the
// canonical node envelope. It is a typed, value-free condition: the caller
// maps it to an invalid draft, never to a parse error and never to a value
// echo.
var ErrNotANodeEnvelope = errors.New("nodes: payload is not a node envelope")

// envelopeIssueField is the fixed, profile-independent path every envelope
// structural failure is reported under. It never carries a submitted name.
const envelopeIssueField = "envelope"

// The canonical write envelope is CLOSED and exact (contract: a protocol plus
// a fields object):
//
//	{"protocol": string,
//	 "fields": {"active": object, "inactive": object, "unknown": object}}
//
// All three buckets must be present objects ({} is allowed); no other member
// exists at the root or inside fields. Go's case-insensitive struct-tag
// matching would ACCEPT lookalikes like "Protocol" or "ACTIVE", so the decode
// is done over raw members with EXACT key comparison instead of struct tags.
// Duplicate keys at ANY object level are rejected by the shared neutral
// scanner before decoding, and the document must be exactly one JSON value.
const (
	envMemberProtocol = "protocol"
	envMemberFields   = "fields"
	bucketActive      = "active"
	bucketInactive    = "inactive"
	bucketUnknown     = "unknown"
)

// envelopeRejected builds the fixed invalid outcome for a non-canonical
// envelope: value-free closed issue, exact raw preserved, ErrNotANodeEnvelope
// as the typed error. reasonCode is one of the package's closed codes chosen
// from package constants; it never derives from input bytes.
func envelopeRejected(doc domain.Document, code IssueCode) (AdapterResult, error) {
	doc.Validation = domain.ValidationInvalid
	return AdapterResult{
		Document:   doc,
		Validation: domain.ValidationInvalid,
		Result: Result{
			Status:     Invalid,
			Applicable: false,
			Issues:     []Issue{{Code: code, Field: envelopeIssueField, Reason: issueReason[code]}},
		},
	}, ErrNotANodeEnvelope
}

// ValidateDocument is the document adapter (decision F). It takes the ORIGINAL
// submitted bytes plus the trusted sealed-secret presence, runs the existing
// syntax gate (domain.ParseDocument), then — when the bytes are a canonical
// node envelope — runs Validate. Rules:
//
//   - malformed JSON or trailing content → domain.ErrMalformedJSON, no
//     Document, no replacement;
//   - valid JSON that is not the exact canonical envelope (missing/null/
//     non-object members, a non-string or empty protocol, unknown members at
//     any level, duplicate keys at any level) → ErrNotANodeEnvelope with
//     ValidationInvalid and the EXACT original bytes preserved (the caller
//     maps this to an invalid draft; nothing is echoed);
//   - a canonical envelope that is semantically invalid → ValidationInvalid
//     with the EXACT original bytes preserved and no mutation or defaulting;
//   - the adapter never turns a semantic problem into a parse error and never
//     materializes an absent field into a default.
//
// presence is the store-supplied sealed-secret map (trusted), never a client
// boolean. The adapter performs no store write and no transport.
func ValidateDocument(profile *capability.Profile, original []byte, presence map[string]bool) (AdapterResult, error) {
	// Syntax gate first: a malformed payload is not a Document at all.
	doc, err := domain.ParseDocument(original)
	if err != nil {
		return AdapterResult{}, err // domain.ErrMalformedJSON
	}
	// Full-consumption and duplicate-key gate over the raw bytes, using the
	// same neutral scanner as the capability authority. A duplicate anywhere
	// in the document is a non-canonical envelope (semantic, raw preserved);
	// anything else the scanner cannot walk on bytes json.Valid accepted can
	// only mean trailing content — still malformed JSON, no Document.
	if serr := jsonscan.FullValue(doc.Raw); serr != nil {
		if errors.Is(serr, jsonscan.ErrDuplicateKey) {
			return envelopeRejected(doc, IssueMalformedEnvelope)
		}
		// Trailing content: the syntax gate's contract (ErrMalformedJSON with
		// NO Document) wins, exactly as for unparseable bytes.
		return AdapterResult{}, domain.ErrMalformedJSON
	}
	// Decode the envelope over RAW members (UseNumber preserves integer
	// fidelity). Map decode is permissive by construction; the closed shape
	// is enforced explicitly below with exact key comparison. The document
	// already passed the syntax hard gate, so if the ROOT is not a JSON object
	// (array/scalar) the decode fails here — that is a non-canonical ENVELOPE
	// (semantic), never malformed JSON: the exact original bytes are preserved
	// and the caller maps it to an invalid draft.
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(doc.Raw))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return envelopeRejected(doc, IssueMalformedEnvelope)
	}
	protocol, fields, ok := canonicalEnvelope(raw)
	if !ok {
		return envelopeRejected(doc, IssueMalformedEnvelope)
	}
	active, inactive, unknown, ok := canonicalBuckets(fields)
	if !ok {
		return envelopeRejected(doc, IssueMalformedEnvelope)
	}
	res := Validate(profile, Input{
		Protocol:       protocol,
		Active:         active,
		Inactive:       inactive,
		Unknown:        unknown,
		SecretPresence: presence,
	})
	if res.Status == Valid {
		doc.Validation = domain.ValidationValid
	} else {
		doc.Validation = domain.ValidationInvalid
	}
	return AdapterResult{Document: doc, Validation: doc.Validation, Result: res}, nil
}

// canonicalEnvelope enforces the exact root members: exactly "protocol" and
// "fields", nothing else. The protocol must be a JSON string and non-empty;
// "fields" must be a JSON object. Keys are compared exactly (case-sensitive,
// already unescaped by the decoder), so "Protocol" is unknown, not an alias.
func canonicalEnvelope(raw map[string]json.RawMessage) (protocol string, fields map[string]json.RawMessage, ok bool) {
	if len(raw) != 2 {
		return "", nil, false
	}
	protoRaw, hasProto := raw[envMemberProtocol]
	fieldsRaw, hasFields := raw[envMemberFields]
	if !hasProto || !hasFields {
		return "", nil, false
	}
	if err := json.Unmarshal(protoRaw, &protocol); err != nil {
		return "", nil, false
	}
	if protocol == "" {
		return "", nil, false
	}
	if err := json.Unmarshal(fieldsRaw, &fields); err != nil {
		return "", nil, false
	}
	if fields == nil { // "fields": null decodes to a nil map without error
		return "", nil, false
	}
	return protocol, fields, true
}

// canonicalBuckets enforces the exact fields members: all of "active",
// "inactive" and "unknown", each a JSON object (empty allowed), nothing else.
// An absent or null bucket is NOT defaulted — the envelope either states its
// buckets or is refused. The returned maps are decoded with UseNumber
// fidelity via decodeObject.
func canonicalBuckets(fields map[string]json.RawMessage) (active, inactive, unknown map[string]any, ok bool) {
	if len(fields) != 3 {
		return nil, nil, nil, false
	}
	a, aok := decodeObject(fields[bucketActive])
	i, iok := decodeObject(fields[bucketInactive])
	u, uok := decodeObject(fields[bucketUnknown])
	if !aok || !iok || !uok {
		return nil, nil, nil, false
	}
	return a, i, u, true
}

// decodeObject decodes a raw member into a field map, requiring it to be a
// JSON object ({} decodes to an empty non-nil map; null, scalars, arrays and
// malformed members fail closed).
func decodeObject(raw json.RawMessage) (map[string]any, bool) {
	if len(raw) == 0 { // absent member: json.RawMessage zero value
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	m := map[string]any{}
	if err := dec.Decode(&m); err != nil {
		return nil, false
	}
	if m == nil { // explicit null
		return nil, false
	}
	return m, true
}
