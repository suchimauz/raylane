package nodes

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/suchimauz/raylane/internal/capability"
	"github.com/suchimauz/raylane/internal/domain"
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

// nodeEnvelope is the documented canonical write envelope compatible with the
// current OpenAPI NodeFields shape: a protocol plus active/inactive/unknown
// field buckets. Secrets are carried by trusted presence, never by value.
type nodeEnvelope struct {
	Protocol string `json:"protocol"`
	Fields   struct {
		Active   map[string]any `json:"active"`
		Inactive map[string]any `json:"inactive"`
		Unknown  map[string]any `json:"unknown"`
	} `json:"fields"`
}

// ErrNotANodeEnvelope reports that syntactically valid JSON does not match the
// canonical node envelope (a protocol plus a fields object). It is a typed,
// value-free condition: the caller maps it to an invalid draft, never to a
// parse error and never to a value echo.
var ErrNotANodeEnvelope = errors.New("nodes: payload is not a node envelope")

// ValidateDocument is the document adapter (decision F). It takes the ORIGINAL
// submitted bytes plus the trusted sealed-secret presence, runs the existing
// syntax gate (domain.ParseDocument), then — when the bytes are a canonical
// node envelope — runs Validate. Rules:
//
//   - malformed JSON → domain.ErrMalformedJSON, no Document, no replacement;
//   - valid JSON but not a node envelope → ErrNotANodeEnvelope (the caller
//     maps this to an invalid draft; the original bytes are preserved);
//   - a valid envelope that is semantically invalid → ValidationInvalid with
//     the EXACT original bytes preserved and no mutation or side effect;
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
	// Decode the canonical envelope. We decode from the PRESERVED doc.Raw, not
	// from a re-marshal, so the validation view matches the stored bytes.
	var env nodeEnvelope
	dec := json.NewDecoder(bytes.NewReader(doc.Raw))
	dec.UseNumber()
	if err := dec.Decode(&env); err != nil {
		// Syntactically valid (ParseDocument passed) but not the envelope
		// shape: this is a semantic/envelope problem, not malformed JSON.
		doc.Validation = domain.ValidationInvalid
		return AdapterResult{Document: doc, Validation: domain.ValidationInvalid, Result: Result{
			Status: Invalid, Applicable: false,
			Issues: []Issue{{Code: IssueUnknownField, Field: "fields", Reason: issueReason[IssueUnknownField]}},
		}}, ErrNotANodeEnvelope
	}
	if env.Protocol == "" {
		doc.Validation = domain.ValidationInvalid
		return AdapterResult{Document: doc, Validation: domain.ValidationInvalid, Result: Result{
			Status: Invalid, Applicable: false,
			Issues: []Issue{{Code: IssueUnknownField, Field: "protocol", Reason: issueReason[IssueUnknownField]}},
		}}, ErrNotANodeEnvelope
	}
	// An envelope may carry an unknown bucket; those names are attacker-
	// controlled and are folded into the active map's unknown detection by the
	// validator. We pass active/inactive; unknown names are treated as unknown
	// by merging them into the active view under their (bucketed) handling.
	active := env.Fields.Active
	if active == nil {
		active = map[string]any{}
	}
	// Unknown-bucket names are not declared; the validator reports them under
	// the generic bucket path. Merge so they are seen as unknown fields.
	for k := range env.Fields.Unknown {
		if _, seen := active[k]; !seen {
			active[k] = env.Fields.Unknown[k]
		}
	}
	res := Validate(profile, Input{
		Protocol:       env.Protocol,
		Active:         active,
		Inactive:       env.Fields.Inactive,
		SecretPresence: presence,
	})
	if res.Status == Valid {
		doc.Validation = domain.ValidationValid
	} else {
		doc.Validation = domain.ValidationInvalid
	}
	return AdapterResult{Document: doc, Validation: doc.Validation, Result: res}, nil
}
