package authhttp

// Authenticated managed-node CREATE and SAFE GET (T012 functional slice).
//
// POST /api/v1/nodes — session-authenticated, Origin-checked, bounded once at
// 262144 bytes. The closed OUTER wire shape is validated strictly here
// (transport 400), the typed secret operations deterministically (422 static,
// no input echo), and everything semantic flows to the accepted atomic writer
// CreateNodeAtomic: an Invalid draft SAVES (201), it is never refused, never
// recomputed and never re-validated here. Saving never applies anything.
//
// GET /api/v1/nodes/{id} — session-authenticated safe read through the
// keyless NodeReader over the SAME store: safe projection, CURRENT row-backed
// secret presence, and the FULL historical verdict, with no key, no decrypt,
// and no partial publication.
//
// The outward wire mapping is EXPLICIT (never a wholesale marshal of the
// store outcome): protocol is emitted only when the decoded derived protocol
// is a member of the closed wire enum (the read-time membership guard),
// fields are the copied safe projection plus the always-empty unknown bucket,
// secrets carry only declared-name presence booleans, and validation is the
// exact historical verdict — every ordered issue becomes one {field,message},
// with no count cap and no truncation.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
	"github.com/suchimauz/raylane/internal/store"
)

// nodeCreateBodyLimit is the settled contract bound for the POST body (the
// OpenAPI x-body-limit-bytes). It is read exactly ONCE via readBounded.
const nodeCreateBodyLimit = 262144

// wireProtocolEnum is the CLOSED outward protocol enumeration (the accepted
// contracts Protocol enum). An internally legal-but-unselected protocol is
// omitted from the wire, never defaulted and never echoed raw.
var wireProtocolEnum = map[string]bool{"vless": true, "socks5": true, "http": true, "wireguard": true}

// nodeCreateOuterKeys is the closed outer wire key set.
var nodeCreateOuterKeys = map[string]bool{"protocol": true, "fields": true, "label": true, "secrets": true}

// nodeCreateRequiredKeys must all be present (the settled contract requires
// protocol and fields; label and secrets are optional).
var nodeCreateRequiredKeys = []string{"protocol", "fields"}

// --- handlers ---------------------------------------------------------------

// handleNodesCreate routes POST /api/v1/nodes (exact path only).
func (s *Server) handleNodesCreate(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r.Context())
	// The bare "/api/v1/nodes" pattern catches every method on the exact
	// collection path. The collection is create-only: POST is the route, any
	// OTHER method is the generic unregistered-surface refusal (403, no
	// oracle) — a 405 there would advertise the registered path to untrusted
	// callers, which the no-existence-oracle rule forbids.
	if r.Method != http.MethodPost {
		writeProblem(w, http.StatusForbidden, codeForbidden, msgForbidden, requestID)
		return
	}
	if !s.authenticated(r) {
		writeProblem(w, http.StatusUnauthorized, codeInvalidCredentials, msgInvalidCredentials, requestID)
		return
	}
	// After Origin+session, a keyless runtime refuses creates with the static
	// 503: no Retry-After, no body inspection, no DB write, no secret detail.
	if s.node == nil || s.node.writer == nil {
		writeProblem(w, http.StatusServiceUnavailable, codeServiceUnavailable, msgServiceUnavailable, requestID)
		return
	}
	body, err := readBounded(r, nodeCreateBodyLimit)
	if err != nil {
		var over *http.MaxBytesError
		if errors.As(err, &over) {
			writeProblem(w, http.StatusRequestEntityTooLarge, codePayloadTooLarge, msgPayloadTooLarge, requestID)
			return
		}
		// Any other read failure (transport error, premature EOF) is a
		// malformed request, never a size claim.
		writeProblem(w, http.StatusBadRequest, codeBadRequest, msgBadRequest, requestID)
		return
	}
	draft, category, err := parseNodeCreateWire(body)
	if err != nil {
		switch category {
		case wireErrTyped:
			writeProblem(w, http.StatusUnprocessableEntity, codeUnprocessable, msgUnprocessable, requestID)
		default:
			writeProblem(w, http.StatusBadRequest, codeBadRequest, msgBadRequest, requestID)
		}
		return
	}
	out, werr := s.node.writer.CreateNodeAtomic(r.Context(), draft)
	if werr != nil {
		switch {
		case errors.Is(werr, domain.ErrConflict):
			writeProblem(w, http.StatusConflict, codeConflict, msgConflict, requestID)
		case errors.Is(werr, store.ErrSecretOp), errors.Is(werr, store.ErrNodeComponent):
			// Typed component refusal: deterministic, static, zero-write, and
			// NEVER an echo of the rejected input.
			writeProblem(w, http.StatusUnprocessableEntity, codeUnprocessable, msgUnprocessable, requestID)
		case errors.Is(werr, domain.ErrMalformedJSON):
			writeProblem(w, http.StatusBadRequest, codeBadRequest, msgBadRequest, requestID)
		default:
			// Any unexpected store failure is a static 500: no driver cause,
			// no partial node, and never a 422 guess.
			writeProblem(w, http.StatusInternalServerError, codeInternalError, msgInternalError, requestID)
		}
		return
	}
	writeJSON(w, http.StatusCreated, s.nodeDraftJSON(out))
}

// handleNodesGet routes GET /api/v1/nodes/{id} (single node, exact pattern).
func (s *Server) handleNodesGet(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r.Context())
	// Read-only node path: GET answers, every other method is the generic
	// unregistered-surface 403 — the no-existence-oracle rule covers the
	// method dimension too, and it must hold regardless of session or Origin
	// (a 405 would leak registration to anonymous CSRF-gated requests).
	if r.Method != http.MethodGet {
		writeProblem(w, http.StatusForbidden, codeForbidden, msgForbidden, requestID)
		return
	}
	if !s.authenticated(r) {
		writeProblem(w, http.StatusUnauthorized, codeInvalidCredentials, msgInvalidCredentials, requestID)
		return
	}
	// Safe reads need NO key: the reader is always composed. A nil reader can
	// only mean a broken composition, which is a static 500, never a 404.
	if s.node == nil || s.node.reader == nil {
		writeProblem(w, http.StatusInternalServerError, codeInternalError, msgInternalError, requestID)
		return
	}
	id := r.PathValue("id")
	out, err := s.node.reader.ReadNodeSafe(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrNotFound):
			writeProblem(w, http.StatusNotFound, codeNotFound, msgNotFound, requestID)
		default:
			// Binding/safe-read (ErrSafeRead), digest mismatch, corruption and
			// any unexpected failure: static 500, no partial node.
			writeProblem(w, http.StatusInternalServerError, codeInternalError, msgInternalError, requestID)
		}
		return
	}
	writeJSON(w, http.StatusOK, s.nodeDraftJSON(out))
}

// --- explicit outcome -> wire mapping ----------------------------------------

// nodeWire is the NodeDraft read model. Members are built explicitly from the
// store outcome; nothing from NodeOutcome/ProjectedNode is marshaled
// wholesale, so an unknown/ref/purpose/raw/ciphertext field has no path to the
// wire even if the internal types ever grow one.
type nodeWire struct {
	ID         string           `json:"id"`
	Protocol   string           `json:"protocol,omitempty"`
	Label      string           `json:"label,omitempty"`
	Revision   int64            `json:"revision"`
	Validation nodeValidation   `json:"validation"`
	Fields     nodeFieldsWire   `json:"fields"`
	Secrets    map[string]boolP `json:"secrets"`
}

type boolP struct {
	Present bool `json:"present"`
}

type nodeFieldsWire struct {
	Active   map[string]any `json:"active"`
	Inactive map[string]any `json:"inactive"`
	Unknown  map[string]any `json:"unknown"`
}

type nodeValidation struct {
	State           string          `json:"state"`
	Applicable      bool            `json:"applicable"`
	ChainCheck      string          `json:"chainCheck"`
	StructuredCheck string          `json:"structuredCheck"`
	Errors          []nodeIssueWire `json:"errors"`
	Unsupported     []string        `json:"unsupportedNames,omitempty"`
	Warnings        []nodeIssueWire `json:"warnings,omitempty"`
}

type nodeIssueWire struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// nodeDraftJSON maps a store outcome to the NodeDraft wire shape. The label is
// SEALED-ONLY at this increment (no lossless read path exists yet), so it is
// omitted — documented bounded editor gap, never a decrypted fold-in.
func (s *Server) nodeDraftJSON(out store.NodeOutcome) nodeWire {
	w := nodeWire{
		ID:         out.NodeID,
		Revision:   out.Revision,
		Validation: nodeValidationJSON(out.Validation),
		Fields: nodeFieldsWire{
			Active:   copyAnyMap(out.Projection.Active),
			Inactive: copyAnyMap(out.Projection.Inactive),
			Unknown:  map[string]any{},
		},
		Secrets: map[string]boolP{},
	}
	// READ-TIME protocol membership guard: emit protocol ONLY when the
	// already-decoded derived protocol is in the closed wire enum AND still
	// declared by the composed authority. A later-persisted unknown protocol
	// can never leak through a write-time-only guard.
	if out.Protocol != "" && wireProtocolEnum[out.Protocol] &&
		s.node.authority.Profile().HasProtocol(out.Protocol) {
		w.Protocol = out.Protocol
	}
	for name, present := range out.SecretPresence {
		w.Secrets[name] = boolP{Present: present}
	}
	if len(out.Projection.Unsupported) > 0 {
		names := make([]string, len(out.Projection.Unsupported))
		copy(names, out.Projection.Unsupported)
		w.Validation.Unsupported = names
	}
	return w
}

func copyAnyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// nodeValidationJSON renders the FULL historical verdict: the exact status,
// applicability and check tokens, and EVERY ordered issue as its own entry —
// no count cap, no grouping, no truncation, no invented warnings.
func nodeValidationJSON(res nodes.Result) nodeValidation {
	state := "invalid-draft"
	if res.Status == nodes.Valid {
		state = "valid-draft"
	}
	v := nodeValidation{
		State:           state,
		Applicable:      res.Applicable,
		ChainCheck:      res.ChainCheck.String(),
		StructuredCheck: res.StructuredCheck.String(),
		Errors:          make([]nodeIssueWire, 0, len(res.Issues)),
	}
	for _, is := range res.Issues {
		v.Errors = append(v.Errors, nodeIssueWire{Field: is.Field, Message: is.Reason})
	}
	return v
}

// --- strict wire parsing ------------------------------------------------------

// wire category selects the HTTP status for a parse refusal.
const (
	wireErrTransport = iota // 400 invalid_request
	wireErrTyped            // 422 semantic_validation_failed (static, no echo)
)

// parseNodeCreateWire validates the closed outer wire shape and builds the
// trusted NodeCreateInput. The transport-vs-typed split is the settled one:
//   - outer envelope problems (UTF-8, syntax, non-object, unknown/case-fold/
//     duplicate outer keys, wrong-typed protocol/fields envelope members,
//     canonical bucket member count over 256) are transport 400 or typed 422
//     per the decision table below;
//   - INNER content (unknown names, duplicate inner keys, noncanonical
//     escapes, semantic junk) is NEVER refused here — it flows to the writer
//     and saves as a faithful Invalid draft.
func parseNodeCreateWire(body []byte) (store.NodeCreateInput, int, error) {
	members, err := decodeOuterMembers(body, nodeCreateOuterKeys)
	if err != nil {
		// Envelope-level violations — non-object body, malformed syntax (incl.
		// raw control bytes in structural positions), trailing content,
		// duplicate outer keys, unknown top-level members — are transport.
		return store.NodeCreateInput{}, wireErrTransport, err
	}
	var in store.NodeCreateInput
	var protocolVal, fieldsVal, labelVal, secretsVal json.RawMessage
	for _, m := range members {
		switch m.key {
		case "protocol":
			protocolVal = m.value
		case "fields":
			fieldsVal = m.value
		case "label":
			labelVal = m.value
		case "secrets":
			secretsVal = m.value
		}
	}
	for _, req := range nodeCreateRequiredKeys {
		switch req {
		case "protocol":
			if protocolVal == nil {
				return store.NodeCreateInput{}, wireErrTyped, errWireShape
			}
		case "fields":
			if fieldsVal == nil {
				return store.NodeCreateInput{}, wireErrTyped, errWireShape
			}
		}
	}
	// protocol: exactly one JSON string from the closed write enum. A nonstring
	// or nonselected protocol is a typed component refusal (static 422, no
	// echo); the write enum is unchanged from the accepted contract.
	protocol, err := strictRawString(protocolVal)
	if err != nil {
		// The protocol member belongs to the CLOSED TYPED component surface:
		// any violation — a non-string value or scalar-unsafe string content —
		// is the typed category (static 422, no echo).
		return store.NodeCreateInput{}, wireErrTyped, err
	}
	if !wireProtocolEnum[protocol] {
		return store.NodeCreateInput{}, wireErrTyped, errWireShape
	}
	// The store receives a CANONICAL JSON string literal for the protocol —
	// never the raw wire spelling: an escaped/case-mixed lexeme (e.g.
	// "V\u006cess") still denotes a legal enum protocol, and the derived
	// document must persist the decoded protocol, not its raw transport form.
	if cb, err := json.Marshal(protocol); err == nil {
		in.ProtocolBytes = cb
	} else {
		return store.NodeCreateInput{}, wireErrTyped, errWireShape
	}

	// fields: must be exactly one JSON OBJECT with the three canonical bucket
	// members (a typed component refusal when not — the writer's component
	// gate agrees). Each bucket's canonical decoded member COUNT over 256 is
	// the explicit transport capacity limit (422, zero write); duplicates are
	// counted without laundering. The bucket CONTENT is not typed/range
	// validated here at all: the profile validator owns every semantic verdict.
	if len(fieldsVal) == 0 || fieldsVal[0] != '{' {
		return store.NodeCreateInput{}, wireErrTyped, errWireShape
	}
	buckets, err := decodeCanonicalBuckets(fieldsVal)
	if err != nil {
		if errors.Is(err, errWireMalformedObject) && !jsonLikeObject(fieldsVal) {
			return store.NodeCreateInput{}, wireErrTransport, err
		}
		return store.NodeCreateInput{}, wireErrTyped, err
	}
	for _, name := range []string{"active", "inactive", "unknown"} {
		if len(buckets[name]) > 256 {
			return store.NodeCreateInput{}, wireErrTyped, errWireShape
		}
	}
	in.FieldsBytes = append([]byte(nil), fieldsVal...)

	// label (optional): one JSON string, scalar-safe, at most 256 runes. An
	// invalid typed label is the static 422 typed-component category (the
	// writer's own gate remains authoritative and agrees).
	if labelVal != nil {
		label, err := strictRawString(labelVal)
		if err != nil {
			// The label member is likewise a CLOSED TYPED component: every
			// strict-string violation is the typed category (no echo).
			return store.NodeCreateInput{}, wireErrTyped, err
		}
		if utf8.RuneCountInString(label) > 256 {
			return store.NodeCreateInput{}, wireErrTyped, errWireShape
		}
		in.LabelBytes = append([]byte(nil), labelVal...)
	}

	// secrets (optional): the CLOSED typed wire surface. Invalid typed ops or
	// undeclared membership are static 422 refusals with NO echo; membership
	// against the profile is confirmed again authoritatively by the store.
	if secretsVal != nil {
		ops, err := parseWireSecretOps(secretsVal)
		if err != nil {
			// CLASSIFICATION (settled): anything inside a PARSEABLE secrets
			// object is a typed component refusal (case-folded / escaped alias
			// keys, duplicate member keys, unknown enums, scalar-unsafe
			// values). Only a secrets value that is not parseable JSON at all
			// is a transport problem.
			if errors.Is(err, errWireMalformedObject) && !jsonLikeObject(secretsVal) {
				return store.NodeCreateInput{}, wireErrTransport, err
			}
			return store.NodeCreateInput{}, wireErrTyped, err
		}
		in.Secrets = ops
	}
	return in, 0, nil
}

// decodeCanonicalBuckets decodes the fields object ONE level into raw bucket
// values, requiring exactly the three canonical members, each an object.
// Duplicate canonical bucket names are a transport problem of the typed
// component; nested duplicates are NOT scanned (semantic, saved).
func decodeCanonicalBuckets(fieldsVal json.RawMessage) (map[string][]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(fieldsVal))
	tok, err := dec.Token()
	if err != nil {
		return nil, errWireMalformedObject
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errWireMalformedObject
	}
	buckets := map[string][]json.RawMessage{}
	counts := map[string]int{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, errWireMalformedObject
		}
		key, ok := kt.(string)
		if !ok {
			return nil, errWireMalformedObject
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, errWireMalformedObject
		}
		if key != "active" && key != "inactive" && key != "unknown" {
			// An extra canonical-level member is a typed shape refusal.
			return nil, errWireShape
		}
		if _, dup := buckets[key]; dup {
			return nil, errWireShape
		}
		buckets[key] = []json.RawMessage{raw}
	}
	if _, err := dec.Token(); err != nil {
		return nil, errWireMalformedObject
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, errWireMalformedObject // trailing content after the fields object
	}
	for _, name := range []string{"active", "inactive", "unknown"} {
		vals, ok := buckets[name]
		if !ok {
			return nil, errWireShape
		}
		if len(vals[0]) == 0 || vals[0][0] != '{' {
			return nil, errWireShape
		}
		// Count the canonical decoded members (duplicates included, without
		// laundering) with the streaming decoder.
		n, err := countObjectMembers(vals[0])
		if err != nil {
			return nil, errWireShape
		}
		counts[name] = n
	}
	_ = counts
	return buckets, nil
}

// countObjectMembers streams the top-level members of one JSON object and
// returns the count INCLUDING duplicates (the capacity limit counts what was
// sent, and duplicate canonicality stays a semantic matter).
func countObjectMembers(raw json.RawMessage) (int, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return 0, errWireMalformedObject
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return 0, errWireMalformedObject
	}
	n := 0
	for dec.More() {
		if _, err := dec.Token(); err != nil {
			return 0, errWireMalformedObject
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return 0, errWireMalformedObject
		}
		n++
	}
	if _, err := dec.Token(); err != nil {
		return 0, errWireMalformedObject
	}
	return n, nil
}

// parseWireSecretOps decodes the closed secrets map: field names scalar-safe
// strings, each update an object with the closed keys op/value, op from the
// closed enum, replace carrying a scalar-safe string of 1..4096 runes and
// never the exact reserved sentinel, unchanged/clear carrying no value.
// Duplicate field names and duplicate op keys (raw-lexeme identity) are
// refused; the store re-checks membership and sentinels authoritatively.
func parseWireSecretOps(raw json.RawMessage) ([]store.NodeSecretUpdate, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, errWireMalformedObject
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, errWireMalformedObject
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errWireMalformedObject
	}
	seen := map[string]bool{}
	var ops []store.NodeSecretUpdate
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, errWireMalformedObject
		}
		field, ok := kt.(string)
		if !ok || field == "" || !validWireStringContent(jsonKeyLexeme(field)[1:len(jsonKeyLexeme(field))-1]) {
			return nil, errWireMalformedObject
		}
		lex := jsonKeyLexeme(field)
		if seen[lex] {
			return nil, errWireDupKey
		}
		seen[lex] = true
		var upVal json.RawMessage
		if err := dec.Decode(&upVal); err != nil {
			return nil, errWireMalformedObject
		}
		op, hasValue, value, err := parseSecretUpdateWire(upVal)
		if err != nil {
			return nil, err
		}
		ops = append(ops, store.NodeSecretUpdate{Field: field, Op: op, HasValue: hasValue, Value: value})
	}
	if _, err := dec.Token(); err != nil {
		return nil, errWireMalformedObject
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, errWireMalformedObject // trailing content after the secrets object
	}
	return ops, nil
}

// parseSecretUpdateWire decodes one SecretUpdate object strictly.
func parseSecretUpdateWire(upVal json.RawMessage) (op string, hasValue bool, value string, err error) {
	if len(upVal) == 0 || upVal[0] != '{' {
		// A parseable non-object update value is a typed shape refusal.
		return "", false, "", errWireShape
	}
	dec := json.NewDecoder(bytes.NewReader(upVal))
	tok, err := dec.Token()
	if err != nil {
		return "", false, "", errWireMalformedObject
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return "", false, "", errWireMalformedObject
	}
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return "", false, "", errWireMalformedObject
		}
		key, ok := kt.(string)
		if !ok {
			return "", false, "", errWireShape // parseable non-string key: typed
		}
		lex := jsonKeyLexeme(key)
		if seen[lex] {
			return "", false, "", errWireDupKey
		}
		if key != "op" && key != "value" {
			return "", false, "", errWireTypedComponent
		}
		seen[lex] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return "", false, "", errWireMalformedObject
		}
		s, err := strictRawString(v)
		if err != nil {
			if errors.Is(err, errWireShape) {
				return "", false, "", errWireTypedComponent
			}
			return "", false, "", err
		}
		if key == "op" {
			op = s
		} else {
			hasValue = true
			value = s
		}
	}
	if _, err := dec.Token(); err != nil {
		return "", false, "", errWireMalformedObject
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return "", false, "", errWireMalformedObject // trailing content
	}
	switch op {
	case "unchanged", "clear":
		if hasValue {
			return "", false, "", errWireShape
		}
		return op, false, "", nil
	case "replace":
		if !hasValue || value == "" {
			return "", false, "", errWireShape
		}
		if value == store.ReservedSecretSentinelValue {
			return "", false, "", errWireShape
		}
		if n := utf8.RuneCountInString(value); n < 1 || n > 4096 {
			return "", false, "", errWireShape
		}
		return op, true, value, nil
	default:
		return "", false, "", errWireShape
	}
}

// errWireMalformedObject marks a nested wire member that is not a parseable
// JSON object at all — a transport (400) problem per the settled split.
var errWireMalformedObject = errors.New("authhttp: malformed nested wire object")

// jsonLikeObject reports whether val parses as a JSON object via the strict
// streaming decoder (used ONLY to route the transport-vs-typed category).
func jsonLikeObject(val json.RawMessage) bool {
	if len(val) == 0 || val[0] != '{' {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(val))
	if _, err := dec.Token(); err != nil {
		return false
	}
	for dec.More() {
		if _, err := dec.Token(); err != nil {
			return false
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return false
		}
	}
	if _, err := dec.Token(); err != nil {
		return false
	}
	// The object must fully consume its bytes: trailing content is junk.
	dec2 := json.NewDecoder(bytes.NewReader(val))
	if err := dec2.Decode(new(json.RawMessage)); err != nil {
		return false
	}
	return dec2.Decode(new(json.RawMessage)) == io.EOF
}

// isNonStringJSONValue reports a wire value that is not even a JSON string
// literal (number, bool, null, array, object) — an envelope-member transport
// violation, distinct from a string with scalar-unsafe CONTENT (typed).
func isNonStringJSONValue(val json.RawMessage) bool {
	return len(val) == 0 || val[0] != '"'
}
