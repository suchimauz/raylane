// Package jsonscan is the dependency-neutral structural JSON scanner shared by
// the capability profile parser and the node envelope adapter. It owns exactly
// two rules and no product knowledge: every JSON object must have unique keys
// at every nesting level, and a document must be exactly one complete value.
// It reports structural verdicts only — key and value bytes are never
// retained, returned or echoed — so each boundary maps a verdict to its own
// static sentinel without leaking input content. Its only import is the
// standard library, which lets any boundary reuse it without importing
// another boundary or growing a dependency cycle.
package jsonscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// ErrDuplicateKey reports that some object in the document repeats a key. The
// error carries no key or value content; callers wrap it into their own typed
// condition.
var ErrDuplicateKey = errors.New("jsonscan: duplicate json object key")

// ErrMalformed reports that the bytes are not exactly one well-formed JSON
// value (unterminated, wrong tokens, or trailing content after the first
// value). It carries no input bytes.
var ErrMalformed = errors.New("jsonscan: malformed json")

// UniqueKeys walks raw with encoding/json's token stream and returns
// ErrDuplicateKey when any object level repeats a key (escaped spellings of
// the same key compare equal because tokens are unescaped), or ErrMalformed if
// the stream is not walkable. Memory stays bounded by one object level's key
// set; nothing is buffered or echoed.
//
// The decoder runs with UseNumber: the scanner is structure-only and never
// converts a number to float64, so a syntactically valid number that exceeds
// float64 range (e.g. 1E400) is walked as an opaque token rather than
// mislabeled malformed.
func UniqueKeys(raw []byte) error {
	dec := newScanner(raw)
	return scanValue(dec)
}

// FullValue walks raw and additionally requires that NOTHING follows the first
// complete JSON value: trailing content is ErrMalformed. Combined with a
// caller's own structural checks it closes the "input fully consumed" gate.
//
// The consumption probe is an ACTUAL EOF read, not dec.More(): More() only
// reports whether the next token COULD START a value, so a trailing closer
// (} or ]) is invisible to it. Only a real token read that returns io.EOF
// proves the input ended exactly after the first value; any token or any
// syntax error after it is trailing content.
func FullValue(raw []byte) error {
	dec := newScanner(raw)
	if err := scanValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrMalformed
	}
	return nil
}

// newScanner returns the shared structural decoder: UseNumber keeps the walk
// numeric-agnostic (structure only, no float conversion), so big valid
// numbers never trip the scanner.
func newScanner(raw []byte) *json.Decoder {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec
}

// scanValue walks the value at the decoder's current position: objects check
// their own key set for repeats and recurse into values; arrays recurse into
// elements; scalars pass.
func scanValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return ErrMalformed
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar at this position
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return ErrMalformed
			}
			key, ok := kt.(string)
			if !ok {
				return ErrMalformed
			}
			if seen[key] {
				return ErrDuplicateKey
			}
			seen[key] = true
			if err := scanValue(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume '}'
			return ErrMalformed
		}
	case '[':
		for dec.More() {
			if err := scanValue(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume ']'
			return ErrMalformed
		}
	}
	return nil
}
