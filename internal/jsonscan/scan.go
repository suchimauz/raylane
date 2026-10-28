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
	"unicode/utf8"
)

// ErrDuplicateKey reports that some object in the document repeats a key. The
// error carries no key or value content; callers wrap it into their own typed
// condition.
var ErrDuplicateKey = errors.New("jsonscan: duplicate json object key")

// ErrMalformed reports that the bytes are not exactly one well-formed JSON
// value (unterminated, wrong tokens, or trailing content after the first
// value). It carries no input bytes.
var ErrMalformed = errors.New("jsonscan: malformed json")

// ErrNonScalar reports that a JSON string token — at any nesting depth, as a
// value or an object key — carries non-scalar content: invalid raw UTF-8, an
// unpaired / wrongly-ordered UTF-16 surrogate escape, an ill-formed \uXXXX
// escape, or a raw unescaped control byte. It carries no content; callers map
// it to their own static sentinel. This is SEPARATE from (and additional to)
// the structural rules above: a document can be structurally unique-keyed and
// exactly-one-value yet still carry non-scalar string bytes.
var ErrNonScalar = errors.New("jsonscan: non-scalar content in a json string")

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

// StringScalar walks the RAW JSON bytes and returns ErrNonScalar when ANY
// JSON string token — a value or an object key at any nesting depth — carries
// non-scalar content: invalid raw UTF-8, an unpaired / wrongly-ordered UTF-16
// surrogate escape, an ill-formed \uXXXX escape, or a raw unescaped control
// byte. It returns ErrMalformed for structurally un-walkable bytes.
//
// This is a RAW lexical byte scan, NOT the encoding/json token stream: the
// decoder lossily maps an invalid \uXXXX escape (e.g. a lone surrogate) to
// U+FFFD even in raw Token() mode, so a decoded token string cannot reveal
// that the source was malformed. Scanning the wire bytes directly preserves
// the escape spelling. Structural rules (unique keys, exactly-one-value) are
// NOT re-checked here; callers that need them still call UniqueKeys/FullValue
// separately. Nothing is buffered or echoed.
//
// A legal literal U+FFFD, an escaped \ufffd, a valid high+low surrogate PAIR,
// ordinary escapes, and an escaped backslash (\\) are all scalar / accepted.
func StringScalar(raw []byte) error {
	i := 0
	if err := scanRawValue(raw, &i); err != nil {
		return err
	}
	skipWS(raw, &i)
	if i != len(raw) {
		return ErrMalformed // trailing content
	}
	return nil
}

// scanRawValue scans a single JSON value starting at raw[i] — object, array,
// string, number, or true/false/null — validating any string content, and
// advances i past the value.
func scanRawValue(raw []byte, i *int) error {
	skipWS(raw, i)
	if *i >= len(raw) {
		return ErrMalformed
	}
	switch c := raw[*i]; {
	case c == '{':
		*i++
		skipWS(raw, i)
		if *i < len(raw) && raw[*i] == '}' {
			*i++
			return nil
		}
		for {
			skipWS(raw, i)
			if *i >= len(raw) || raw[*i] != '"' {
				return ErrMalformed
			}
			if err := scanRawString(raw, i); err != nil {
				return err
			}
			skipWS(raw, i)
			if *i >= len(raw) || raw[*i] != ':' {
				return ErrMalformed
			}
			*i++
			if err := scanRawValue(raw, i); err != nil {
				return err
			}
			skipWS(raw, i)
			if *i >= len(raw) {
				return ErrMalformed
			}
			switch raw[*i] {
			case ',':
				*i++
				continue
			case '}':
				*i++
				return nil
			default:
				return ErrMalformed
			}
		}
	case c == '[':
		*i++
		skipWS(raw, i)
		if *i < len(raw) && raw[*i] == ']' {
			*i++
			return nil
		}
		for {
			if err := scanRawValue(raw, i); err != nil {
				return err
			}
			skipWS(raw, i)
			if *i >= len(raw) {
				return ErrMalformed
			}
			switch raw[*i] {
			case ',':
				*i++
				continue
			case ']':
				*i++
				return nil
			default:
				return ErrMalformed
			}
		}
	case c == '"':
		return scanRawString(raw, i)
	case c == '-' || (c >= '0' && c <= '9'):
		// number: consume a bare numeric token
		for *i < len(raw) && !isWS(raw[*i]) && raw[*i] != ',' && raw[*i] != '}' && raw[*i] != ']' {
			*i++
		}
		return nil
	case c == 't': // true
		if *i+4 <= len(raw) && string(raw[*i:*i+4]) == "true" {
			*i += 4
			return nil
		}
		return ErrMalformed
	case c == 'f': // false
		if *i+5 <= len(raw) && string(raw[*i:*i+5]) == "false" {
			*i += 5
			return nil
		}
		return ErrMalformed
	case c == 'n': // null
		if *i+4 <= len(raw) && string(raw[*i:*i+4]) == "null" {
			*i += 4
			return nil
		}
		return ErrMalformed
	default:
		return ErrMalformed
	}
}

// scanRawString scans a JSON string token starting at raw[i]=='"', validates
// its inner content for scalar integrity, and advances i past the closing
// '"'.
func scanRawString(raw []byte, i *int) error {
	start := *i
	j := *i + 1
	n := len(raw)
	for j < n {
		switch raw[j] {
		case '"':
			if !stringScalar(string(raw[start+1 : j])) {
				return ErrNonScalar
			}
			*i = j + 1
			return nil
		case '\\':
			j += 2 // skip the escape's second char (stringScalar validates the form)
		default:
			j++
		}
	}
	return ErrMalformed // unterminated
}

func skipWS(raw []byte, i *int) {
	for *i < len(raw) && isWS(raw[*i]) {
		*i++
	}
}

func isWS(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// stringScalar reports whether s — a JSON string token's raw bytes — is scalar:
// every `\` introduces a recognized two-char escape (" \ / b f n r t) or a
// well-formed \uXXXX escape, every UTF-16 surrogate escape is part of a valid
// high+low pair, no raw control byte appears unescaped, and the content is
// valid UTF-8. U+FFFD (literal or escaped) and a valid surrogate pair are
// scalar and accepted; an escaped backslash (\\) is not a surrogate escape.
func stringScalar(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		if c < 0x20 {
			return false // raw control byte must be escaped
		}
		if c == '\\' {
			i++
			if i >= n {
				return false // trailing backslash
			}
			e := s[i]
			switch e {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i++
			case 'u':
				if i+5 > n {
					return false // \\u needs exactly 4 hex digits after 'u'
				}
				v, hok := hexQuad(s[i+1 : i+5]) // s[i]=='u'; digits are s[i+1..i+4]
				if !hok {
					return false
				}
				if v >= 0xD800 && v <= 0xDBFF { // high surrogate: needs a low half
					// A following low escape \\uXXXX occupies s[i+5..i+10]; the last
					// index consumed is i+10, which must be within s (i+10 <= n-1).
					if i+10 >= n || s[i+5] != '\\' || s[i+6] != 'u' {
						return false // unpaired high surrogate
					}
					lv, lok := hexQuad(s[i+7 : i+11]) // low digits s[i+7..i+10]
					if !lok || lv < 0xDC00 || lv > 0xDFFF {
						return false // high not followed by a low surrogate
					}
					i += 10 // consume both \\uXXXX escapes (i was at 'u' of high)
					continue
				}
				if v >= 0xDC00 && v <= 0xDFFF {
					return false // low surrogate without a preceding high
				}
				i += 5 // consume \\uXXXX (i was at 'u'; +1 backslash +4 digits)
			default:
				return false // unrecognized escape
			}
			continue
		}
		i++
	}
	return true
}

// hexQuad parses exactly four hex digits into a value; hok=false on a non-hex
// digit. Each digit is folded into the low nibble of v (shift-then-or), so all
// four nibbles are preserved.
func hexQuad(q string) (v int, hok bool) {
	if len(q) != 4 {
		return 0, false
	}
	for i := 0; i < 4; i++ {
		d := q[i]
		var nib int
		switch {
		case d >= '0' && d <= '9':
			nib = int(d - '0')
		case d >= 'a' && d <= 'f':
			nib = int(d-'a') + 10
		case d >= 'A' && d <= 'F':
			nib = int(d-'A') + 10
		default:
			return 0, false
		}
		v = v<<4 | nib
	}
	return v, true
}
