package authhttp

// Strict wire decoding for the node create/read surface (T012). These helpers
// decode the CLOSED outer wire shape exactly: case-sensitive exact key names,
// duplicate outer keys (including escaped aliases of the same name) refused,
// raw UTF-8 checked on the WIRE (never the lossy U+FFFD replacement), numbers
// preserved as exact lexemes (json.RawMessage — never float64), and no
// reserialization of captured component bytes. The INNER field content is
// deliberately NOT recursively scanned here: inner duplicate keys are a
// SEMANTIC invalid draft the accepted writer SAVES, not a transport refusal.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// outerMember is one decoded top-level wire member: the decoded key, the exact
// raw key lexeme (for alias-duplicate detection), and the exact raw value
// slice (no float64, no reserialization).
type outerMember struct {
	key       string
	keyLexeme string
	value     json.RawMessage
}

// errWireDupKey is the internal refusal for a duplicate JSON object key at
// the closed wire surface; the HTTP layer maps it to the transport category.
var errWireDupKey = errors.New("authhttp: duplicate wire key")

// errWireShape is the internal static refusal for any outer-shape violation;
// the handler maps it to the 400 invalid_request category and never echoes it.
var errWireShape = errors.New("authhttp: strict wire shape refusal")

// decodeOuterMembers decodes the top-level JSON OBJECT of a request body with
// the settled strictness, returning its members in wire order. Refusals:
// invalid wire UTF-8, a non-object or empty top level, malformed/trailing
// JSON, a control-character-laden or non-string key, an unknown key under the
// caller-supplied closed key set, and a duplicate key — where a duplicate is
// the same decoded name OR the same raw key lexeme (so "a\u0042" aliases "aB"
// and must not bypass the duplicate rule).
func decodeOuterMembers(body []byte, closedKeys map[string]bool) ([]outerMember, error) {
	// Raw-UTF8 wire gate FIRST: encoding/json accepts raw invalid bytes and
	// silently replaces them, so the original bytes must be valid UTF-8 for
	// what the caller decoded to be what the client sent.
	if !utf8.Valid(body) {
		return nil, errWireShape
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errWireShape
	}
	s := string(trimmed)
	pos := 1 // past '{'
	var members []outerMember
	seenLexemes := map[string]bool{}
	seenDecoded := map[string]bool{}
	for {
		pos = skipJSONSpace(s, pos)
		if pos >= len(s) {
			return nil, errWireMalformedObject
		}
		if s[pos] == '}' {
			pos++
			break
		}
		if len(members) > 0 {
			if s[pos] != ',' {
				return nil, errWireMalformedObject
			}
			pos++
			pos = skipJSONSpace(s, pos)
		}
		if pos >= len(s) || s[pos] != '"' {
			return nil, errWireMalformedObject
		}
		keyStart := pos
		var keyCtl bool
		key, next, ok := scanJSONString(s, pos, &keyCtl)
		if !ok {
			return nil, errWireMalformedObject
		}
		if keyCtl {
			// Raw control byte inside the envelope KEY literal: transport.
			return nil, errWireShape
		}
		pos = skipJSONSpace(s, next)
		if pos >= len(s) || s[pos] != ':' {
			return nil, errWireMalformedObject
		}
		pos = skipJSONSpace(s, pos+1)
		var valCtl bool
		_, valEnd, ok := scanJSONValueCtl(s, pos, &valCtl)
		if !ok {
			return nil, errWireMalformedObject
		}
		if valCtl {
			// Raw control byte inside a member VALUE literal: the settled
			// typed scalar rule refuses scalar-unsafe values statically.
			return nil, errWireTypedComponent
		}
		lex := s[keyStart:next]
		// Duplicate detection uses BOTH the raw lexeme (catches same-spelling
		// and escaped-vs-plain pairs the raw scan cannot unify otherwise) and
		// the DECODED key (catches "protoco\u006c" vs "protocol").
		if seenLexemes[lex] || seenDecoded[key] {
			// Duplicate OUTER envelope member (raw or escaped spelling): the
			// transport category of the closed envelope rule.
			return nil, errWireDupKey
		}
		seenLexemes[lex] = true
		seenDecoded[key] = true
		if !closedKeys[key] {
			// Unknown top-level member: a shape violation of the closed
			// envelope contract — the caller maps it to transport (no echo).
			return nil, errWireUnknownMember
		}
		members = append(members, outerMember{key: key, keyLexeme: lex, value: json.RawMessage(s[pos:valEnd])})
		pos = skipJSONSpace(s, valEnd)
	}
	if skipJSONSpace(s, pos) != len(s) {
		return nil, errWireMalformedObject // trailing content after the object
	}
	return members, nil
}

// errWireUnknownMember marks a well-formed envelope member the closed schema
// does not define (unknown top-level key) — the caller maps it to transport.
var errWireUnknownMember = errors.New("authhttp: unknown closed-surface member")

// skipJSONSpace returns the first index at or after i that is not JSON
// whitespace, or len(s).
func skipJSONSpace(s string, i int) int {
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

// scanJSONString scans one JSON string literal starting at s[i] == '"',
// returning the DECODED value, the index past the closing quote, and ok.
// rawControl (when non-nil) reports a raw C0 control byte inside the literal:
// an RFC 8259 violation whose CATEGORY belongs to the caller — an envelope
// KEY control byte is transport, a member VALUE control byte is the settled
// typed scalar-unsafe refusal.
func scanJSONString(s string, i int, rawControl *bool) (string, int, bool) {
	if i >= len(s) || s[i] != '"' {
		return "", 0, false
	}
	var b []byte
	i++
	for i < len(s) {
		c := s[i]
		switch {
		case c == '"':
			return string(b), i + 1, true
		case c == '\\':
			if i+1 >= len(s) {
				return "", 0, false
			}
			e := s[i+1]
			switch e {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				b = append(b, e2e(c, e))
				i += 2
			case 'u':
				if i+5 >= len(s) {
					return "", 0, false
				}
				r, ok := runeAt(s[i+2 : i+6])
				if !ok {
					return "", 0, false
				}
				b = utf8.AppendRune(b, r)
				i += 6
			default:
				return "", 0, false
			}
		case c < 0x20:
			// RFC 8259 violation: recorded for the caller's classification.
			if rawControl != nil {
				*rawControl = true
			}
			b = append(b, c)
			i++
		default:
			b = append(b, c)
			i++
		}
	}
	return "", 0, false
}

func e2e(quote, esc byte) byte {
	switch esc {
	case 'b':
		return '\b'
	case 'f':
		return '\f'
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	default:
		return esc
	}
}

func runeAt(hex4 string) (rune, bool) {
	var r rune
	for i := 0; i < 4; i++ {
		c := hex4[i]
		switch {
		case c >= '0' && c <= '9':
			r = r*16 + rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r*16 + rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r*16 + rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// scanJSONValue returns the end index (exclusive) of one complete JSON value
// starting at s[i], validating its syntax. The caller slices the RAW bytes.
func scanJSONValue(s string, i int) (int, int, bool) {
	return scanJSONValueCtl(s, i, nil)
}

// scanJSONValueCtl scans one complete JSON value, recording whether ANY string
// literal inside it carries a raw C0 control byte.
func scanJSONValueCtl(s string, i int, rawControl *bool) (int, int, bool) {
	if i >= len(s) {
		return 0, 0, false
	}
	switch c := s[i]; {
	case c == '{' || c == '[':
		closer := byte('}')
		if c == '[' {
			closer = ']'
		}
		depth := 0
		for i < len(s) {
			switch s[i] {
			case '{', '[':
				depth++
			case '}', ']':
				if s[i] != closer {
					return 0, 0, false // mismatched closer: malformed
				}
				depth--
				if depth == 0 {
					return i, i + 1, true
				}
			case '"':
				_, next, ok := scanJSONString(s, i, rawControl)
				if !ok {
					return 0, 0, false
				}
				i = next - 1
			}
			i++
		}
		return 0, 0, false
	case c == '"':
		_, next, ok := scanJSONString(s, i, rawControl)
		if !ok {
			return 0, 0, false
		}
		return i, next, ok
	case c == 't' || c == 'f' || c == 'n':
		for _, lit := range []string{"true", "false", "null"} {
			if strings.HasPrefix(s[i:], lit) {
				return i, i + len(lit), true
			}
		}
		return 0, 0, false
	default:
		start := i
		if s[i] == '-' {
			i++
		}
		digits := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
			digits++
		}
		if digits == 0 {
			return 0, 0, false
		}
		if i < len(s) && s[i] == '.' {
			i++
			digits = 0
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++
				digits++
			}
			if digits == 0 {
				return 0, 0, false
			}
		}
		if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
			i++
			if i < len(s) && (s[i] == '+' || s[i] == '-') {
				i++
			}
			digits = 0
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++
				digits++
			}
			if digits == 0 {
				return 0, 0, false
			}
		}
		return start, i, true
	}
}

func jsonKeyLexeme(s string) string {
	var b []byte
	b = append(b, '"')
	for _, r := range s {
		switch r {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\b':
			b = append(b, '\\', 'b')
		case '\f':
			b = append(b, '\\', 'f')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			if r < 0x20 {
				b = append(b, fmt.Sprintf("\\u%04x", r)...)
			} else {
				b = appendRune(b, r)
			}
		}
	}
	b = append(b, '"')
	return string(b)
}

func appendRune(b []byte, r rune) []byte {
	var tmp [utf8.UTFMax]byte
	n := utf8.EncodeRune(tmp[:], r)
	return append(b, tmp[:n]...)
}

// errWireTypedComponent marks a TYPED-component string refusal (422): the
// envelope is well-formed transport-wise, but a typed string VALUE carries
// scalar-unsafe content (raw C0 control, unpaired surrogate escape) that the
// settled rule refuses statically without echoing.
var errWireTypedComponent = errors.New("authhttp: typed wire component scalar refusal")

// strictRawString decodes a wire value that must be exactly one JSON STRING,
// classifying violations for the closed typed surface:
//   - non-string value                       -> errWireShape (transport)
//   - raw C0 control byte inside the literal -> errWireTypedComponent
//     (the settled typed-scalar rule: a scalar-unsafe value, static, no echo)
//   - a lossy \uXXXX escape (control/surrogate) -> errWireTypedComponent: the
//     decoded scalar is unsafe and the store-side check is byte-form based, so
//     it would not refuse it there; refusing here preserves save-or-refuse.
//   - any other undecodable literal          -> errWireShape (transport)
func strictRawString(val json.RawMessage) (string, error) {
	if len(val) == 0 || val[0] != '"' {
		return "", errWireShape
	}
	inner := string(val[1 : len(val)-1])
	if hasLossyEscape(inner) {
		return "", errWireTypedComponent
	}
	var s string
	if err := json.Unmarshal(val, &s); err != nil {
		return "", errWireShape
	}
	return s, nil
}

// hasLossyEscape reports a \uXXXX escape whose decoded value is NOT a valid
// Unicode scalar on its own — a C0 control (incl. \u0000) or a lone surrogate
// escape. Such a value is decoded scalar-unsafe and must be a static typed
// refusal for the closed typed members (label/protocol/secrets values).
// A legal high+low surrogate PAIR is fine; the pairing itself is enforced by
// the store's own content scan for the label.
func hasLossyEscape(inner string) bool {
	for i := 0; i < len(inner); i++ {
		if inner[i] != '\\' {
			continue
		}
		i++
		if i >= len(inner) {
			return false
		}
		if inner[i] != 'u' {
			continue
		}
		if i+5 > len(inner) {
			return false
		}
		v, ok := hexQuad4(inner[i+1 : i+5])
		if !ok {
			return false
		}
		if v <= 0x001F || (v >= 0xD800 && v <= 0xDFFF) {
			// A surrogate is only unsafe when UNPAIRED; a following \uDCXX low
			// half makes it a legal pair.
			if v >= 0xD800 && v <= 0xDBFF && i+11 <= len(inner) &&
				inner[i+5] == '\\' && inner[i+6] == 'u' {
				if lv, lok := hexQuad4(inner[i+7 : i+11]); lok && lv >= 0xDC00 && lv <= 0xDFFF {
					i += 11
					continue
				}
			}
			return true
		}
		i += 5
	}
	return false
}

func hasRawControlByte(inner string) bool {
	for i := 0; i < len(inner); i++ {
		if inner[i] == '\\' {
			i++ // skip the escaped pair
			continue
		}
		if inner[i] < 0x20 {
			return true
		}
	}
	return false
}

// validWireStringContent scans the RAW inner bytes of a JSON string literal
// for scalar integrity: raw C0 controls and raw invalid UTF-8 are refused,
// and every \uXXXX escape must be well-formed with correct high+low surrogate
// pairing. Legal surrogate PAIRS, escaped or literal U+FFFD and ordinary
// escapes pass. This is the same integrity rule the typed store components
// already enforce; it is wired here for the outer typed values.
func validWireStringContent(inner string) bool {
	for i := 0; i < len(inner); {
		c := inner[i]
		if c == '\\' {
			if i+1 >= len(inner) {
				return false
			}
			e := inner[i+1]
			switch e {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i += 2
			case 'u':
				if len(inner) < i+6 {
					return false
				}
				q1, ok1 := hexQuad(inner[i+2 : i+6])
				if !ok1 {
					return false
				}
				i += 6
				if q1 >= 0xD800 && q1 <= 0xDFFF {
					if q1 > 0xDBFF { // must be a HIGH surrogate
						return false
					}
					if len(inner) < i+6 || inner[i] != '\\' || inner[i+1] != 'u' {
						return false
					}
					q2, ok2 := hexQuad(inner[i+2 : i+6])
					if !ok2 || q2 < 0xDC00 || q2 > 0xDFFF { // must be a LOW surrogate
						return false
					}
					i += 6
				}
			default:
				return false
			}
			continue
		}
		if c < 0x20 {
			return false
		}
		r, size := utf8.DecodeRuneInString(inner[i:])
		if r == utf8.RuneError && size <= 1 {
			return false
		}
		i += size
	}
	return true
}

// hexQuad parses exactly four hex digits.
func hexQuad(q string) (int, bool) {
	if len(q) != 4 {
		return 0, false
	}
	v := 0
	for i := 0; i < 4; i++ {
		c := q[i]
		switch {
		case c >= '0' && c <= '9':
			v = v*16 + int(c-'0')
		case c >= 'a' && c <= 'f':
			v = v*16 + int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = v*16 + int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

// hexQuad4 parses exactly four hex digits (no length check needed at call
// sites that already sliced four bytes).
func hexQuad4(q string) (int, bool) {
	if len(q) != 4 {
		return 0, false
	}
	return hexQuad(q)
}
