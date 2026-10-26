package capability

import (
	"encoding/json"
	"sort"
)

// sortStrings sorts in place for deterministic enumeration.
func sortStrings(s []string) { sort.Strings(s) }

// checkValue validates one decoded JSON value against a field spec and returns
// the normalized value on success. It is the shared value gate used both for
// authored defaults (at parse time) and for node field validation. Rules match
// the T007 projection's safeCopy semantics, extended so validation can report
// WHICH constraint failed rather than only refusing the value.
//
// Returns (normalized, true) when valid; (nil, false) when invalid. Never
// mutates the input; arrays are copied.
func checkValue(val any, fi fieldInternal) (any, bool) {
	f := fi.Field
	switch f.Type {
	case "string":
		s, ok := val.(string)
		if !ok {
			return nil, false
		}
		if f.HasMinLength && len(s) < f.MinLength {
			return nil, false
		}
		if f.HasMaxLength && len(s) > f.MaxLength {
			return nil, false
		}
		if fi.patternRe != nil && !fi.patternRe.MatchString(s) {
			return nil, false
		}
		return s, true
	case "integer":
		n, ok := jsonNumber(val)
		if !ok {
			return nil, false
		}
		if f.HasMinimum && n < f.Minimum {
			return nil, false
		}
		if f.HasMaximum && n > f.Maximum {
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
		for _, a := range f.AllowedValues {
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
		if f.HasMaxItems && len(arr) > f.MaxItems {
			return nil, false
		}
		if f.HasMinItems && len(arr) < f.MinItems {
			return nil, false
		}
		item := fieldInternal{Field: Field{Type: f.ItemType, Classification: "known"}}
		out := make([]any, 0, len(arr))
		for _, el := range arr {
			if _, isObj := el.(map[string]any); isObj {
				return nil, false // nested object cannot bypass the leaf rules
			}
			nv, ok := checkValue(el, item)
			if !ok {
				return nil, false
			}
			out = append(out, nv)
		}
		return out, true
	}
	return nil, false
}

// jsonNumber accepts only integral JSON numbers. When the caller decoded with
// encoding/json, numbers arrive as float64; a non-integer or out-of-int64
// value is refused rather than approximated. json.Number (UseNumber) is
// accepted when integral.
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
