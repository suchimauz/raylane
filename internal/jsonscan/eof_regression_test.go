package jsonscan

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// TestFullValueRejectsTrailingClosers is the QA3-A1 regression for the shared
// scanner's full-consumption contract. dec.More() only reports whether the next
// token COULD START a value, so a trailing closer (} or ]) slipped through.
// The scanner must reject ANY bytes after the first complete value except
// whitespace: closers, extra values, garbage. Only an actual EOF read proves
// the input ended exactly after the first value.
func TestFullValueRejectsTrailingClosers(t *testing.T) {
	cases := []string{
		`{"a":1} }`,
		`{"a":1} ]`,
		`{"a":1} }}`,
		`{"a":1} ]}`,
		`{"a":1} {}`,
		`{"a":1} 5`,
		`[1] ]`,
		`[1] }`,
		`{"a":1} x`,
		`{"a":1} ,`,
	}
	for _, s := range cases {
		if err := FullValue([]byte(s)); !errors.Is(err, ErrMalformed) {
			t.Errorf("FullValue(%q) = %v, want ErrMalformed (trailing content after first value)", s, err)
		}
	}
}

// TestFullValueAcceptsSingleValueAndWhitespace: exactly one complete value,
// optionally followed by whitespace, is success — the EOF probe must not
// reject ordinary valid documents. Big valid numbers still pass (structure
// only, no float conversion).
func TestFullValueAcceptsSingleValueAndWhitespace(t *testing.T) {
	ok := []string{
		`{"a":1}`,
		`{"a":1} `,
		"\t{\"a\":1}\n ",
		`[1,2,3]`,
		`1E400`,
		`{"a":1E400}`,
		`"x"`,
		`5`,
		`null`,
		`true`,
	}
	for _, s := range ok {
		if err := FullValue([]byte(s)); err != nil {
			t.Errorf("FullValue(%q) = %v, want nil (exactly one value)", s, err)
		}
	}
}

// TestFullValueDuplicatePrecedencePreserved: a structural duplicate key is
// still ErrDuplicateKey even when trailing content follows — duplicate
// detection runs inside scanValue before any EOF classification.
func TestFullValueDuplicatePrecedencePreserved(t *testing.T) {
	for _, s := range []string{
		`{"a":1,"a":2} }`,
		`{"a":1,"a":2} 5`,
		`{"a":1,"a":2} trailing`,
	} {
		if err := FullValue([]byte(s)); !errors.Is(err, ErrDuplicateKey) {
			t.Errorf("FullValue(%q) = %v, want ErrDuplicateKey (precedence over trailing)", s, err)
		}
	}
}

// TestFullValueEOFErrorCarriesNoInputBytes: the malformed sentinel stays
// static and value-free even when the trailing content is attacker-controlled.
func TestFullValueEOFErrorCarriesNoInputBytes(t *testing.T) {
	canary := "CANARY-EOF-7q"
	err := FullValue([]byte(`{"a":1} ` + canary))
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
	if err != nil && strings.Contains(err.Error(), canary) {
		t.Fatalf("error echoed input bytes: %v", err)
	}
	// io.EOF itself is never leaked to the caller as the verdict.
	if errors.Is(err, io.EOF) {
		t.Fatalf("io.EOF must be mapped to ErrMalformed, not leaked")
	}
}
