package domain

import (
	"errors"
	"testing"
)

func TestParseDocumentSyntaxGate(t *testing.T) {
	for _, bad := range []string{"", "{", `{"a":`, `{"a": }`, "not json"} {
		if _, err := ParseDocument([]byte(bad)); !errors.Is(err, ErrMalformedJSON) {
			t.Errorf("ParseDocument(%q) err = %v, want ErrMalformedJSON", bad, err)
		}
	}
	for _, good := range []string{`{}`, `{"a":[1,2]}`, " \n{\"x\":1}\t"} {
		doc, err := ParseDocument([]byte(good))
		if err != nil {
			t.Errorf("ParseDocument(%q) = %v", good, err)
			continue
		}
		if doc.Validation != ValidationNotRun {
			t.Errorf("ParseDocument(%q) validation = %v, want NotRun (no implied PASS)", good, doc.Validation)
		}
	}
}

func TestValidationStatusNotRunIsNotPass(t *testing.T) {
	if ValidationNotRun == ValidationValid {
		t.Fatal("NotRun must be distinct from Valid")
	}
	if ValidationNotRun.String() != "not_run" || ValidationValid.String() != "valid" || ValidationInvalid.String() != "invalid" {
		t.Fatal("unexpected status rendering")
	}
}

func TestParseDocumentCopiesBytes(t *testing.T) {
	raw := []byte(`{"a":1}`)
	doc, err := ParseDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[2] = '9'
	if string(doc.Raw) != `{"a":1}` {
		t.Fatalf("document must not alias caller bytes, got %s", doc.Raw)
	}
}
