package jsonscan

import (
	"errors"
	"strings"
	"testing"
)

func TestUniqueKeys(t *testing.T) {
	ok := []string{
		`{}`, `[]`, `1`, `"x"`, `null`, `true`,
		`{"a":1,"b":{"a":2}}`, // same key at DIFFERENT levels is fine
		`{"a":[1,2,{"b":3}]}`, // arrays unique per element object
		`{"\u0061":1,"b":2}`,  // escaped single key
	}
	for _, s := range ok {
		if err := UniqueKeys([]byte(s)); err != nil {
			t.Errorf("UniqueKeys(%q) = %v, want nil", s, err)
		}
	}
	dup := []string{
		`{"a":1,"a":2}`,
		`{"a":1,"b":{"a":2,"a":3}}`,
		`{"a":[1,{"x":1,"x":2}]}`,
		`{"\u0061":1,"a":2}`, // escaped spelling collides with the plain key
	}
	for _, s := range dup {
		if err := UniqueKeys([]byte(s)); !errors.Is(err, ErrDuplicateKey) {
			t.Errorf("UniqueKeys(%q) = %v, want ErrDuplicateKey", s, err)
		}
	}
	bad := []string{`{`, `{"a"}`, `[1,]`, ``}
	for _, s := range bad {
		if err := UniqueKeys([]byte(s)); !errors.Is(err, ErrMalformed) {
			t.Errorf("UniqueKeys(%q) = %v, want ErrMalformed", s, err)
		}
	}
}

func TestFullValue(t *testing.T) {
	if err := FullValue([]byte(`{"a":1}`)); err != nil {
		t.Errorf("single value must pass: %v", err)
	}
	if err := FullValue([]byte(`{"a":1} {}`)); !errors.Is(err, ErrMalformed) {
		t.Errorf("trailing value must be ErrMalformed: %v", err)
	}
	if err := FullValue([]byte(`{"a":1,"a":2} {}`)); !errors.Is(err, ErrDuplicateKey) {
		t.Errorf("duplicate must win over trailing: %v", err)
	}
}

func TestErrorsCarryNoInputBytes(t *testing.T) {
	canary := "CANARY-9f"
	for _, err := range []error{
		UniqueKeys([]byte(`{"` + canary + `":1,"` + canary + `":2}`)),
		UniqueKeys([]byte(`{"` + canary + `":`)),
		FullValue([]byte(`{"` + canary + `":1} trailing`)),
	} {
		if err != nil && strings.Contains(err.Error(), canary) {
			t.Errorf("error echoed input bytes: %v", err)
		}
	}
}
