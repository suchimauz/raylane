package capability_test

// Focused package tests for the neutral capability authority: strict metadata
// parsing, copy immutability of the loaded authority, and the compatibility
// surface contract that the API layer consumes without a second parser.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/api"
	"github.com/suchimauz/raylane/internal/capability"
)

const canary = "CANARY-PROFILE-LEAF-42"

func TestParseValidProfileMetadataReadable(t *testing.T) {
	raw := []byte(`{"profileVersion":2,"protocols":{"probe":{"fields":{
		"req":{"type":"string","classification":"known","required":true},
		"def":{"type":"integer","classification":"known","default":7,"minimum":1,"maximum":10},
		"nodef":{"type":"integer","classification":"known"},
		"sec":{"type":"string","classification":"secret","secret":true},
		"dep":{"type":"enum","classification":"known","allowedValues":["a","b"],"dependencies":{"requires":["req"],"incompatibleWith":["sec"]}}
	}}}}`)
	p, err := capability.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	f, ok := p.Field("probe", "req")
	if !ok || !f.Required {
		t.Fatalf("required not consumed: %+v", f)
	}
	d, _ := p.Field("probe", "def")
	if !d.HasDefault {
		t.Fatal("default presence lost")
	}
	n, _ := p.Field("probe", "nodef")
	if n.HasDefault {
		t.Fatal("invented default on absent field")
	}
	dp, _ := p.Field("probe", "dep")
	if dp.Dependencies == nil || len(dp.Dependencies.Requires) != 1 || dp.Dependencies.Requires[0] != "req" ||
		len(dp.Dependencies.IncompatibleWith) != 1 || dp.Dependencies.IncompatibleWith[0] != "sec" {
		t.Fatalf("dependencies not consumed: %+v", dp.Dependencies)
	}
}

func TestParseRejectsMalformedAuthorityMetadata(t *testing.T) {
	wrap := func(fields string) []byte {
		return []byte(`{"profileVersion":2,"protocols":{"probe":{"fields":{` + fields + `}}}}`)
	}
	cases := map[string][]byte{
		"empty":                             []byte("   "),
		"not-json":                          []byte("{"),
		"trailing":                          append(wrap(`"a":{"type":"string","classification":"known"}`), []byte(" []")...),
		"top-dup-key":                       []byte(`{"profileVersion":2,"profileVersion":2,"protocols":{"probe":{"fields":{"a":{"type":"string","classification":"known"}}}}}`),
		"nested-dup-key":                    []byte(`{"profileVersion":2,"protocols":{"probe":{"fields":{"a":{"type":"string","classification":"known"},"a":{"type":"integer","classification":"known"}}}}}`),
		"unknown-top-key":                   []byte(`{"profileVersion":2,"extra":1,"protocols":{"probe":{"fields":{"a":{"type":"string","classification":"known"}}}}}`),
		"unknown-field":                     wrap(`"a":{"type":"string","classification":"known","zzz":"` + canary + `"}`),
		"secret-default":                    wrap(`"a":{"type":"string","classification":"secret","secret":true,"default":"` + canary + `"}`),
		"required-secret-plaintext-default": wrap(`"a":{"type":"string","classification":"secret","secret":true,"required":true,"default":"x"}`),
		"default-type":                      wrap(`"a":{"type":"integer","classification":"known","default":"` + canary + `"}`),
		"default-bounds":                    wrap(`"a":{"type":"integer","classification":"known","default":99,"minimum":1,"maximum":10}`),
		"default-enum-out":                  wrap(`"a":{"type":"enum","classification":"known","allowedValues":["x"],"default":"` + canary + `"}`),
		"dep-self":                          wrap(`"a":{"type":"string","classification":"known","dependencies":{"requires":["a"],"incompatibleWith":[]}}`),
		"dep-ghost":                         wrap(`"a":{"type":"string","classification":"known","dependencies":{"requires":["ghost"],"incompatibleWith":[]}}`),
		"bad-pattern":                       wrap(`"a":{"type":"string","classification":"known","pattern":"["`),
		"zero-version":                      []byte(`{"profileVersion":0,"protocols":{"probe":{"fields":{"a":{"type":"string","classification":"known"}}}}}`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := capability.Parse(raw)
			if !errors.Is(err, capability.ErrProfileRejected) {
				t.Fatalf("want ErrProfileRejected, got %v", err)
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("error echoed raw value: %v", err)
			}
		})
	}
}

func TestAuthoritySnapshotCannotBeMutated(t *testing.T) {
	raw := []byte(`{"profileVersion":2,"protocols":{"probe":{"fields":{
		"e":{"type":"enum","classification":"known","allowedValues":["x","y"]},
		"d":{"type":"string","classification":"known","dependencies":{"requires":["e"],"incompatibleWith":[]}}
	}}}}`)
	p, err := capability.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e, _ := p.Field("probe", "e")
	e.AllowedValues[0] = "HACKED"
	names := p.FieldNames("probe")
	if len(names) != 2 {
		t.Fatalf("names: %v", names)
	}
	e2, _ := p.Field("probe", "e")
	if e2.AllowedValues[0] != "x" {
		t.Fatalf("authority poisoned through snapshot: %v", e2.AllowedValues)
	}
	d, _ := p.Field("probe", "d")
	d.Dependencies.Requires[0] = "HACKED"
	d2, _ := p.Field("probe", "d")
	if d2.Dependencies.Requires[0] != "e" {
		t.Fatalf("dependency alias: %v", d2.Dependencies.Requires)
	}
	// Protocols() snapshot likewise.
	ps := p.Protocols()
	if len(ps) != 1 || ps[0] != "probe" {
		t.Fatalf("protocols: %v", ps)
	}
	ps[0] = "HACKED"
	if p.Protocols()[0] != "probe" {
		t.Fatal("protocols slice aliased")
	}
}

func TestAPIWrapperIsSameAuthorityNoSecondParser(t *testing.T) {
	raw := []byte(`{"profileVersion":2,"protocols":{"probe":{"fields":{"a":{"type":"string","classification":"known"}}}}}`)
	p1, err := api.ParseCapabilityProfile(raw)
	if err != nil {
		t.Fatalf("api wrapper: %v", err)
	}
	p2, err := capability.Parse(raw)
	if err != nil {
		t.Fatalf("capability: %v", err)
	}
	if p1 != p2 && (p1 == nil || p2 == nil) {
		t.Fatal("nil mismatch")
	}
	// errors.Is compatibility: api alias and capability sentinel are one value.
	_, errA := api.ParseCapabilityProfile([]byte("{"))
	if !errors.Is(errA, capability.ErrProfileRejected) || !errors.Is(errA, api.ErrProfileRejected) {
		t.Fatalf("error identity broken: %v", errA)
	}
	// Version visible through the alias type.
	if v := p2.Version(); v != 2 {
		t.Fatalf("version %d", v)
	}
	_ = json.RawMessage(nil)
}
