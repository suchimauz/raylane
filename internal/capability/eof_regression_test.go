package capability_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/capability"
)

// authoredProfileBytes loads the repository's authored profile so the test
// exercises the REAL authority bytes, not a hand-built fixture.
func authoredProfileBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../contracts/capability-profile.json")
	if err != nil {
		t.Fatalf("read authored profile: %v", err)
	}
	return raw
}

// TestParseRejectsTrailingContent is the QA3-A1 regression for the capability
// authority's own full-consumption guard. capability.Parse decoded the first
// value then probed with dec.More(), which cannot see a trailing closer, so a
// valid profile followed by '}' / ']' / '}}' / '}]' was ACCEPTED as an
// authority. A malformed profile must never become an accepted authority:
// any bytes after the first complete value except whitespace are rejected
// with ErrProfileRejected. The guard is independent of the later shared
// scanner (its own decoder, its own EOF probe).
func TestParseRejectsTrailingContent(t *testing.T) {
	base := authoredProfileBytes(t)
	// The authored profile alone must still parse (unchanged success).
	if _, err := capability.Parse(base); err != nil {
		t.Fatalf("authored profile alone must parse: %v", err)
	}
	cases := []struct {
		name string
		suf  string
	}{
		{"single-close-brace", "}"},
		{"single-close-bracket", "]"},
		{"double-close-brace", "}}"},
		{"bracket-then-brace", "}]"},
		{"trailing-object", " {}"},
		{"trailing-number", " 5"},
		{"trailing-string", ` "x"`},
		{"trailing-garbage", " garbage"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			payload := append(append([]byte{}, base...), []byte(c.suf)...)
			p, err := capability.Parse(payload)
			if err == nil {
				t.Fatalf("Parse(profile+%q) accepted a malformed profile as authority", c.suf)
			}
			if p != nil {
				t.Fatalf("non-nil profile returned alongside error for trailing %q", c.suf)
			}
			if !errors.Is(err, capability.ErrProfileRejected) {
				t.Fatalf("want ErrProfileRejected, got %v", err)
			}
		})
	}
}

// TestParseTrailingRejectionIsValueFree: the trailing-content rejection echoes
// no submitted bytes — the reason stays a static package constant.
func TestParseTrailingRejectionIsValueFree(t *testing.T) {
	base := authoredProfileBytes(t)
	canary := "CANARY-TRAIL-9z"
	err := func() error {
		_, err := capability.Parse(append(append([]byte{}, base...), []byte(" "+canary)...))
		return err
	}()
	if err == nil || !errors.Is(err, capability.ErrProfileRejected) {
		t.Fatalf("want ErrProfileRejected, got %v", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("trailing rejection echoed input bytes: %v", err)
	}
}

// TestParseExistingContractsUnchanged: metadata validation, duplicate-key
// rejection, unknown-key rejection and errors.Is behavior are untouched by the
// EOF guard.
func TestParseExistingContractsUnchanged(t *testing.T) {
	// Valid authored profile still parses and reports version 2.
	p, err := capability.Parse(authoredProfileBytes(t))
	if err != nil {
		t.Fatalf("authored profile: %v", err)
	}
	if p.Version() != 4 {
		t.Fatalf("version = %d, want 4", p.Version())
	}
	// Duplicate key still rejected.
	dup := `{"profileVersion":2,"protocols":{"vless":{"fields":{"a":{"type":"string","classification":"known"},"a":{"type":"string","classification":"known"}}}}}`
	if _, err := capability.Parse([]byte(dup)); !errors.Is(err, capability.ErrProfileRejected) {
		t.Fatalf("duplicate key must stay rejected: %v", err)
	}
	// Unknown metadata key still rejected.
	unknown := `{"profileVersion":2,"bogus":true,"protocols":{}}`
	if _, err := capability.Parse([]byte(unknown)); !errors.Is(err, capability.ErrProfileRejected) {
		t.Fatalf("unknown key must stay rejected: %v", err)
	}
	// Trailing whitespace alone is still accepted.
	ws := append(append([]byte{}, authoredProfileBytes(t)...), []byte("  \n\t")...)
	if _, err := capability.Parse(ws); err != nil {
		t.Fatalf("trailing whitespace must stay accepted: %v", err)
	}
}
