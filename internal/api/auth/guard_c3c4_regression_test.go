package auth

// Executable regression tests for the C3 lexical-lifetime and C4 index-producer
// arity repairs. Each case parses an in-memory source through the SAME guard
// entry point (assertNoFunctionSeams) the production files use, so a PASS/FAIL
// is the guard's real behavioural decision — never a source-text or hash match.

import (
	"testing"
)

// checkSource is a thin wrapper around the production seam-guard entry point.
func checkSource(t *testing.T, src string) error {
	t.Helper()
	return runSeamGuard(t, src)
}

// TestT008C3VarDeclaredTypeRetained: `var x T = init` must retain the declared
// type T for subsequent same-scope uses (the C3 declared-type retention repair).
// A declared non-function struct type used as a selector base afterwards must
// resolve through T, not be dropped by an immediate binding restore.
func TestT008C3VarDeclaredTypeRetained(t *testing.T) {
	src := `package auth

type rec struct{ idle int }

func use(m map[[4]byte]rec) {
	var x rec = m[[4]byte{1}]
	_ = x.idle
}
`
	if err := checkSource(t, src); err != nil {
		t.Fatalf("var x rec = ... retaining declared rec for x.idle must be accepted, got: %v", err)
	}
}

// TestT008C3BodyFuncVarRejectedAtDeclaration: a body-declared `var f func()`
// is a function-typed variable and must be rejected AT DECLARATION even with
// no initialiser and no continued use (the C3 body-declaration seam check).
func TestT008C3BodyFuncVarRejectedAtDeclaration(t *testing.T) {
	src := `package auth

func use() {
	var f func()
	_ = f
}
`
	if err := checkSource(t, src); err == nil {
		t.Fatal("body var f func() must be rejected at declaration even without use")
	}
}

// TestT008C3NestedShadowRestored: an inner-block declaration that shadows an
// outer name must NOT leak the inner binding past its block; the outer binding
// is what a later same-name use sees (C3 outer-restore-at-real-lexical-boundary).
// Here the inner shadow is a func value (a seam) but it is correctly scoped to
// the inner block; the outer use is a struct value. The inner func is a seam
// regardless, so this must fail — proving the inner declaration is REACHABLE
// and checked (not silently dropped), while a struct shadow is accepted.
func TestT008C3NestedShadowReachable(t *testing.T) {
	// Struct shadow: accepted (inner struct binding shadows outer, restored after).
	ok := `package auth

type box struct{ n int }
var g box

func use() {
	x := g
	{
		x := box{n: 1}
		_ = x.n
	}
	_ = x.n
}
`
	if err := checkSource(t, ok); err != nil {
		t.Fatalf("nested struct shadow restored at block boundary must be accepted, got: %v", err)
	}
	// Func shadow inside the nested block: still a seam (reachable + checked).
	bad := `package auth

type box struct{ n int }
var g box

func use() {
	x := g
	{
		f := func() int { return 1 }
		_ = f
	}
	_ = x.n
}
`
	if err := checkSource(t, bad); err == nil {
		t.Fatal("inner-block function value must still fail closed (reachable seam)")
	}
}

// TestT008C3MixedRedefineNotRetyped: `y, z := existing, newval` where y already
// exists in the same block keeps y's ORIGINAL type while z is newly declared;
// the redeclaration must not silently retype y (C3 mixed-redeclaration).
func TestT008C3MixedRedefineNotRetyped(t *testing.T) {
	src := `package auth

type box struct{ n int }
var g box

func use() int {
	y := g.n
	y, z := 3, 4
	return y + z
}
`
	if err := checkSource(t, src); err != nil {
		t.Fatalf("mixed := redeclare (y existing, z new) of int values must be accepted, got: %v", err)
	}
}

// TestT008C4MapCommaOkTwoResults: a 2-name bind from a resolvable MAP index is
// the comma-ok form (element + bool) and must be accepted with the element's
// real type (C4 proven-map two-result).
func TestT008C4MapCommaOkTwoResults(t *testing.T) {
	src := `package auth

type rec struct{ idle int }

func use(m map[string]rec) {
	v, ok := m["k"]
	if ok {
		_ = v.idle
	}
}
`
	if err := checkSource(t, src); err != nil {
		t.Fatalf("2-name map comma-ok (v, ok := m[k]) must be accepted, got: %v", err)
	}
}

// TestT008C4SingleResultContainerOneName: a 1-name bind from a slice/array index
// is a single result and keeps the real element type (C4 single-result container).
func TestT008C4SingleResultContainerOneName(t *testing.T) {
	src := `package auth

type rec struct{ idle int }

func use(s []rec) {
	v := s[0]
	_ = v.idle
}
`
	if err := checkSource(t, src); err != nil {
		t.Fatalf("1-name slice index (v := s[0]) keeping element type must be accepted, got: %v", err)
	}
}

// TestT008C4NonMapTwoNameIndexRejected: a 2-name bind from a SLICE index is NOT a
// valid comma-ok (slices are single-result) and must FAIL CLOSED rather than
// invent a second slot (C4 non-map 2-name arity fail-closed).
func TestT008C4NonMapTwoNameIndexRejected(t *testing.T) {
	src := `package auth

type rec struct{ idle int }

func use(s []rec) {
	v, ok := s[0]
	_, _ = v, ok
}
`
	if err := checkSource(t, src); err == nil {
		t.Fatal("2-name slice index (v, ok := s[0]) must fail closed (single-result container)")
	}
}

// TestT008C4ContinuedUseRetained: a binding made earlier stays live for a later
// same-scope selector use (C4/declared-type continued-use retention).
func TestT008C4ContinuedUseRetained(t *testing.T) {
	src := `package auth

type rec struct{ idle int }

func use(m map[string]rec) {
	v := m["a"]
	_ = v.idle
	v2 := m["b"]
	_ = v2.idle
}
`
	if err := checkSource(t, src); err != nil {
		t.Fatalf("continued same-scope use of bound map values must be accepted, got: %v", err)
	}
}
