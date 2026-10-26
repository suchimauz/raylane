package auth

// Executable regression tests for the T008 function-seam guard (C3/C4).
// These PARSE synthetic in-memory sources and run the SAME guard entry point
// (assertNoFunctionSeams) the production files go through, so each case is a
// real behavioural check — not a source-text or hash assertion. Positive cases
// must be ACCEPTED; negative (genuinely seam) cases must FAIL CLOSED.

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// runSeamGuard parses src as package auth and runs the production seam guard.
// It returns the guard's error (nil = accepted).
func runSeamGuard(t *testing.T, src string) error {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "protect_token.go", src, 0)
	if err != nil {
		t.Fatalf("synthetic source does not parse: %v", err)
	}
	return assertNoFunctionSeams("protect_token.go", f)
}

// seamCase is one executable guard expectation.
type seamCase struct {
	name   string
	src    string
	accept bool // true = guard must accept; false = guard must fail closed
}

// seamPositiveHeader is the common accepted package header: the seam guard's
// file-scope checks require the file to be in the closed three-file set and
// parse as package auth, with a sync import available for mutex cases.
const seamPositiveMutex = `package auth

import "sync"

type limiter struct {
	mu sync.Mutex
	n  int
}

func (l *limiter) inc() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n++
}
`

func TestT008SeamGuardDirectMethodCallsAccepted(t *testing.T) {
	// The original regression: l.mu.Lock()/Unlock() are legitimate ordinary
	// method calls on a resolved non-function field, NOT a function-typed
	// dispatch seam. This is positive resolution through the field's type,
	// not a selector-name allowlist (a function-typed field with the same
	// selector shape must still fail — see the negative cases).
	if err := runSeamGuard(t, seamPositiveMutex); err != nil {
		t.Fatalf("direct sync.Mutex Lock/Unlock must be accepted, got: %v", err)
	}
}

func TestT008SeamGuardMethodValueRejected(t *testing.T) {
	// Method VALUE extraction (f := l.mu.Lock) binds a function value, a
	// dispatch seam — direct invocation is NOT method-value extraction.
	src := `package auth

import "sync"

type limiter struct {
	mu sync.Mutex
}

func (l *limiter) grab() {
	f := l.mu.Lock
	_ = f
}
`
	if err := runSeamGuard(t, src); err == nil {
		t.Fatal("method value extraction (f := l.mu.Lock) must fail closed")
	}
}

func TestT008SeamGuardFunctionTypedFieldCallRejected(t *testing.T) {
	// A call on a function-TYPED field (s.fn()) is a real seam even though it
	// looks like a selector call; it must fail closed.
	src := `package auth

type runner struct {
	fn func() int
}

func (r *runner) run() int {
	return r.fn()
}
`
	if err := runSeamGuard(t, src); err == nil {
		t.Fatal("call on a function-typed field (r.fn()) must fail closed")
	}
}

func TestT008SeamGuardFunctionLiteralValueRejected(t *testing.T) {
	src := `package auth

func use() {
	f := func() int { return 1 }
	_ = f
}
`
	if err := runSeamGuard(t, src); err == nil {
		t.Fatal("binding a function literal value must fail closed")
	}
}

func TestT008SeamGuardNamedFunctionValueCaptureRejected(t *testing.T) {
	// Capturing a declared function into a variable (even unused) is a seam.
	src := `package auth

func helper() int { return 1 }

func use() {
	g := helper
	_ = g
}
`
	if err := runSeamGuard(t, src); err == nil {
		t.Fatal("named function value capture (g := helper) must fail closed")
	}
}

func TestT008SeamGuardUnresolvableCallTargetRejected(t *testing.T) {
	// A bare call to a name that is neither a this-file function, a local
	// binding, nor a builtin must fail closed.
	src := `package auth

func use() {
	mysterious(1)
}
`
	if err := runSeamGuard(t, src); err == nil {
		t.Fatal("call to an unresolvable bare target must fail closed")
	}
}

// TestT008SeamGuardTableDriven runs the full positive/negative matrix through
// the real guard. Each row is executed, not pattern-matched.
func TestT008SeamGuardTableDriven(t *testing.T) {
	cases := []seamCase{
		{
			name:   "sync_mutex_lock_unlock_accepted",
			src:    seamPositiveMutex,
			accept: true,
		},
		{
			name: "defer_mutex_unlock_accepted",
			src: `package auth

import "sync"

type l struct{ mu sync.Mutex }

func (x *l) f() {
	x.mu.Lock()
	defer x.mu.Unlock()
}
`,
			accept: true,
		},
		{
			name: "time_time_method_on_field_accepted",
			src: `package auth

import "time"

type holder struct{ when time.Time }

func (h *holder) due(now time.Time) bool {
	return h.when.Before(now)
}
`,
			accept: true,
		},
		{
			name: "function_field_call_rejected",
			src: `package auth

type r struct{ fn func() }

func (x *r) run() { x.fn() }
`,
			accept: false,
		},
		{
			name: "function_literal_rejected",
			src: `package auth

func u() { g := func() {}; g() }
`,
			accept: false,
		},
		{
			name: "named_func_value_capture_rejected",
			src: `package auth

func h() {}
func u() { g := h; g() }
`,
			accept: false,
		},
		{
			name: "unresolvable_bare_call_rejected",
			src: `package auth

func u() { mystery() }
`,
			accept: false,
		},
		{
			name: "method_value_extraction_rejected",
			src: `package auth

import "sync"

type l struct{ mu sync.Mutex }

func (x *l) g() { f := x.mu.Lock; _ = f }
`,
			accept: false,
		},
		{
			name: "param_pointer_mutex_method_accepted",
			src: `package auth

import "sync"

type mgr struct{ mu sync.Mutex }

func reg(m *mgr) {
	m.mu.Lock()
	defer m.mu.Unlock()
}
`,
			accept: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runSeamGuard(t, tc.src)
			if tc.accept && err != nil {
				t.Fatalf("expected ACCEPT, got fail-closed: %v", err)
			}
			if !tc.accept && err == nil {
				t.Fatal("expected FAIL CLOSED, got accepted")
			}
		})
	}
}

// TestT008SeamGuardDirectVsValueDistinguish pins the core distinction: the
// SAME selector is accepted when INVOKED as a method call but rejected when
// EXTRACTED as a method value.
func TestT008SeamGuardDirectVsValueDistinguish(t *testing.T) {
	direct := `package auth

import "sync"

type l struct{ mu sync.Mutex }

func (x *l) f() { x.mu.Lock() }
`
	if err := runSeamGuard(t, direct); err != nil {
		t.Fatalf("direct method invocation x.mu.Lock() must be accepted, got: %v", err)
	}
	value := `package auth

import "sync"

type l struct{ mu sync.Mutex }

func (x *l) f() { g := x.mu.Lock; _ = g }
`
	if err := runSeamGuard(t, value); err == nil {
		t.Fatal("method value g := x.mu.Lock must fail closed")
	}
}

// TestT008SeamGuardNoTextSubstitution guards the test itself: if a case's
// expectation were satisfied by a substring/allowlist check rather than the
// real guard, these assertions would be vacuous. We assert the guard actually
// returns DISTINCT accept/reject across the matrix (proving it ran).
func TestT008SeamGuardExecutesRealCheck(t *testing.T) {
	accepted := 0
	rejected := 0
	matrix := []seamCase{
		{name: "a", src: seamPositiveMutex, accept: true},
		{name: "b", src: `package auth

type r struct{ fn func() }
func (x *r) run() { x.fn() }
`, accept: false},
	}
	for _, tc := range matrix {
		err := runSeamGuard(t, tc.src)
		if tc.accept && err == nil {
			accepted++
		}
		if !tc.accept && err != nil {
			rejected++
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("guard did not discriminate accept vs reject (accepted=%d rejected=%d)", accepted, rejected)
	}
	if !strings.Contains(seamPositiveMutex, "sync") {
		t.Fatal("test fixture sanity")
	}
}
