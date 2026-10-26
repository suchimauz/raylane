package auth

// Executable fixture regressions for the go/types seam classifier (V4 STEP 1).
//
// Every fixture is a self-contained Go source that the classifier type-checks
// and classifies. NEGATIVE fixtures must be REJECTED, each failing for the
// RIGHT structural reason (a function-typed field, a call via a function-typed
// value, or an unresolved target) — never "the name is absent from a map".
// POSITIVE fixtures must be ACCEPTED: a sync.Mutex method call, a time.Time
// method call, and a type conversion are all legitimate and must produce zero
// seams and the expected safe-method count.

import (
	"go/token"
	"strings"
	"testing"
)

// runFixture type-checks a single-fixture source and returns its seam report.
func runFixture(t *testing.T, src string) (*seamReport, error) {
	t.Helper()
	fset := token.NewFileSet()
	return classifySources(fset, []string{"fixture.go"}, map[string]string{"fixture.go": src})
}

// requireSeamFails runs a NEGATIVE fixture and asserts it is rejected with a
// reason that contains every string in wantReasonParts (the RIGHT reason), and
// that safeMethods is 0 (the seam is not mis-counted as a safe method).
func requireSeamFails(t *testing.T, name, src string, wantReasonParts ...string) {
	t.Helper()
	rep, err := runFixture(t, src)
	if err != nil {
		// A TYPE-CHECK failure is a valid, fail-closed rejection: go/types could
		// not resolve the program (e.g. a method the receiver type does not
		// declare), which is strictly stronger than a classifier flag. Accept it
		// as REJECTED; if the caller named a reason, require it in the message.
		msg := err.Error()
		for _, part := range wantReasonParts {
			if !strings.Contains(msg, part) {
				t.Fatalf("%s: type-check rejection %q missing expected reason part %q", name, msg, part)
			}
		}
		return
	}
	if len(rep.fieldSeams) == 0 && len(rep.callSeams) == 0 && len(rep.unresolved) == 0 {
		t.Fatalf("%s: fixture was ACCEPTED but must be REJECTED as a dispatch seam", name)
	}
	all := strings.Join(append(append([]string{}, rep.fieldSeams...), rep.callSeams...), " | ") + " | " + strings.Join(rep.unresolved, " | ")
	for _, part := range wantReasonParts {
		if !strings.Contains(all, part) {
			t.Fatalf("%s: rejection reason %q missing expected part %q (got: %s)", name, all, part, all)
		}
	}
}

// requireSeamPasses runs a POSITIVE fixture and asserts it is fully accepted:
// no field seams, no call seams, no unresolved targets.
func requireSeamPasses(t *testing.T, name, src string, wantSafeMethods int) {
	t.Helper()
	rep, err := runFixture(t, src)
	if err != nil {
		t.Fatalf("%s: positive fixture must type-check and pass, got: %v", name, err)
	}
	if len(rep.fieldSeams) != 0 || len(rep.callSeams) != 0 || len(rep.unresolved) != 0 {
		t.Fatalf("%s: positive fixture must be ACCEPTED clean, got fieldSeams=%v callSeams=%v unresolved=%v",
			name, rep.fieldSeams, rep.callSeams, rep.unresolved)
	}
	if rep.safeMethods != wantSafeMethods {
		t.Fatalf("%s: safeMethods = %d, want %d", name, rep.safeMethods, wantSafeMethods)
	}
}

// --- NEGATIVE fixtures: C3 lexical-lifetime seam classes, rejected for the
// right structural reason (NOT a name-allowlist miss). ---

// C3-snapshot: a struct field whose type is a function type is a dispatch seam
// reachable from outside, regardless of how it is initialised.
func TestFixture_StructFieldFuncType_Rejected(t *testing.T) {
	requireSeamFails(t, "struct-field-func-type", `package auth

type sink struct {
	hook func() error
}

var _ sink
`, "field hook")
}

// C3-init: initialising a function-typed field from an inline literal is still
// a function-typed struct field — the seam is the FIELD TYPE, not the literal.
func TestFixture_StructFieldFuncLitInit_Rejected(t *testing.T) {
	requireSeamFails(t, "struct-field-func-lit-init", `package auth

type runner struct {
	run func() int
}

func makeRunner() runner {
	return runner{run: func() int { return 1 }}
}
`, "field run")
}

// C3-declared-type: a field declared via a NAMED function type is still a
// function-typed struct field once resolved through go/types.
func TestFixture_StructFieldNamedFuncType_Rejected(t *testing.T) {
	requireSeamFails(t, "struct-field-named-func-type", `package auth

type handler func(string) error

type server struct {
	onRequest handler
}

var _ server
`, "field onRequest")
}

// C3-channel: storing a function-typed value in a struct field behind a
// channel-of-func type is still a function-typed struct field.
func TestFixture_StructFieldChanOfFunc_Rejected(t *testing.T) {
	requireSeamFails(t, "struct-field-chan-of-func", `package auth

type gate struct {
	notify chan func()
}

var _ gate
`, "field notify")
}

// C3-switch: a function-typed field selected in a switch is still a seam at
// the field declaration (the switch does not launder the type).
func TestFixture_StructFieldUsedInSwitch_Rejected(t *testing.T) {
	requireSeamFails(t, "struct-field-used-in-switch", `package auth

type cfg struct {
	resolve func(string) string
}

func pick(c cfg, mode int) string {
	switch mode {
	case 0:
		if c.resolve != nil {
			return c.resolve("a")
		}
	}
	return ""
}
`, "field resolve")
}

// Local func-typed variable used as a call target is a dispatch seam.
func TestFixture_LocalFuncVarCall_Rejected(t *testing.T) {
	requireSeamFails(t, "local-func-var-call", `package auth

func use() int {
	f := func() int { return 1 }
	return f()
}
`, "func-typed variable f")
}

// Captured method value (m := x.run; m()) is a function-typed call target.
func TestFixture_CapturedMethodValue_Rejected(t *testing.T) {
	requireSeamFails(t, "captured-method-value", `package auth

type engine struct{ n int }

func (e engine) run() int { return e.n }

func use() int {
	var x engine
	m := x.run
	return m()
}
`, "func-typed variable m")
}

// A method call on a func-typed receiver is a seam (dispatch through a
// function value's method set).
func TestFixture_MethodOnFuncTypedReceiver_Rejected(t *testing.T) {
	requireSeamFails(t, "method-on-func-typed-receiver", `package auth

type fn func() int

func (f fn) describe() string { return "fn" }

func use() string {
	var f fn
	return f.describe()
}
`, "func-typed receiver")
}

// --- POSITIVE fixtures: legitimate constructs the bespoke interpreter
// false-positived on; these MUST be accepted. ---

// A direct sync.Mutex method call is a safe method on a non-function receiver.
func TestFixture_MutexMethodCall_Accepted(t *testing.T) {
	requireSeamPasses(t, "mutex-method-call", `package auth

import "sync"

func use() {
	var m sync.Mutex
	m.Lock()
	m.Unlock()
}
`, 2)
}

// A defer of a mutex unlock is still a direct method call on a non-function
// receiver (one safe method at the defer site).
func TestFixture_DeferMutexUnlock_Accepted(t *testing.T) {
	requireSeamPasses(t, "defer-mutex-unlock", `package auth

import "sync"

func use() {
	var m sync.Mutex
	m.Lock()
	defer m.Unlock()
}
`, 2)
}

// A time.Time method call is a safe method on a non-function receiver.
func TestFixture_TimeMethodCall_Accepted(t *testing.T) {
	requireSeamPasses(t, "time-method-call", `package auth

import "time"

func use(t0 time.Time) bool {
	return t0.IsZero()
}
`, 1)
}

// A type conversion time.Duration(x) is a conversion, not a dispatch seam.
func TestFixture_TypeConversion_Accepted(t *testing.T) {
	requireSeamPasses(t, "type-conversion", `package auth

import "time"

func use(n int64) time.Duration {
	return time.Duration(n)
}
`, 0)
}

// An ordinary call of a package-level function declared in the same fixture is
// a normal function call, not a seam.
func TestFixture_LocalFunctionCall_Accepted(t *testing.T) {
	requireSeamPasses(t, "local-function-call", `package auth

func helper() int { return 1 }

func use() int {
	return helper()
}
`, 0)
}

// A struct with only non-function fields plus a mutex method call is fully
// clean — the field census and the method resolution agree.
func TestFixture_MixedCleanStructAndMethod_Accepted(t *testing.T) {
	requireSeamPasses(t, "mixed-clean-struct-and-method", `package auth

import "sync"

type ledger struct {
	mu  sync.Mutex
	cnt int
}

func (l *ledger) incr() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cnt++
}
`, 2)
}

// The discriminating case the bespoke interpreter could not express: invoking
// a method directly on a value is ACCEPTED, but extracting the same method as
// a value and calling that value is a REJECTED seam. Both use the identical
// receiver and method; only the call-vs-value distinction differs.
func TestFixture_DirectCallAccepted_ButMethodValueRejected(t *testing.T) {
	// Direct call: accepted, one safe method.
	requireSeamPasses(t, "direct-call-accepted", `package auth

type engine struct{ n int }

func (e engine) run() int { return e.n }

func use() int {
	var x engine
	return x.run()
}
`, 1)
	// Method value extracted then called: rejected seam.
	requireSeamFails(t, "method-value-rejected", `package auth

type engine struct{ n int }

func (e engine) run() int { return e.n }

func use() int {
	var x engine
	m := x.run
	return m()
}
`, "func-typed variable m")
}

// A function literal assigned to a variable and then called is a call via a
// function-typed value — a seam — even though the literal is inline.
func TestFixture_FuncLiteralValueCalled_Rejected(t *testing.T) {
	requireSeamFails(t, "func-literal-value-called", `package auth

func use() int {
	f := func() int { return 1 }
	return f()
}
`, "func-typed variable f")
}

// An immediately-invoked function literal is a plain inline call, not an
// external dispatch seam — accepted.
func TestFixture_ImmediatelyInvokedFuncLit_Accepted(t *testing.T) {
	requireSeamPasses(t, "immediately-invoked-func-lit", `package auth

func use() int {
	return func() int { return 1 }()
}
`, 0)
}

// A DIRECT method call on a CUSTOM CONCRETE type is ACCEPTED whatever the
// method is named — including a method literally named Lock on a type that is
// NOT sync.Mutex. This locks in the type-based rule (no name list, no
// receiver-type list) and inverts the old backwards fixture that rejected a
// custom fake.Lock. The contrast: a method the receiver type DOES declare on
// a concrete type is safe; a method the type does NOT declare would fail to
// type-check (unresolvable, fail closed) — go/types enforces the method set.
func TestFixture_CustomConcreteMethodAnyName_Accepted(t *testing.T) {
	requireSeamPasses(t, "custom-concrete-method-any-name", `package auth

type fake struct{ n int }

func (f fake) Lock() int { return f.n }

func use() int {
	var h fake
	return h.Lock()
}
`, 1)
}

// A method the concrete receiver type does NOT declare is an unresolvable
// target: go/types fails the type-check (fail closed). This closes the old
// method-name-authorization defect for free — the method set is checked
// against the resolved concrete receiver type.
func TestFixture_AbsentMethodOnConcreteType_Rejected(t *testing.T) {
	requireSeamFails(t, "absent-method-on-concrete", `package auth

type fake struct{ n int }

func use() int {
	var h fake
	return h.Lock()
}
`)
}

// A channel-range element method call: the loop variable is the concrete
// element type, so a direct method call on it is safe (no bespoke rule).
func TestFixture_ChannelRangeElementMethod_Accepted(t *testing.T) {
	requireSeamPasses(t, "channel-range-element-method", `package auth

import "sync"

type item struct{ mu sync.Mutex }

func use(ch chan item) {
	for v := range ch {
		v.mu.Lock()
		v.mu.Unlock()
	}
}
`, 2)
}

// Nested different-type shadow restore: an inner block re-binds x to a value
// of a DIFFERENT type, then the outer x (original concrete type) is used for a
// direct method call. go/types binds each scope correctly by construction.
func TestFixture_NestedDifferentTypeShadowRestore_Accepted(t *testing.T) {
	requireSeamPasses(t, "nested-different-type-shadow-restore", `package auth

import "sync"

type clock struct{ when int }

type holder struct{ mu sync.Mutex }

var y clock

func use(x holder) {
	_ = x
	{
		x := y
		_ = x.when
	}
	x.mu.Lock()
}
`, 1)
}

// Switch-init restore: a variable declared in a switch init does not leak past
// the switch; a direct method call on the outer concrete value is safe.
func TestFixture_SwitchInitRestore_Accepted(t *testing.T) {
	requireSeamPasses(t, "switch-init-restore", `package auth

import "sync"

type gate struct{ mu sync.Mutex }

func use(g gate, mode int) {
	switch v := mode; v {
	case 0:
		_ = v
	}
	g.mu.Lock()
}
`, 1)
}

// Type-switch binding: the bound variable in a type switch has a resolved
// concrete type in each arm; a direct method call on a concrete arm is safe.
func TestFixture_TypeSwitchBinding_Accepted(t *testing.T) {
	requireSeamPasses(t, "type-switch-binding", `package auth

import "sync"

type a struct{ mu sync.Mutex }

type b struct{ n int }

func use(x interface{}) {
	switch v := x.(type) {
	case a:
		v.mu.Lock()
	case b:
		_ = v.n
	}
}
`, 1)
}

// A method call on an INTERFACE receiver is a seam (dynamic dispatch: the
// concrete method is chosen at run time), even though the static receiver is
// not a func type.
func TestFixture_MethodOnInterfaceReceiver_Rejected(t *testing.T) {
	requireSeamFails(t, "method-on-interface-receiver", `package auth

type runner interface {
	run() int
}

func use(r runner) int {
	return r.run()
}
`, "interface receiver")
}

// Call-result dispatch f()(): the call target is a function VALUE produced at
// run time, not a statically bound method — a seam.
func TestFixture_CallResultDispatch_Rejected(t *testing.T) {
	requireSeamFails(t, "call-result-dispatch", `package auth

func makeFn() func() int { return func() int { return 1 } }

func use() int {
	return makeFn()()
}
`, "call-result dispatch")
}

// A package-level function VARIABLE used as a call target is a seam (a
// function-typed value not statically bound to a concrete method).
func TestFixture_PackageLevelFuncVarDispatch_Rejected(t *testing.T) {
	requireSeamFails(t, "package-level-func-var-dispatch", `package auth

var dispatch = func() int { return 1 }

func use() int {
	return dispatch()
}
`, "func-typed variable dispatch")
}
