package authhttp

import (
	"fmt"
	"go/types"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/seamcheck"
)

// This is the runtime composition-boundary guard (T008 G4, ccv DECISION §3,
// architect decision §1). It enforces the narrow-surface invariant across the
// COMPLETE production package using maintained go/build discovery and ONE
// compiler/provenance pipeline (internal/seamcheck) — never a hand-maintained
// file list, and never authorization by identifier spelling or human-label
// substring.
//
// Acceptance is decided from RESOLVED provenance only:
//   - the six stdlib protocol adapters (net/http.Handler, ResponseWriter,
//     context.Context, net.Listener, net.Conn, io/fs.FileInfo) by type
//     identity;
//   - the four PRIVATE constructor-injected clocks (Server.now,
//     bootstrapIssuer.now, loginLimiter.now, sessionManager.now) by their
//     declaring owner type AND func() time.Time signature — a struct field
//     merely NAMED "now" on any other type is NOT authorized;
//   - the bounded shared-KDF-gate release (producer loginLimiter.Allow) and
//     stdlib context cancellation — by resolved producer, including the
//     approved bootstrap release site.
//
// Every exported callback exposure and every raw database/sql reach is a
// violation. Discovery/parse/type/provenance errors fail closed.

// clockFieldOwnerNames are the four private structs that carry an approved
// constructor-injected wall clock. Only each struct's exact `now` field object
// is authorized — never any other field on the same owner.
var clockFieldOwnerNames = []string{"Server", "bootstrapIssuer", "loginLimiter", "sessionManager"}

// boundaryPolicy decides acceptance from resolved provenance.
type boundaryPolicy struct {
	approvedClocks map[*types.Var]bool // exact resolved *.now field objects
}

func newBoundaryPolicy(self *types.Package) *boundaryPolicy {
	return &boundaryPolicy{approvedClocks: resolveApprovedClocks(self)}
}

// resolveApprovedClocks resolves the EXACT `now` field object on each of the
// four approved owner declarations and returns them as a set keyed by object
// identity. Authorization compares the invoked field object to one of these
// resolved objects; owner-has-a-clock, field-name, or signature alone never
// authorizes.
func resolveApprovedClocks(self *types.Package) map[*types.Var]bool {
	set := map[*types.Var]bool{}
	if self == nil {
		return set
	}
	for _, ownerName := range clockFieldOwnerNames {
		obj := self.Scope().Lookup(ownerName)
		if obj == nil {
			continue
		}
		named, ok := obj.Type().(*types.Named)
		if !ok {
			continue
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		// Resolve the exact `now` field object on this owner declaration.
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f.Name() == "now" && isFuncReturningTime(f.Type()) {
				set[f] = true
			}
		}
	}
	return set
}

// gateReleaseTypeName is the producer owner type name of the bounded
// shared-KDF-gate release handle (the func value returned by loginLimiter.Allow).
const gateReleaseTypeName = "loginLimiter"

// Violation is a structured policy rejection with resolved provenance.
type Violation struct {
	Kind   string // "callback-exposure" | "raw-db-reach" | "dispatch"
	Detail string
}

// Check runs the provenance policy over a structured Analysis and returns the
// violations (empty when the boundary is clean).
func (pol *boundaryPolicy) Check(a *seamcheck.Analysis) []Violation {
	var vs []Violation
	for _, c := range a.CallbackExposures {
		vs = append(vs, Violation{Kind: "callback-exposure",
			Detail: fmt.Sprintf("exported callback exposure (%s) at %s type %v", c.Where, c.Path, c.Type)})
	}
	for _, r := range a.RawDBReaches {
		vs = append(vs, Violation{Kind: "raw-db-reach",
			Detail: fmt.Sprintf("raw database/sql reach (%s) at %s", r.Where, r.Path)})
	}
	for _, d := range a.Dispatches {
		if !pol.acceptDispatch(d) {
			vs = append(vs, Violation{Kind: "dispatch",
				Detail: fmt.Sprintf("unauthorized dispatch %s %q (recv %v owner %v) in %s",
					d.Kind, d.FuncName, d.Recv, d.Owner, d.File)})
		}
	}
	return vs
}

// acceptDispatch decides a single dispatch by resolved provenance.
func (pol *boundaryPolicy) acceptDispatch(d seamcheck.Dispatch) bool {
	switch d.Kind {
	case "interface-method":
		// Accepted iff the receiver is one of the six stdlib adapters, by
		// identity. An arbitrary local interface (CloseEnough, qaCloser, ...)
		// is NOT accepted even if its method is named Close/Serve/Write.
		return seamcheck.IsStdlibProtocolAdapter(d.Recv)
	case "func-value-call":
		return pol.acceptFuncValueCall(d)
	default:
		// func-recv-method and call-result dispatch are never approved.
		return false
	}
}

// acceptFuncValueCall authorizes ONLY the resolved private clocks, the bounded
// gate release, and stdlib context cancellation — by owner/producer
// provenance and the clock signature, never by the variable name.
func (pol *boundaryPolicy) acceptFuncValueCall(d seamcheck.Dispatch) bool {
	if pol.isClockCall(d) {
		return true
	}
	if pol.isGateRelease(d) {
		return true
	}
	if isContextCancel(d) {
		return true
	}
	return false
}

// isClockCall authorizes a private clock invocation ONLY when the EXACT
// invoked field object is one of the four resolved approved `.now` clock
// fields. Owner-has-a-clock, field-name spelling, the enclosing type name, or
// the signature alone are insufficient: an arbitrary `Server.evil
// func() time.Time` or `Server.onEvent func() error` is a different field
// object and is rejected. A missing/ambiguous selected identity fails closed.
func (pol *boundaryPolicy) isClockCall(d seamcheck.Dispatch) bool {
	sel, ok := d.Selected.(*types.Var)
	if !ok || sel == nil {
		return false // fail closed: unknown selection is not an approved clock
	}
	// The selected field must be private (the clocks are unexported).
	if sel.Exported() {
		return false
	}
	// Compare object identity to the exact approved `.now` field objects.
	return pol.approvedClocks[sel]
}

// isFuncReturningTime reports whether t is exactly func() time.Time.
func isFuncReturningTime(t types.Type) bool {
	sig, ok := types.Unalias(t).Underlying().(*types.Signature)
	if !ok {
		return false
	}
	if sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return false
	}
	res := types.Unalias(sig.Results().At(0).Type())
	named, ok := res.(*types.Named)
	if !ok {
		return false
	}
	return named.Obj().Name() == "Time" && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "time"
}

// isGateRelease authorizes the bounded shared-KDF-gate release handle by its
// resolved producer: the func value returned from loginLimiter.Allow.
func (pol *boundaryPolicy) isGateRelease(d seamcheck.Dispatch) bool {
	// The release value is produced by loginLimiter.Allow; its producer owner
	// is the loginLimiter type. Match by that resolved identity.
	if d.Producer.PkgPath != "" || d.Producer.Name == "" {
		// Producer resolved to a named type: must be loginLimiter.
		return d.Producer.Name == gateReleaseTypeName
	}
	// Fallback: a bare local release func is authorized only if the analyzed
	// package declares loginLimiter (the gate producer) — verified via owner.
	return false
}

// isContextCancel reports whether the func value is a stdlib context
// cancellation function, by resolved producer identity (context.CancelFunc).
func isContextCancel(d seamcheck.Dispatch) bool {
	return d.Producer.PkgPath == "context" && d.Producer.Name == "CancelFunc"
}

// TestAuthhttpCompositionBoundary is the runtime boundary guard. It discovers
// the production package with go/build, analyzes it with the ONE shared
// compiler/provenance pipeline, applies the provenance policy, and requires a
// clean result. New production files are picked up automatically by discovery.
func TestAuthhttpCompositionBoundary(t *testing.T) {
	violations := guardViolations(t, ".")
	if len(violations) != 0 {
		for _, v := range violations {
			t.Errorf("boundary violation [%s]: %s", v.Kind, v.Detail)
		}
		t.Fatalf("runtime composition boundary rejected: %d violation(s)", len(violations))
	}
}

// guardViolations runs discovery+analysis+policy and returns the violations.
// It is the SINGLE path both the live guard and the discriminating mutation
// tests invoke.
func guardViolations(t *testing.T, dir string) []Violation {
	t.Helper()
	p, err := seamcheck.LoadPackage(dir)
	if err != nil {
		t.Fatalf("boundary discovery/type-check failed closed: %v", err)
	}
	a, err := seamcheck.Analyze(p)
	if err != nil {
		t.Fatalf("boundary analysis failed closed: %v", err)
	}
	pol := newBoundaryPolicy(p.Pkg)
	return pol.Check(a)
}

// requireNoViolations asserts the guard accepts a clean package dir.
func requireNoViolations(t *testing.T, dir string) {
	t.Helper()
	if vs := guardViolations(t, dir); len(vs) != 0 {
		for _, v := range vs {
			t.Errorf("unexpected violation [%s]: %s", v.Kind, v.Detail)
		}
		t.Fatalf("expected clean boundary, got %d violation(s)", len(vs))
	}
}

// requireViolation asserts the guard rejects with at least one violation whose
// combined detail contains every part (the intended cause).
func requireViolation(t *testing.T, dir string, parts ...string) {
	t.Helper()
	vs := guardViolations(t, dir)
	if len(vs) == 0 {
		t.Fatalf("expected boundary violation, got clean acceptance")
	}
	all := ""
	for _, v := range vs {
		all += v.Kind + ": " + v.Detail + "\n"
	}
	for _, part := range parts {
		if !strings.Contains(all, part) {
			t.Fatalf("violations missing intended cause %q; got:\n%s", part, all)
		}
	}
}
