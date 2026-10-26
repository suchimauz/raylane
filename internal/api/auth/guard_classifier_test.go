package auth

// go/types-based function-seam classifier (V4 STEP 1), test infrastructure.
//
// This REPLACES the bespoke AST interpreter (the ~47-helper hand-rolled Go
// interpreter that previously lived in storekdf_test.go) with the stdlib
// go/parser + go/types pipeline, per the ccv wire decision (DECISION.md §7).
// go/types is strictly more precise: it resolves m.mu.Lock() to a DIRECT
// method call on sync.Mutex and time.Duration(x) to a type conversion, so
// legitimate method calls on provably non-function receivers stop producing
// false positives while every real dispatch seam is still caught.
//
// No new dependency: go/parser, go/token, go/types and go/importer are
// stdlib; golang.org/x/tools is NOT required. The package is type-checked
// inside the module with importer.ForCompiler(fset, "source", nil).
//
// Enduring security guarantees expressed here (unchanged intent, go/types form):
//   G-2  no function-typed STRUCT FIELD; no CALL TARGET that is a function-typed
//        VALUE (local func-typed var, captured method value, method on a
//        func-typed receiver). A direct method call on a provably NON-function
//        receiver is NOT a seam.
//   G-3  import direction: only storekdf.go may import internal/store;
//        internal/store must never import internal/api/auth.
//   G-5' forbidden SQL/raw-DB escape (literal + db-handle forms), enforced on a
//        comment-masked copy of every production file.
//   G-1  no package-level EXPORTED symbol and no package-level VAR in the
//        primitive production files (scoped to the primitive slice; the runtime
//        composition boundary is a SEPARATE package).
//   G-scope the primitive file set is exactly the accepted five.
//   G-6  no arbitrary hooks: the ONLY function-typed value permitted is the
//        single accepted creation-only rand.Read reader seam in kdf.go.

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"strings"
)

// primitiveProductionFiles is the closed set of primitive files the seam and
// package-wide guarantees are scoped to (G-scope). The runtime composition
// boundary lives in a SEPARATE package and is not part of this census.
var primitiveProductionFiles = []string{
	"kdf.go",
	"storekdf.go",
	"protect_token.go",
	"protect_session.go",
	"protect_admission.go",
}

// seamReport is the classifier outcome over one type-checked package.
type seamReport struct {
	fieldSeams  []string // function-typed struct fields (file: field names)
	callSeams   []string // call targets that are function-typed values
	safeMethods int      // invoked direct method calls on non-function receivers
	unresolved  []string // call targets go/types could not resolve (fail closed)
}

// classifySources type-checks the provided sources (one map entry per file
// name; empty string means "read from disk") as a single "auth" package and
// classifies dispatch seams. It returns an error (fail closed) if parsing or
// type-checking fails, so an unverifiable file is never silently accepted.
func classifySources(fset *token.FileSet, fileNames []string, srcs map[string]string) (*seamReport, error) {
	var parsed []*ast.File
	nameOf := map[*ast.File]string{}
	for _, fn := range fileNames {
		var data []byte
		if srcs[fn] == "" {
			// Production file: read from disk relative to the package dir (tests
			// run with the package dir as cwd).
			b, err := os.ReadFile(fn)
			if err != nil {
				return nil, fmt.Errorf("classifySources: read %s: %w — fail closed", fn, err)
			}
			data = b
		} else {
			data = []byte(srcs[fn])
		}
		f, err := parser.ParseFile(fset, fn, data, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("classifySources: parse %s: %w — fail closed", fn, err)
		}
		parsed = append(parsed, f)
		nameOf[f] = fn
	}

	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	if _, err := conf.Check("auth", fset, parsed, info); err != nil {
		return nil, fmt.Errorf("classifySources: type-check: %w — fail closed", err)
	}

	rep := &seamReport{}
	for _, f := range parsed {
		fn := nameOf[f]
		rep.walkFile(f, fn, info)
	}
	return rep, nil
}

// walkFile classifies a single type-checked file.
func (rep *seamReport) walkFile(f *ast.File, fn string, info *types.Info) {
	// G-2a: function-typed STRUCT FIELDS only. A *ast.Field under a StructType;
	// function parameters and results are NOT struct fields and must not be
	// flagged (e.g. the accepted creation-only reader parameter).
	ast.Inspect(f, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok || st.Fields == nil {
			return true
		}
		for _, fld := range st.Fields.List {
			if tv, ok := info.Types[fld.Type]; ok {
				if typeIsOrCarriesFunc(tv.Type) {
					rep.fieldSeams = append(rep.fieldSeams, fmt.Sprintf("%s: field %s", fn, fieldLabel(fld)))
				}
			}
		}
		return true
	})

	// G-2b: call-target classification and safe-method counting. Determine
	// invocation context by tracking enclosing CallExpr function positions.
	invoked := map[*ast.SelectorExpr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				invoked[sel] = true
			}
		}
		return true
	})

	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if seam, why := callTargetIsFuncValue(x, info); seam {
				rep.callSeams = append(rep.callSeams, fmt.Sprintf("%s: %s", fn, why))
			} else if !callTargetResolved(x, info) {
				rep.unresolved = append(rep.unresolved, fmt.Sprintf("%s: %s", fn, callTargetLabel(x.Fun)))
			}
		case *ast.SelectorExpr:
			if s, ok := info.Selections[x]; ok && s.Kind() == types.MethodVal {
				recv := s.Recv()
				if _, isFunc := recv.Underlying().(*types.Signature); isFunc {
					// (4) method on a func-typed receiver — a seam.
					rep.callSeams = append(rep.callSeams, fmt.Sprintf("%s: method %s on func-typed receiver", fn, x.Sel.Name))
				} else if _, isIface := recv.Underlying().(*types.Interface); isIface {
					// (5) method on an interface receiver — dynamic dispatch, a seam.
					rep.callSeams = append(rep.callSeams, fmt.Sprintf("%s: method %s on interface receiver", fn, x.Sel.Name))
				} else if invoked[x] {
					// A real DIRECT method call on a positively resolved CONCRETE
					// (non-function, non-interface) receiver is NOT a seam — whatever
					// the method is named and whatever the concrete type is. This is
					// the class the bespoke interpreter false-positived on.
					rep.safeMethods++
				}
			}
		}
		return true
	})
}

// callTargetIsFuncValue reports whether a call's target resolves to a
// function-typed VALUE (local func-typed var, captured method value, or method
// on a func-typed receiver). Returns (true, reason) for a seam.
// callTargetIsFuncValue reports whether a call's target is a dispatch SEAM.
// Per the enduring contract the rule is purely TYPE-based with NO name list
// and NO receiver-type list. A seam is a call target that denotes a
// function-typed value not statically bound to a concrete method:
//
//	(1) struct field whose type is a function type        -> caught by fieldSeams
//	(2) local variable of function type used as a target  -> here
//	(3) captured method value (m := x.F; m())             -> here
//	(4) method call whose RECEIVER is function-typed      -> here
//	(5) method call whose RECEIVER is an INTERFACE type   -> here (dynamic dispatch)
//	(6) the result of a call used as a call target f()()  -> here
//	(7) an unresolvable target                            -> unresolved (fail closed)
//
// A DIRECT method call on a positively resolved CONCRETE (non-interface,
// non-function) receiver is NOT a seam — WHATEVER the method is named and
// WHATEVER the concrete type is (so fake.Lock() on a custom concrete type is
// ACCEPTED; sync.Mutex.Lock and time.Time methods are accepted as a subset).
func callTargetIsFuncValue(call *ast.CallExpr, info *types.Info) (bool, string) {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		// (2)/(3): a call whose function is an identifier bound to a
		// function-typed VARIABLE (a local func-typed var or a captured method
		// value). A *types.Func (declared function) or a type name (conversion)
		// is a normal static call.
		if obj, ok := info.Uses[fun]; ok {
			switch o := obj.(type) {
			case *types.Var:
				if _, isFunc := o.Type().Underlying().(*types.Signature); isFunc {
					return true, fmt.Sprintf("call via func-typed variable %s", fun.Name)
				}
			}
		}
		return false, ""
	case *ast.SelectorExpr:
		if s, ok := info.Selections[fun]; ok && s.Kind() == types.MethodVal {
			recv := s.Recv()
			// (4) method on a func-typed receiver.
			if _, isFunc := recv.Underlying().(*types.Signature); isFunc {
				return true, fmt.Sprintf("method %s on func-typed receiver", fun.Sel.Name)
			}
			// (5) method on an INTERFACE receiver: the concrete method is chosen
			// at run time (dynamic dispatch), so it is a seam even though the
			// static receiver is not a func type.
			if _, isIface := recv.Underlying().(*types.Interface); isIface {
				return true, fmt.Sprintf("method %s on interface receiver (dynamic dispatch)", fun.Sel.Name)
			}
			return false, "" // direct method call on a concrete non-func receiver: safe
		}
		// Package-qualified call pkg.Fn(...) or a struct-field value used as a
		// call target. A func-typed struct/package field value is a seam (2).
		if obj, ok := info.Uses[fun.Sel]; ok {
			if v, ok := obj.(*types.Var); ok {
				if _, isFunc := v.Type().Underlying().(*types.Signature); isFunc {
					return true, fmt.Sprintf("call via func-typed value %s", fun.Sel.Name)
				}
			}
		}
		return false, ""
	case *ast.CallExpr:
		// (6) the result of a call used as a call target (f()()): the target is
		// a function VALUE produced at run time, not a statically bound method.
		if tv, ok := info.Types[fun]; ok && tv.Type != nil {
			if _, isFunc := tv.Type.Underlying().(*types.Signature); isFunc {
				return true, "call-result dispatch (f()())"
			}
		}
		return false, ""
	default:
		return false, ""
	}
}

// callTargetResolved reports whether a call target has a resolved non-function
// meaning (direct method call, package call, conversion, ordinary function).
func callTargetResolved(call *ast.CallExpr, info *types.Info) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		if obj, ok := info.Uses[fun]; ok {
			if _, isVar := obj.(*types.Var); isVar {
				return false // func-typed var handled elsewhere; a var call target is unresolved
			}
			return true
		}
		if tv, ok := info.Types[fun]; ok && tv.Type != nil {
			return true
		}
		return false
	case *ast.SelectorExpr:
		if _, ok := info.Selections[fun]; ok {
			return true
		}
		if obj, ok := info.Uses[fun.Sel]; ok {
			if _, isFn := obj.(*types.Func); isFn {
				return true
			}
			if v, ok := obj.(*types.Var); ok {
				if _, isFunc := v.Type().Underlying().(*types.Signature); isFunc {
					return false
				}
			}
			return true
		}
		return false
	case *ast.FuncLit:
		return true
	case *ast.IndexExpr, *ast.IndexListExpr:
		return info.Types[fun].Type != nil
	default:
		// Conversions (time.Duration(x)), parenthesised targets, etc.
		return info.Types[call.Fun].Type != nil
	}
}

// typeIsOrCarriesFunc reports whether a type is a function type or a container
// (pointer, slice, array, map, channel) whose ELEMENT type is or carries a
// function type. A struct field of such a type can store or transport a
// function value and is therefore a dispatch seam.
func typeIsOrCarriesFunc(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Signature:
		return true
	case *types.Pointer:
		return typeIsOrCarriesFunc(u.Elem())
	case *types.Slice:
		return typeIsOrCarriesFunc(u.Elem())
	case *types.Array:
		return typeIsOrCarriesFunc(u.Elem())
	case *types.Map:
		return typeIsOrCarriesFunc(u.Elem()) || typeIsOrCarriesFunc(u.Key())
	case *types.Chan:
		return typeIsOrCarriesFunc(u.Elem())
	}
	return false
}

func fieldLabel(f *ast.Field) string {
	var names []string
	for _, n := range f.Names {
		names = append(names, n.Name)
	}
	return strings.Join(names, ",")
}

func callTargetLabel(e ast.Expr) string {
	var sb strings.Builder
	writeExprLabel(&sb, e)
	return sb.String()
}

func writeExprLabel(sb *strings.Builder, e ast.Expr) {
	switch x := e.(type) {
	case *ast.Ident:
		sb.WriteString(x.Name)
	case *ast.SelectorExpr:
		writeExprLabel(sb, x.X)
		sb.WriteString("." + x.Sel.Name)
	default:
		sb.WriteString("expr")
	}
}
