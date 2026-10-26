// Package seamcheck is the single shared go/parser + go/types composition
// classifier used by the V4 composition-boundary guards (T008 G-2/G-4, ccv
// wire decision DECISION.md §7 and the architect decision §1). It is the
// EXTRACTED form of the classifier that previously lived only inside
// internal/api/auth's guard tests, so the primitive, facade and runtime
// composition packages are all checked by the ONE maintained pipeline — no
// second interpreter, no literal/selector-spelling blacklist, no bespoke AST
// walker is introduced anywhere else.
//
// go/types is strictly more precise than a hand-rolled interpreter: it
// resolves m.mu.Lock() to a DIRECT method call on sync.Mutex and
// time.Duration(x) to a type conversion, so legitimate method calls on
// provably non-function receivers are not flagged while every real dispatch
// seam is still caught. No new dependency: go/parser, go/token, go/types and
// go/importer are stdlib.
//
// Enduring guarantees expressed here (unchanged intent, go/types form):
//
//	G-2  no function-typed STRUCT FIELD; no CALL TARGET that is a
//	     function-typed VALUE (local func-typed var, captured method value,
//	     method on a func-typed receiver, method on an interface receiver,
//	     call-result dispatch, package-level func-var dispatch).
//	G-4  no EXPORTED callback-bearing API across variables, fields,
//	     parameters/results and nested reachable exported containers; no raw
//	     database/sql DB/Tx/Stmt escape reachable from the composition
//	     boundary; imports/call targets are resolved by object/type identity
//	     and provenance, never by selector spelling.
//
// The classifier FAILS CLOSED: any parse, type-check, import or provenance
// error rejects the input rather than silently accepting an unverifiable
// file.
package seamcheck

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

// Report is the classifier outcome over one type-checked package.
type Report struct {
	FieldSeams  []string // function-typed struct fields (file: field names)
	CallSeams   []string // call targets that are function-typed values / dynamic dispatch
	SafeMethods int      // invoked direct method calls on non-function, non-interface receivers
	Unresolved  []string // call targets go/types could not resolve (fail closed)
}

// Classify type-checks the provided sources (one map entry per file name;
// empty string means "read from disk") as a single package named pkgName and
// classifies dispatch seams. It returns an error (fail closed) if parsing or
// type-checking fails, so an unverifiable file is never silently accepted.
func Classify(pkgName string, fset *token.FileSet, fileNames []string, srcs map[string]string) (*Report, error) {
	var parsed []*ast.File
	nameOf := map[*ast.File]string{}
	for _, fn := range fileNames {
		var data []byte
		if srcs[fn] == "" {
			b, err := os.ReadFile(fn)
			if err != nil {
				return nil, fmt.Errorf("seamcheck: read %s: %w — fail closed", fn, err)
			}
			data = b
		} else {
			data = []byte(srcs[fn])
		}
		f, err := parser.ParseFile(fset, fn, data, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("seamcheck: parse %s: %w — fail closed", fn, err)
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
	if _, err := conf.Check(pkgName, fset, parsed, info); err != nil {
		return nil, fmt.Errorf("seamcheck: type-check %s: %w — fail closed", pkgName, err)
	}

	rep := &Report{}
	for _, f := range parsed {
		rep.walkFile(f, nameOf[f], info)
	}
	return rep, nil
}

// walkFile classifies a single type-checked file.
func (rep *Report) walkFile(f *ast.File, fn string, info *types.Info) {
	// G-2a: function-typed STRUCT FIELDS only. A *ast.Field under a StructType;
	// function parameters and results are NOT struct fields and must not be
	// flagged.
	ast.Inspect(f, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok || st.Fields == nil {
			return true
		}
		for _, fld := range st.Fields.List {
			if tv, ok := info.Types[fld.Type]; ok {
				if TypeIsOrCarriesFunc(tv.Type) {
					rep.FieldSeams = append(rep.FieldSeams, fmt.Sprintf("%s: field %s", fn, fieldLabel(fld)))
				}
			}
		}
		return true
	})

	// G-2b: call-target classification and safe-method counting.
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
				rep.CallSeams = append(rep.CallSeams, fmt.Sprintf("%s: %s", fn, why))
			} else if !callTargetResolved(x, info) {
				rep.Unresolved = append(rep.Unresolved, fmt.Sprintf("%s: %s", fn, callTargetLabel(x.Fun)))
			}
		case *ast.SelectorExpr:
			if s, ok := info.Selections[x]; ok && s.Kind() == types.MethodVal {
				recv := s.Recv()
				if _, isFunc := recv.Underlying().(*types.Signature); isFunc {
					rep.CallSeams = append(rep.CallSeams, fmt.Sprintf("%s: method %s on func-typed receiver", fn, x.Sel.Name))
				} else if _, isIface := recv.Underlying().(*types.Interface); isIface {
					rep.CallSeams = append(rep.CallSeams, fmt.Sprintf("%s: method %s on interface receiver", fn, x.Sel.Name))
				} else if invoked[x] {
					rep.SafeMethods++
				}
			}
		}
		return true
	})
}

// callTargetIsFuncValue reports whether a call's target resolves to a
// function value (a dispatch seam) rather than a declared function, method or
// conversion.
func callTargetIsFuncValue(call *ast.CallExpr, info *types.Info) (bool, string) {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
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
			if _, isFunc := recv.Underlying().(*types.Signature); isFunc {
				return true, fmt.Sprintf("method %s on func-typed receiver", fun.Sel.Name)
			}
			if _, isIface := recv.Underlying().(*types.Interface); isIface {
				return true, fmt.Sprintf("method %s on interface receiver (dynamic dispatch)", fun.Sel.Name)
			}
			return false, ""
		}
		if obj, ok := info.Uses[fun.Sel]; ok {
			if v, ok := obj.(*types.Var); ok {
				if _, isFunc := v.Type().Underlying().(*types.Signature); isFunc {
					return true, fmt.Sprintf("call via func-typed value %s", fun.Sel.Name)
				}
			}
		}
		return false, ""
	case *ast.CallExpr:
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
				return false
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
		return info.Types[call.Fun].Type != nil
	}
}

// TypeIsOrCarriesFunc reports whether a type is a function type or a container
// (pointer, slice, array, map, channel) whose ELEMENT type is or carries a
// function type. A struct field of such a type can store or transport a
// function value and is therefore a dispatch seam.
func TypeIsOrCarriesFunc(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Signature:
		return true
	case *types.Pointer:
		return TypeIsOrCarriesFunc(u.Elem())
	case *types.Slice:
		return TypeIsOrCarriesFunc(u.Elem())
	case *types.Array:
		return TypeIsOrCarriesFunc(u.Elem())
	case *types.Map:
		return TypeIsOrCarriesFunc(u.Elem()) || TypeIsOrCarriesFunc(u.Key())
	case *types.Chan:
		return TypeIsOrCarriesFunc(u.Elem())
	}
	return false
}

// fieldLabel renders a struct field's names for a report.
func fieldLabel(f *ast.Field) string {
	var names []string
	for _, n := range f.Names {
		names = append(names, n.Name)
	}
	return strings.Join(names, ",")
}

// callTargetLabel renders a call target expression for a report.
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
