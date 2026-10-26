package seamcheck

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
)

// Analyze runs the structured provenance analysis over a loaded Package:
//   - the externally-reachable exported callback graph (vars, named types,
//     aliases, struct fields, func params AND results, pointer/value method
//     sets, and unexported-returned-types' exported members), cycle-safe;
//   - raw database/sql DB/Tx/Stmt identity reach through the exported surface
//     and import call targets;
//   - resolved dynamic-dispatch sites (for the provenance policy).
//
// The results carry resolved objects/types so the acceptance policy decides
// by provenance; the Path/Where strings are diagnostics only.
func Analyze(p *Package) (*Analysis, error) {
	if p == nil || p.Pkg == nil {
		return nil, fmt.Errorf("seamcheck: Analyze on nil package — fail closed")
	}
	a := &Analysis{Package: p, DiscoveryGoFiles: append([]string{}, p.GoFiles...)}
	a.collectExportedCallbacks()
	a.collectRawDBReaches()
	a.collectDispatches()
	return a, nil
}

// collectExportedCallbacks walks the exported package scope and every type
// externally reachable from it, recording exposures of function values. It
// does NOT descend into types defined OUTSIDE the analyzed package: stdlib
// and third-party struct fields/methods are not this package's API surface,
// so their internal callbacks (e.g. http.Request.GetBody, x509 verify
// funcs) must not be attributed to the boundary.
func (a *Analysis) collectExportedCallbacks() {
	self := a.Package.Pkg.Path()
	isExternal := func(t types.Type) bool {
		t = types.Unalias(t)
		named, ok := t.(*types.Named)
		if !ok {
			return false
		}
		obj := named.Obj()
		return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() != self
	}
	seen := map[types.Type]bool{}
	var walk func(t types.Type, path string)
	walk = func(t types.Type, path string) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		// Stop at external named types: not this package's reachable API.
		if isExternal(t) {
			return
		}
		switch u := t.Underlying().(type) {
		case *types.Signature:
			// A function VALUE exposure: record it. Its params/results are
			// traversed for nested callback containers.
			for i := 0; i < u.Params().Len(); i++ {
				walk(u.Params().At(i).Type(), path+"/param")
			}
			for i := 0; i < u.Results().Len(); i++ {
				walk(u.Results().At(i).Type(), path+"/result")
			}
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if !f.Exported() {
					continue // private field is not externally reachable
				}
				if TypeIsOrCarriesFunc(f.Type()) {
					a.CallbackExposures = append(a.CallbackExposures, CallbackExposure{
						Object: f, Type: f.Type(), Where: "field", Path: path + "." + f.Name(),
					})
				}
				walk(f.Type(), path+"."+f.Name())
			}
		case *types.Pointer:
			walk(u.Elem(), path+"*")
		case *types.Slice:
			walk(u.Elem(), path+"[]")
		case *types.Array:
			walk(u.Elem(), path+"[n]")
		case *types.Map:
			// BOTH key and value are reachable positions for a callback value.
			if TypeIsOrCarriesFunc(u.Key()) {
				a.CallbackExposures = append(a.CallbackExposures, CallbackExposure{
					Object: nil, Type: u.Key(), Where: "map-key", Path: path + "<key>",
				})
			}
			if TypeIsOrCarriesFunc(u.Elem()) {
				a.CallbackExposures = append(a.CallbackExposures, CallbackExposure{
					Object: nil, Type: u.Elem(), Where: "map-value", Path: path + "<value>",
				})
			}
			walk(u.Key(), path+"<key>")
			walk(u.Elem(), path+"<value>")
		case *types.Chan:
			if TypeIsOrCarriesFunc(u.Elem()) {
				a.CallbackExposures = append(a.CallbackExposures, CallbackExposure{
					Object: nil, Type: u.Elem(), Where: "chan", Path: path + "<-chan",
				})
			}
			walk(u.Elem(), path+"<-chan")
		}
		// Method sets: inspect params/results of exported methods on the
		// named type, BOTH the pointer and value method sets, and the exported
		// members of an UNEXPORTED named type reachable via the API.
		if named, ok := t.(*types.Named); ok {
			for _, ms := range []*types.MethodSet{
				types.NewMethodSet(types.NewPointer(named)),
				types.NewMethodSet(named),
			} {
				for i := 0; i < ms.Len(); i++ {
					sel := ms.At(i)
					m := sel.Obj()
					if !m.Exported() {
						continue
					}
					sig, ok := types.Unalias(sel.Type()).(*types.Signature)
					if !ok {
						continue
					}
					for p := 0; p < sig.Params().Len(); p++ {
						pt := sig.Params().At(p).Type()
						if TypeIsOrCarriesFunc(pt) && !IsStdlibProtocolAdapter(pt) {
							a.CallbackExposures = append(a.CallbackExposures, CallbackExposure{
								Object: sig.Params().At(p), Type: pt, Where: "method-param",
								Path: path + "." + m.Name() + "/param",
							})
						}
						walk(pt, path+"."+m.Name()+"/param")
					}
					for r := 0; r < sig.Results().Len(); r++ {
						rt := sig.Results().At(r).Type()
						if TypeIsOrCarriesFunc(rt) && !IsStdlibProtocolAdapter(rt) {
							a.CallbackExposures = append(a.CallbackExposures, CallbackExposure{
								Object: sig.Results().At(r), Type: rt, Where: "method-result",
								Path: path + "." + m.Name() + "/result",
							})
						}
						walk(rt, path+"."+m.Name()+"/result")
					}
				}
			}
		}
	}

	scope := a.Package.Pkg.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if !obj.Exported() {
			continue
		}
		switch o := obj.(type) {
		case *types.Var:
			// An exported function-typed VAR is a public hook.
			if TypeIsOrCarriesFunc(o.Type()) {
				a.CallbackExposures = append(a.CallbackExposures, CallbackExposure{
					Object: o, Type: o.Type(), Where: "var", Path: name,
				})
			}
			walk(o.Type(), name)
		case *types.Const:
			walk(o.Type(), name)
		case *types.Func:
			// Ordinary exported function: params AND results are part of the
			// reachable callback surface even if a param is unused.
			sig, ok := types.Unalias(o.Type()).(*types.Signature)
			if !ok {
				continue
			}
			for i := 0; i < sig.Params().Len(); i++ {
				pt := sig.Params().At(i).Type()
				if TypeIsOrCarriesFunc(pt) && !IsStdlibProtocolAdapter(pt) {
					a.CallbackExposures = append(a.CallbackExposures, CallbackExposure{
						Object: sig.Params().At(i), Type: pt, Where: "param", Path: name + "/param",
					})
				}
				walk(pt, name+"/param")
			}
			for i := 0; i < sig.Results().Len(); i++ {
				rt := sig.Results().At(i).Type()
				if TypeIsOrCarriesFunc(rt) && !IsStdlibProtocolAdapter(rt) {
					a.CallbackExposures = append(a.CallbackExposures, CallbackExposure{
						Object: sig.Results().At(i), Type: rt, Where: "result", Path: name + "/result",
					})
				}
				walk(rt, name+"/result")
			}
		case *types.TypeName:
			// An exported type alias to a callback, or a named type whose
			// underlying/fields/methods expose callbacks.
			if TypeIsOrCarriesFunc(o.Type()) {
				a.CallbackExposures = append(a.CallbackExposures, CallbackExposure{
					Object: o, Type: o.Type(), Where: "alias", Path: name,
				})
			}
			walk(o.Type(), name)
		}
	}
}

// collectRawDBReaches resolves raw database/sql handle reach: an exported
// var/field/param/result whose type is DB/Tx/Stmt, or an import of
// database/sql with a call through it, is a raw-DB escape from the boundary.
func (a *Analysis) collectRawDBReaches() {
	seen := map[types.Type]bool{}
	var walk func(t types.Type, path string)
	walk = func(t types.Type, path string) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if IsRawDBHandle(t) {
			return // recorded by caller
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem(), path+"*")
		case *types.Slice:
			walk(u.Elem(), path+"[]")
		case *types.Array:
			walk(u.Elem(), path+"[n]")
		case *types.Map:
			walk(u.Key(), path+"<key>")
			walk(u.Elem(), path+"<value>")
		case *types.Chan:
			walk(u.Elem(), path+"<-chan")
		case *types.Signature:
			for i := 0; i < u.Params().Len(); i++ {
				walk(u.Params().At(i).Type(), path+"/param")
			}
			for i := 0; i < u.Results().Len(); i++ {
				walk(u.Results().At(i).Type(), path+"/result")
			}
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if !f.Exported() {
					continue
				}
				if IsRawDBHandle(f.Type()) {
					a.RawDBReaches = append(a.RawDBReaches, RawDBReach{
						Object: f, Type: f.Type(), Where: "field", Path: path + "." + f.Name(),
					})
				}
				walk(f.Type(), path+"."+f.Name())
			}
		}
	}

	scope := a.Package.Pkg.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if !obj.Exported() {
			continue
		}
		if IsRawDBHandle(obj.Type()) {
			a.RawDBReaches = append(a.RawDBReaches, RawDBReach{
				Object: obj, Type: obj.Type(), Where: "var", Path: name,
			})
		}
		walk(obj.Type(), name)
		if fn, ok := obj.(*types.Func); ok {
			sig, _ := types.Unalias(fn.Type()).(*types.Signature)
			if sig != nil {
				for i := 0; i < sig.Params().Len(); i++ {
					if IsRawDBHandle(sig.Params().At(i).Type()) {
						a.RawDBReaches = append(a.RawDBReaches, RawDBReach{
							Object: sig.Params().At(i), Type: sig.Params().At(i).Type(), Where: "param", Path: name + "/param",
						})
					}
				}
				for i := 0; i < sig.Results().Len(); i++ {
					if IsRawDBHandle(sig.Results().At(i).Type()) {
						a.RawDBReaches = append(a.RawDBReaches, RawDBReach{
							Object: sig.Results().At(i), Type: sig.Results().At(i).Type(), Where: "result", Path: name + "/result",
						})
					}
				}
			}
		}
	}

	// Import call-target provenance: a production file importing database/sql
	// and calling through a raw handle is an escape even if not exported.
	for _, f := range a.Package.Files {
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) == "database/sql" {
				a.RawDBReaches = append(a.RawDBReaches, RawDBReach{
					Object: nil, Type: nil, Where: "import", Path: "import database/sql",
				})
			}
		}
	}
}

// collectDispatches records resolved dynamic-dispatch call sites with their
// receiver/owner provenance for the acceptance policy.
func (a *Analysis) collectDispatches() {
	nameOf := map[*ast.File]string{}
	for i, fn := range a.Package.GoFiles {
		if i < len(a.Package.Files) {
			nameOf[a.Package.Files[i]] = fn
		}
	}
	a.producers = map[types.Object]NamedRef{}
	// First pass: record producers of local function-typed values from their
	// defining assignments (e.g. `release := s.limiter.Allow(...)` produces the
	// release handle from the loginLimiter receiver).
	for _, f := range a.Package.Files {
		a.recordProducers(f)
	}
	for _, f := range a.Package.Files {
		fn := nameOf[f]
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			d, found := a.dispatchOf(call)
			if found {
				d.File = fn
				a.Dispatches = append(a.Dispatches, d)
			}
			return true
		})
	}
}

// recordProducers maps local function-typed variables to the provenance of
// the call that produced them: for `x := recv.Method(...)` it records the
// named type of recv as the producer of every function-typed LHS variable.
func (a *Analysis) recordProducers(f *ast.File) {
	info := a.Package.Info
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || as.Tok != token.DEFINE {
			return true
		}
		var producer NamedRef
		for _, rhs := range as.Rhs {
			if call, ok := rhs.(*ast.CallExpr); ok {
				if ref, ok := a.producerOfCall(call); ok {
					producer = ref
				}
			}
		}
		if producer.Name == "" {
			return true
		}
		for _, lhs := range as.Lhs {
			if id, ok := lhs.(*ast.Ident); ok {
				if obj, ok := info.Defs[id]; ok {
					if _, isFunc := obj.Type().Underlying().(*types.Signature); isFunc {
						a.producers[obj] = producer
					}
				}
			}
		}
		return true
	})
}

// producerOfCall resolves the producer of a call's result to the named type
// of the receiver when the call is a method invocation recv.Method(...).
func (a *Analysis) producerOfCall(call *ast.CallExpr) (NamedRef, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return NamedRef{}, false
	}
	if s, ok := a.Package.Info.Selections[sel]; ok && s.Kind() == types.MethodVal {
		if ref, ok := Ref(s.Recv()); ok {
			return ref, true
		}
	}
	return NamedRef{}, false
}

// dispatchOf resolves a call site into a Dispatch when it is a dynamic
// dispatch (interface/func-typed receiver method, func-value call, or
// call-result dispatch). It returns found=false for ordinary static calls.
func (a *Analysis) dispatchOf(call *ast.CallExpr) (Dispatch, bool) {
	info := a.Package.Info
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		if obj, ok := info.Uses[fun]; ok {
			if v, ok := obj.(*types.Var); ok {
				if _, isFunc := v.Type().Underlying().(*types.Signature); isFunc {
					return Dispatch{FuncName: fun.Name, Kind: "func-value-call", Producer: a.producerFor(obj)}, true
				}
			}
		}
	case *ast.SelectorExpr:
		if s, ok := info.Selections[fun]; ok && s.Kind() == types.MethodVal {
			recv := s.Recv()
			if _, isFunc := recv.Underlying().(*types.Signature); isFunc {
				return Dispatch{FuncName: fun.Sel.Name, Recv: recv, Kind: "func-recv-method", Owner: ownerOfSelector(info, fun)}, true
			}
			if _, isIface := recv.Underlying().(*types.Interface); isIface {
				return Dispatch{FuncName: fun.Sel.Name, Recv: recv, Kind: "interface-method", Owner: ownerOfSelector(info, fun)}, true
			}
		}
		if obj, ok := info.Uses[fun.Sel]; ok {
			if v, ok := obj.(*types.Var); ok {
				if _, isFunc := v.Type().Underlying().(*types.Signature); isFunc {
					return Dispatch{FuncName: fun.Sel.Name, Kind: "func-value-call", Producer: a.producerFor(v), Owner: ownerOfSelector(info, fun)}, true
				}
			}
		}
	case *ast.CallExpr:
		if tv, ok := info.Types[fun]; ok && tv.Type != nil {
			if _, isFunc := tv.Type.Underlying().(*types.Signature); isFunc {
				return Dispatch{Kind: "call-result"}, true
			}
		}
	}
	return Dispatch{}, false
}

// producerFor resolves the producer provenance of a function-typed object: the
// named type that produced it (from a recorded defining assignment) when
// known, else the identity of its own named type.
func (a *Analysis) producerFor(obj types.Object) NamedRef {
	if ref, ok := a.producers[obj]; ok {
		return ref
	}
	if v, ok := obj.(*types.Var); ok {
		if ref, ok := Ref(v.Type()); ok {
			return ref
		}
	}
	return NamedRef{}
}

// ownerOfSelector resolves the provenance of the receiver expression X in a
// selector X.Name: for i.now() it is the named struct type of i (e.g.
// *bootstrapIssuer). This is the OWNER provenance used to authorize the four
// private clocks by their declaring type, never by the field spelling.
func ownerOfSelector(info *types.Info, sel *ast.SelectorExpr) types.Type {
	if tv, ok := info.Types[sel.X]; ok && tv.Type != nil {
		return types.Unalias(tv.Type)
	}
	return nil
}
