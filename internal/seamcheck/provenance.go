// Provenance-structured composition analysis (T008 G4 correction).
//
// The label-based Report in seamcheck.go is retained for diagnostics and for
// the accepted primitive closed-census guard. This file adds the structured,
// compiler-resolved analysis the RUNTIME boundary needs: maintained package
// discovery (go/build, no hand-maintained file list), an externally-reachable
// exported callback graph, and raw database/sql identity resolution — all
// decided by resolved object/type/owner/producer provenance, never by
// identifier spelling or human label substrings.
//
// Every entry point fails closed: a discovery, parse, import or type-check
// error rejects the input rather than silently accepting an unverifiable
// package.
package seamcheck

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
)

// Package is a type-checked package plus the parsed files and discovery
// provenance needed for structured analysis.
type Package struct {
	Pkg     *types.Package
	Info    *types.Info
	Fset    *token.FileSet
	Files   []*ast.File
	FileSrc map[*ast.File][]byte
	Dir     string
	GoFiles []string
}

// LoadPackage discovers the production Go files of the package in dir using
// go/build (the maintained build context: build tags, GOOS/GOARCH), parses
// and type-checks them as one package, and returns the structured Package. It
// fails closed on any discovery/parse/import/type error.
//
// Production GoFiles from go/build already exclude *_test.go (including
// export_test.go), so the test-only adapters never enter this analysis.
func LoadPackage(dir string) (*Package, error) {
	bp, err := build.ImportDir(dir, build.ImportComment)
	if err != nil {
		return nil, fmt.Errorf("seamcheck: discover package in %s: %w — fail closed", dir, err)
	}
	if len(bp.GoFiles) == 0 {
		return nil, fmt.Errorf("seamcheck: no production Go files discovered in %s — fail closed", dir)
	}
	fset := token.NewFileSet()
	var parsed []*ast.File
	srcs := map[*ast.File][]byte{}
	names := map[*ast.File]string{}
	for _, fn := range bp.GoFiles {
		full := filepath.Join(dir, fn)
		data, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("seamcheck: read %s: %w — fail closed", full, err)
		}
		f, err := parser.ParseFile(fset, fn, data, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("seamcheck: parse %s: %w — fail closed", fn, err)
		}
		parsed = append(parsed, f)
		srcs[f] = data
		names[f] = fn
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check(bp.ImportPath, fset, parsed, info)
	if err != nil {
		return nil, fmt.Errorf("seamcheck: type-check %s: %w — fail closed", bp.ImportPath, err)
	}
	return &Package{
		Pkg:     pkg,
		Info:    info,
		Fset:    fset,
		Files:   parsed,
		FileSrc: srcs,
		Dir:     dir,
		GoFiles: append([]string{}, bp.GoFiles...),
	}, nil
}

// LoadPackage discovers the production Go files a resolved named type by package path and name — the
// provenance identity used for acceptance decisions (never spelling of use
// sites).
type NamedRef struct {
	PkgPath string
	Name    string
}

// Ref returns the NamedRef identity of a named type, following aliases and
// one pointer level.
func Ref(t types.Type) (NamedRef, bool) {
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok {
		return NamedRef{}, false
	}
	obj := named.Obj()
	if obj == nil {
		return NamedRef{}, false
	}
	pkgPath := ""
	if obj.Pkg() != nil {
		pkgPath = obj.Pkg().Path()
	}
	return NamedRef{PkgPath: pkgPath, Name: obj.Name()}, true
}

// IsNamed reports whether t resolves (through aliases/pointers) to the named
// type with the given package path and name.
func IsNamed(t types.Type, pkgPath, name string) bool {
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Name() != name {
		return false
	}
	if obj.Pkg() == nil {
		return pkgPath == ""
	}
	return obj.Pkg().Path() == pkgPath
}

// IsStdlibProtocolAdapter reports whether t is one of the six accepted
// resolved stdlib protocol interfaces, matched by package path and interface
// identity (types.Unalias resolves os.FileInfo -> io/fs.FileInfo).
func IsStdlibProtocolAdapter(t types.Type) bool {
	iface, ok := types.Unalias(t).Underlying().(*types.Interface)
	if !ok {
		return false
	}
	_ = iface
	for _, a := range []NamedRef{
		{PkgPath: "net/http", Name: "Handler"},
		{PkgPath: "net/http", Name: "ResponseWriter"},
		{PkgPath: "context", Name: "Context"},
		{PkgPath: "net", Name: "Listener"},
		{PkgPath: "net", Name: "Conn"},
		{PkgPath: "io/fs", Name: "FileInfo"},
	} {
		if IsNamed(t, a.PkgPath, a.Name) {
			return true
		}
	}
	return false
}

// IsRawDBHandle reports whether t resolves (through aliases and one pointer
// level) to database/sql.DB, Tx or Stmt, matched by package identity.
func IsRawDBHandle(t types.Type) bool {
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	for _, name := range []string{"DB", "Tx", "Stmt"} {
		if IsNamed(t, "database/sql", name) {
			return true
		}
	}
	return false
}

// CallbackExposure is a resolved reachable exposure of a function value
// through the exported API. Path is the provenance chain (for diagnostics
// only); the decision uses the resolved object/type, not the path text.
type CallbackExposure struct {
	Object types.Object
	Type   types.Type
	Where  string // "var" | "field" | "param" | "result" | "alias" | "method-param" | "method-result"
	Path   string
}

// RawDBReach is a resolved reach of a raw database/sql handle through the
// exported API or an import call target.
type RawDBReach struct {
	Object types.Object
	Type   types.Type
	Where  string
	Path   string
}

// Analysis is the structured provenance result for one package.
type Analysis struct {
	Package           *Package
	CallbackExposures []CallbackExposure
	RawDBReaches      []RawDBReach
	Dispatches        []Dispatch
	DiscoveryGoFiles  []string
	producers         map[types.Object]NamedRef
}

// Dispatch is a resolved dynamic-dispatch call site (interface or
// func-typed-receiver method call, call via a func value, or call-result
// dispatch). The decision to accept or reject uses the resolved receiver /
// producer provenance, never the method-name spelling.
type Dispatch struct {
	FuncName string
	Recv     types.Type // resolved receiver type (interface or func), nil if a bare func value
	Kind     string     // "interface-method" | "func-recv-method" | "func-value-call" | "call-result"
	Owner    types.Type // enclosing receiver/object type for provenance
	File     string
	Producer NamedRef     // resolved producer of a func value when known
	Selected types.Object // the EXACT resolved field/var object invoked (e.g. the *types.Var for s.now); nil if unknown
}
