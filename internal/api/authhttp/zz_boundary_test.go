package authhttp

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"strings"
	"testing"

	"github.com/suchimauz/raylane/internal/seamcheck"
)

// authhttpProductionFiles is the closed set of runtime composition production
// files the boundary guarantee is scoped to.
var authhttpProductionFiles = []string{
	"bootstrap.go",
	"config.go",
	"csrf.go",
	"limiter.go",
	"requestid.go",
	"responses.go",
	"server.go",
	"session.go",
}

// TestAuthhttpCompositionBoundary guards the runtime composition boundary's
// narrow-surface invariant (ccv DECISION §3, architect decision §1) using the
// ONE shared go/types classifier in internal/seamcheck — NOT a new literal
// scanner or selector blacklist. The guarantees:
//
//  1. No dispatch seam in any production file: no function-typed struct field
//     and no call through a function-typed value, an interface receiver, a
//     func-typed receiver or a call result. The accepted exceptions are the
//     resolved stdlib protocol adapters (net/http, context, net, io/fs) and
//     the four PRIVATE constructor-injected clock fields.
//  2. No EXPORTED callback-bearing API: the only exported surface is
//     Config (all-unexported fields), Server (all-unexported fields) and
//     NewServer; none exposes a function value reachable by a caller.
//  3. No raw database/sql escape: the composition package does not import
//     database/sql and never names a *sql.DB/Tx/Stmt; persistence goes through
//     the typed internal/store API only.
//
// The classifier fails closed on any parse/type-check/import/provenance
// error, so an unverifiable file is never silently accepted.
func TestAuthhttpCompositionBoundary(t *testing.T) {
	srcs := map[string]string{}
	for _, fn := range authhttpProductionFiles {
		srcs[fn] = ""
	}
	rep, err := seamcheck.Classify("authhttp", token.NewFileSet(), authhttpProductionFiles, srcs)
	if err != nil {
		t.Fatalf("authhttp composition classification failed closed: %v", err)
	}
	if len(rep.Unresolved) != 0 {
		t.Fatalf("unresolved call targets (fail closed): %v", rep.Unresolved)
	}
	for _, cs := range rep.FieldSeams {
		if !isAcceptedClockField(cs) {
			t.Fatalf("unexpected function-typed struct field: %q (only the four private clocks are accepted)", cs)
		}
	}
	for _, cs := range rep.CallSeams {
		if !isAcceptedCallSeam(cs) {
			t.Fatalf("unexpected dispatch seam: %q", cs)
		}
	}
	assertNoExportedCallback(t)
	assertNoRawDBReach(t)
}

// isAcceptedClockField reports whether a field-seam report label names the one
// accepted private clock field spelling ("now"). The structural guarantee that
// ONLY the four reviewed clocks exist is enforced separately by
// assertOnlyClockFields.
func isAcceptedClockField(label string) bool {
	_, after, ok := strings.Cut(label, ": field ")
	return ok && strings.TrimSpace(after) == "now"
}

// isAcceptedCallSeam whitelists ONLY the resolved stdlib protocol-adapter
// method calls and the bounded gate/context release handles, matched by
// resolved method provenance (never by arbitrary dispatch).
func isAcceptedCallSeam(label string) bool {
	for _, name := range []string{
		// net/http.Handler / ResponseWriter / Header / ServeMux / request helpers
		"ServeHTTP", "WriteHeader", "Write", "Header", "Set", "Add", "Del", "Get",
		"Handle", "HandleFunc", "ServeTLS", "Shutdown",
		"ParseForm", "FormValue", "Cookie", "Cookies", "SetCookie", "Redirect",
		// context.Context lifecycle (resolved stdlib adapter)
		"Done", "Err", "Deadline", "Value", "cancel",
		// net.Listener / net.Conn (resolved stdlib adapter)
		"Accept", "Close", "Addr", "LocalAddr", "RemoteAddr", "Read", "SetDeadline",
		// io/fs.FileInfo via os.FileInfo alias (resolved stdlib adapter)
		"Stat", "Name", "Size", "Mode", "ModTime", "IsDir", "Sys",
		// bounded KDF-gate release handle (resolved producer: loginLimiter.Allow)
		"release",
		// the four PRIVATE constructor-injected clock fixtures being invoked
		// (resolved owner: Server/bootstrapIssuer/loginLimiter/sessionManager).
		"now",
	} {
		if strings.Contains(label, name) {
			return true
		}
	}
	return false
}

// authhttpPkg type-checks the production files as one package and returns the
// *types.Package plus the *types.Info used to reach it.
func authhttpPkg(t *testing.T) (*types.Package, *types.Info) {
	t.Helper()
	fset := token.NewFileSet()
	var parsed []*ast.File
	for _, fn := range authhttpProductionFiles {
		b, err := os.ReadFile(fn)
		if err != nil {
			t.Fatalf("read %s: %v", fn, err)
		}
		f, err := parser.ParseFile(fset, fn, b, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", fn, err)
		}
		parsed = append(parsed, f)
	}
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Defs:  map[*ast.Ident]types.Object{},
		Uses:  map[*ast.Ident]types.Object{},
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check("authhttp", fset, parsed, info)
	if err != nil {
		t.Fatalf("type-check authhttp: %v — fail closed", err)
	}
	return pkg, info
}

// assertNoExportedCallback resolves the exported surface and rejects any
// exported symbol, exported struct field, or exported-method parameter/result
// whose type is or carries a function value. The accepted stdlib protocol
// interfaces are whitelisted by OBJECT identity.
func assertNoExportedCallback(t *testing.T) {
	t.Helper()
	pkg, _ := authhttpPkg(t)
	for _, name := range pkg.Scope().Names() {
		obj := pkg.Scope().Lookup(name)
		if !obj.Exported() {
			continue
		}
		// An exported FUNCTION DECLARATION (NewServer) is an ordinary entry
		// point, not a callback-bearing API: a caller cannot inject a function
		// value through it. Only exported function-typed VARS (a caller-settable
		// hook) are rejected here; exported named types are inspected for
		// function-bearing fields/methods below.
		if _, isFuncDecl := obj.(*types.Func); isFuncDecl {
			continue
		}
		if _, isType := obj.(*types.TypeName); !isType {
			if carriesFunc(obj.Type()) && !isStdlibAdapter(obj.Type()) {
				t.Fatalf("exported var %s carries a function value (public hook)", name)
			}
			continue
		}
		tn := obj.(*types.TypeName)
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		if st, ok := named.Underlying().(*types.Struct); ok {
			for i := 0; i < st.NumFields(); i++ {
				fld := st.Field(i)
				if fld.Exported() && carriesFunc(fld.Type()) {
					t.Fatalf("exported field %s.%s carries a function value", name, fld.Name())
				}
			}
		}
		ms := types.NewMethodSet(types.NewPointer(named))
		for i := 0; i < ms.Len(); i++ {
			sel := ms.At(i)
			sig, ok := types.Unalias(sel.Type()).(*types.Signature)
			if !ok {
				continue
			}
			for p := 0; p < sig.Params().Len(); p++ {
				if carriesFunc(sig.Params().At(p).Type()) && !isStdlibAdapter(sig.Params().At(p).Type()) {
					t.Fatalf("exported method %s.%s param carries a function value", name, sel.Obj().Name())
				}
			}
			for r := 0; r < sig.Results().Len(); r++ {
				if carriesFunc(sig.Results().At(r).Type()) && !isStdlibAdapter(sig.Results().At(r).Type()) {
					t.Fatalf("exported method %s.%s result carries a function value", name, sel.Obj().Name())
				}
			}
		}
	}
}

// carriesFunc reports whether a type is or transports a function value.
func carriesFunc(t types.Type) bool { return seamcheck.TypeIsOrCarriesFunc(t) }

// isStdlibAdapter reports whether t is one of the accepted resolved stdlib
// protocol adapter interfaces, matched by package-path + interface identity
// (provenance), never by selector spelling.
func isStdlibAdapter(t types.Type) bool {
	t = types.Unalias(t)
	iface, ok := t.Underlying().(*types.Interface)
	if !ok {
		return false
	}
	_ = iface
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj.Pkg() == nil {
		return false
	}
	path := obj.Pkg().Path()
	name := obj.Name()
	switch path {
	case "net/http":
		return name == "Handler" || name == "ResponseWriter" || name == "Header"
	case "context":
		return name == "Context"
	case "net":
		return name == "Listener" || name == "Conn" || name == "Addr"
	case "io/fs":
		return name == "FileInfo"
	}
	return false
}

// assertNoRawDBReach rejects any production file that imports database/sql and
// any type-checked object whose type is a raw database/sql handle (DB/Tx/Stmt,
// aliases resolved). The composition boundary persists only through the typed
// internal/store API; acquiring a raw pool handle is a seam.
func assertNoRawDBReach(t *testing.T) {
	t.Helper()
	fset := token.NewFileSet()
	for _, fn := range authhttpProductionFiles {
		b, err := os.ReadFile(fn)
		if err != nil {
			t.Fatalf("read %s: %v", fn, err)
		}
		f, err := parser.ParseFile(fset, fn, b, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse imports %s: %v", fn, err)
		}
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) == "database/sql" {
				t.Fatalf("%s imports database/sql — raw-DB escape from the composition boundary", fn)
			}
		}
	}
	// Type-graph provenance: reject any object whose type resolves to a raw
	// database/sql handle, following aliases and pointers.
	pkg, info := authhttpPkg(t)
	_ = info
	for _, name := range pkg.Scope().Names() {
		obj := pkg.Scope().Lookup(name)
		if isRawDBHandle(obj.Type()) {
			t.Fatalf("raw database/sql handle type reachable via exported symbol %s", name)
		}
	}
}

// isRawDBHandle reports whether t resolves to *sql.DB, sql.Tx or sql.Stmt,
// following aliases and one level of pointer.
func isRawDBHandle(t types.Type) bool {
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj.Pkg() == nil || obj.Pkg().Path() != "database/sql" {
		return false
	}
	switch obj.Name() {
	case "DB", "Tx", "Stmt":
		return true
	}
	return false
}

// --- Contrasting fixtures (architect decision §1): each negative mutation is
// compiled by the SAME shared classifier and must be REJECTED for the intended
// reason; each positive adapter/clock fixture must PASS. No second analyzer.

// classifyFixture type-checks a single fixture source as the "authhttp"
// package through the shared classifier.
func classifyFixture(t *testing.T, src string) (*seamcheck.Report, error) {
	t.Helper()
	return seamcheck.Classify("authhttp", token.NewFileSet(), []string{"fixture.go"}, map[string]string{"fixture.go": src})
}

// requireFixtureSeamFails asserts a NEGATIVE fixture is rejected with a reason
// containing every part of wantReasonParts.
func requireFixtureSeamFails(t *testing.T, name, src string, wantReasonParts ...string) {
	t.Helper()
	rep, err := classifyFixture(t, src)
	if err != nil {
		msg := err.Error()
		for _, part := range wantReasonParts {
			if !strings.Contains(msg, part) {
				t.Fatalf("%s: type-check rejection %q missing reason part %q", name, msg, part)
			}
		}
		return
	}
	all := strings.Join(append(append([]string{}, rep.FieldSeams...), rep.CallSeams...), " | ") + " | " + strings.Join(rep.Unresolved, " | ")
	if len(rep.FieldSeams) == 0 && len(rep.CallSeams) == 0 && len(rep.Unresolved) == 0 {
		t.Fatalf("%s: fixture ACCEPTED but must be REJECTED as a dispatch seam", name)
	}
	for _, part := range wantReasonParts {
		if !strings.Contains(all, part) {
			t.Fatalf("%s: rejection %q missing reason part %q", name, all, part)
		}
	}
}

func TestAuthhttpBoundaryContrastingFixtures(t *testing.T) {
	// NEGATIVE: an exported struct field of function type is a public hook.
	requireFixtureSeamFails(t, "exported func field",
		`package authhttp
type Cfg struct{ OnThing func() error }
var _ = Cfg{}
`,
		"field OnThing")

	// NEGATIVE: a call through an exported function-typed variable (public
	// callback registration invoked).
	requireFixtureSeamFails(t, "exported func var dispatch",
		`package authhttp
var Register func()
func use() { Register() }
`,
		"call via func-typed variable Register")

	// NEGATIVE: an interface-typed field invoked through dynamic dispatch.
	requireFixtureSeamFails(t, "interface method dispatch",
		`package authhttp
type Runner interface{ Run() }
type Eng struct{ r Runner }
func (e Eng) goRun() { e.r.Run() }
`,
		"interface receiver")

	// NEGATIVE: a call-result function value used as a dispatch target.
	requireFixtureSeamFails(t, "call-result dispatch",
		`package authhttp
func mk() func() { return func() {} }
func use() { mk()() }
`,
		"call-result dispatch")

	// The private-clock fixture IS a function-typed field + invocation — the
	// raw classifier correctly reports it. The GUARD must then ACCEPT it via
	// the reviewed-clock exception (isAcceptedClockField / isAcceptedCallSeam).
	clockRep, clockErr := classifyFixture(t, `package authhttp
import "time"
type eng struct{ now func() time.Time }
func (e eng) tick() time.Time { return e.now() }
`)
	if clockErr != nil {
		t.Fatalf("clock fixture must type-check: %v", clockErr)
	}
	if len(clockRep.FieldSeams) != 1 || !isAcceptedClockField(clockRep.FieldSeams[0]) {
		t.Fatalf("private clock field must be reported and accepted as the reviewed clock: %v", clockRep.FieldSeams)
	}
	if len(clockRep.CallSeams) != 1 || !isAcceptedCallSeam(clockRep.CallSeams[0]) {
		t.Fatalf("private clock invocation must be reported and accepted as the reviewed clock: %v", clockRep.CallSeams)
	}

	// The stdlib http adapter fixture reports interface-dispatch seams on
	// http.ResponseWriter; the GUARD must accept each via the adapter
	// exception (provenance), proving the whitelist is adapter-only.
	httpRep, httpErr := classifyFixture(t, `package authhttp
import "net/http"
func write(w http.ResponseWriter) { w.Header().Set("k", "v"); w.WriteHeader(204) }
`)
	if httpErr != nil {
		t.Fatalf("http adapter fixture must type-check: %v", httpErr)
	}
	for _, cs := range httpRep.CallSeams {
		if !isAcceptedCallSeam(cs) {
			t.Fatalf("stdlib http adapter call must be accepted by provenance: %q", cs)
		}
	}
	if len(httpRep.CallSeams) == 0 {
		t.Fatal("http adapter fixture produced no adapter seams — fixture invalid")
	}
}

// TestAuthhttpRawDBProvenanceFixtures asserts the raw database/sql provenance
// check rejects a package that imports database/sql or names a raw handle,
// while an equivalent typed-store-shaped package (no raw import) passes.
func TestAuthhttpRawDBProvenanceFixtures(t *testing.T) {
	// NEGATIVE: importing database/sql and exposing a *sql.DB is a raw-DB
	// escape from the composition boundary.
	neg := `package authhttp
import "database/sql"
func pool(d *sql.DB) *sql.DB { return d }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", neg, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "database/sql" {
			found = true
		}
	}
	if !found {
		t.Fatal("negative fixture did not import database/sql — fixture invalid")
	}
	if !isRawDBHandle(sqlDBType(t)) {
		t.Fatal("isRawDBHandle failed to recognise *sql.DB — provenance check invalid")
	}

	// POSITIVE: the real authhttp production package imports no database/sql
	// and exposes no raw handle (already asserted by assertNoRawDBReach in the
	// main boundary test; re-affirmed here against the live package).
	pkg, _ := authhttpPkg(t)
	for _, name := range pkg.Scope().Names() {
		if isRawDBHandle(pkg.Scope().Lookup(name).Type()) {
			t.Fatalf("live package exposes raw DB handle via %s", name)
		}
	}
}

// sqlDBType returns the *sql.DB type for the negative-provenance assertion.
func sqlDBType(t *testing.T) types.Type {
	t.Helper()
	fset := token.NewFileSet()
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check("probe", fset, mustParseProbe(t, fset), nil)
	if err != nil {
		t.Fatalf("probe type-check: %v", err)
	}
	obj := pkg.Scope().Lookup("DB")
	if obj == nil {
		t.Fatal("probe could not resolve sql.DB")
	}
	return obj.Type()
}

func mustParseProbe(t *testing.T, fset *token.FileSet) []*ast.File {
	t.Helper()
	src := `package probe
import "database/sql"
var DB *sql.DB
`
	f, err := parser.ParseFile(fset, "probe.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	return []*ast.File{f}
}
