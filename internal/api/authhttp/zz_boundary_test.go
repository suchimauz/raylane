package authhttp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestAuthhttpCompositionBoundary guards the runtime composition boundary's
// narrow-surface invariant (ccv DECISION §3 / bui correction): the package
// exposes NO exported function-typed API (no arbitrary public callback or
// hook), and NO production file reaches for a raw store handle or SQL. The
// necessary typed stdlib net/http/io/context protocol interfaces and the
// PRIVATE constructor-injected clock fixtures are accepted adapter boundaries,
// not dispatch seams — so this guard checks the EXPORTED surface and the
// forbidden-literal reach, not the stdlib adapter method calls.
func TestAuthhttpCompositionBoundary(t *testing.T) {
	entries, _ := os.ReadDir(".")
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		srcBytes, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		src := string(srcBytes)
		// Scan the COMMENT-MASKED source (the same discipline as the primitive
		// guard): a banned literal inside a comment or the HTTP-method word
		// "DELETE (logout)" is not a SQL reach. Line and block comments are
		// stripped before the literal scan; string literals remain scanned.
		masked := stripCommentsForBoundary(src)
		for _, ban := range []string{"SELECT ", "INSERT ", "UPDATE ", "DELETE ", "PRAGMA ",
			"db.Query", "db.Exec", "BeginTx", ".DB(", "sql.Open", "sql.DB"} {
			if strings.Contains(masked, ban) {
				t.Fatalf("%s contains forbidden raw-DB/SQL form %q", name, ban)
			}
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, srcBytes, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		// No EXPORTED function-typed name: no public callback/hook can be
		// registered by a caller. (Unexported constructor-injected clocks are
		// private fixtures, allowed.)
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, sp := range gd.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if _, isFunc := vs.Type.(*ast.FuncType); isFunc {
					for _, n := range vs.Names {
						if ast.IsExported(n.Name) {
							t.Fatalf("%s exports function-typed var %s (public hook)", name, n.Name)
						}
					}
				}
			}
		}
	}
}

// stripCommentsForBoundary removes // line comments and /* */ block comments
// (preserving newlines and byte length is NOT required here — only that the
// banned literals are not matched inside comments). String and rune literals
// are left intact so a banned form inside a string still matches.
func stripCommentsForBoundary(src string) string {
	var out strings.Builder
	i := 0
	n := len(src)
	for i < n {
		// Line comment.
		if src[i] == '/' && i+1 < n && src[i+1] == '/' {
			for i < n && src[i] != '\n' {
				i++
			}
			continue
		}
		// Block comment.
		if src[i] == '/' && i+1 < n && src[i+1] == '*' {
			i += 2
			for i+1 < n && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			i += 2
			continue
		}
		out.WriteByte(src[i])
		i++
	}
	return out.String()
}
