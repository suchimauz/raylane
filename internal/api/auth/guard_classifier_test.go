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
	"go/token"
	"go/types"

	"github.com/suchimauz/raylane/internal/seamcheck"
)

// The classifier itself is the ONE maintained pipeline, extracted to
// internal/seamcheck so the primitive, facade and runtime composition packages
// are all checked by the same go/types code (architect decision §1: reuse the
// existing classifier, no second interpreter). This file keeps the original
// names as thin delegations so every accepted guard and fixture test below
// keeps compiling and asserting the SAME semantics — no behaviour change.

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

// seamReport is the classifier outcome over one type-checked package. It is
// the same shape as seamcheck.Report, kept as a distinct name for the
// in-package tests.
type seamReport struct {
	fieldSeams  []string
	callSeams   []string
	safeMethods int
	unresolved  []string
}

// classifySources type-checks the sources as a single "auth" package and
// classifies dispatch seams, failing closed on any parse/type-check error.
func classifySources(fset *token.FileSet, fileNames []string, srcs map[string]string) (*seamReport, error) {
	r, err := seamcheck.Classify("auth", fset, fileNames, srcs)
	if err != nil {
		return nil, err
	}
	return &seamReport{
		fieldSeams:  r.FieldSeams,
		callSeams:   r.CallSeams,
		safeMethods: r.SafeMethods,
		unresolved:  r.Unresolved,
	}, nil
}

// typeIsOrCarriesFunc is the accepted primitive spelling, delegating to the
// shared container-of-function predicate.
func typeIsOrCarriesFunc(t types.Type) bool { return seamcheck.TypeIsOrCarriesFunc(t) }
