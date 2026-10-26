package authhttp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/suchimauz/raylane/internal/seamcheck"
)

// These are the discriminating mutation tests for the runtime composition
// boundary (T008 G4). Each test copies the production sources to an isolated
// temp dir, injects ONE compiling mutation, and runs the SAME production
// discovery+analysis+policy path (guardViolations) the live guard uses. RED
// mutations are rejected for the intended cause; the real approved runtime is
// a positive control that stays clean.
//
// The point is that authorization is provenance-based: a new file, an
// arbitrary interface, a fake clock, a callback result, an alias/container
// callback — none is authorized by spelling, filename or hand-maintained list.

// productionSources are the maintained production files, read from disk via
// go/build discovery (LoadPackage), not a hard-coded list here. This slice is
// only used to COPY the package into an isolated temp dir for mutation tests;
// the guard itself always discovers via go/build.
var productionSources = []string{
	"bootstrap.go", "config.go", "csrf.go", "limiter.go",
	"requestid.go", "responses.go", "server.go", "session.go",
}

// copyProduction copies the production package into an isolated temp dir and
// returns it. The guard then discovers the files there with go/build.
func copyProduction(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, s := range productionSources {
		b, err := os.ReadFile(s)
		if err != nil {
			t.Fatalf("read %s: %v", s, err)
		}
		if err := os.WriteFile(filepath.Join(dir, s), b, 0644); err != nil {
			t.Fatalf("write %s: %v", s, err)
		}
	}
	return dir
}

// inject writes a mutation production file into the isolated package copy.
func inject(t *testing.T, dir, name, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0644); err != nil {
		t.Fatalf("inject %s: %v", name, err)
	}
}

// TestBoundaryPositiveControl confirms the real approved production package
// (isolated copy, no mutation) is accepted by the SAME path.
func TestBoundaryPositiveControl(t *testing.T) {
	requireNoViolations(t, copyProduction(t))
}

// TestBoundaryRejectsNewFileExportedHook reproduces the reviewer bypass: a NEW
// production file (not in any list) exporting a hook must be discovered and
// rejected. Discovery is go/build, so the new file is seen automatically.
func TestBoundaryRejectsNewFileExportedHook(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_new_production.go", `package authhttp

// ExportedBoundaryBypass exposes a callback through the exported API.
func ExportedBoundaryBypass(callback func() error) error { return callback() }
`)
	requireViolation(t, dir, "callback-exposure")
}

// TestBoundaryRejectsNewFileRawDB reproduces the QA raw-DB bypass: a NEW file
// reaching database/sql is discovered and rejected as a raw-DB escape.
func TestBoundaryRejectsNewFileRawDB(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_newprod_db.go", `package authhttp

import "database/sql"

// PublicHook is an exported escape; reachDB touches a raw *sql.DB.
var PublicHook func(string) error

func reachDB(db *sql.DB, q string) (int, error) {
	var n int
	err := db.QueryRow(q).Scan(&n)
	return n, err
}
`)
	requireViolation(t, dir, "raw-db-reach")
}

// TestBoundaryRejectsCallbackResult reproduces QA G4-b: an exported function
// whose RESULT is a callback must be checked (the param asymmetry defect).
func TestBoundaryRejectsCallbackResult(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_factory.go", `package authhttp

// QaPublicFactory returns a callback through the exported result.
func QaPublicFactory() func() error { return func() error { return nil } }
`)
	requireViolation(t, dir, "callback-exposure")
}

// TestBoundaryRejectsUnusedPublicParam: an exported function with an UNUSED
// callback param is still an exposure (a called-param seam does not cover an
// unused one).
func TestBoundaryRejectsUnusedPublicParam(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_unused_param.go", `package authhttp

// QaUnusedParam takes a callback it never invokes.
func QaUnusedParam(h func() error) {}
`)
	requireViolation(t, dir, "callback-exposure")
}

// TestBoundaryRejectsFakeClockNow reproduces QA G4-c clock spelling: a struct
// field merely NAMED "now" with a non-time signature is NOT one of the four
// reviewed clocks and must be rejected as an unauthorized dispatch.
func TestBoundaryRejectsFakeClockNow(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_fakeclock.go", `package authhttp

type qaFakeClock struct{ now func() int64 }

func (q *qaFakeClock) tick() int64 { return q.now() }
`)
	// q.now() is a func-value-call whose owner qaFakeClock is not a reviewed
	// clock; its field type is func() int64, not func() time.Time.
	requireViolation(t, dir, "dispatch")
}

// TestBoundaryRejectsArbitraryCloseInterface reproduces cah substring defect:
// an arbitrary local interface with a method named Close must NOT be
// authorized by method-name spelling; only the resolved stdlib adapters are.
func TestBoundaryRejectsArbitraryCloseInterface(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_closer.go", `package authhttp

type qaCloser interface{ Close() error }

func useCloser(c qaCloser) error { return c.Close() }
`)
	requireViolation(t, dir, "dispatch")
}

// TestBoundaryRejectsCloseEnoughInterface: the exact reviewer seam — an
// arbitrary CloseEnough interface dispatched on a listed file is rejected.
func TestBoundaryRejectsCloseEnoughInterface(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_closeenough.go", `package authhttp

type qaCloseEnough interface{ CloseEnough() error }

func drive(e qaCloseEnough) error { return e.CloseEnough() }
`)
	requireViolation(t, dir, "dispatch")
}

// TestBoundaryRejectsAliasCallback: a named func type / alias laundering a
// callback through the exported surface is still an exposure.
func TestBoundaryRejectsAliasCallback(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_alias.go", `package authhttp

// QaFn is a named callback type exported directly.
type QaFn func() error

// QaAlias exposes the callback under an alias.
var QaAlias QaFn
`)
	requireViolation(t, dir, "callback-exposure")
}

// TestBoundaryRejectsContainerCallback: callbacks in a map value and a slice
// reachable from the exported surface are exposures (container traversal).
func TestBoundaryRejectsContainerCallback(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_container.go", `package authhttp

// QaHandlers is an exported slice of callbacks.
var QaHandlers []func() error

// QaTable is an exported map whose VALUE is a callback.
var QaTable = map[string]func(){}
`)
	requireViolation(t, dir, "callback-exposure")
}

// TestBoundaryRejectsImportedRawDBProvider: a production file importing
// database/sql (an import-call reach) is a raw-DB escape even without an
// exported hook, isolating the rawDB cause from any coexisting PublicHook.
func TestBoundaryRejectsImportedRawDBProvider(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_importdb.go", `package authhttp

import "database/sql"

var qaDB *sql.DB

func ping() error { return qaDB.Ping() }
`)
	requireViolation(t, dir, "raw-db-reach")
}

// TestBoundaryRejectsSameNameReleaseImpostor: a local func-value named release
// NOT produced by the loginLimiter gate (the approved producer) is rejected.
func TestBoundaryRejectsSameNameReleaseImpostor(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_release_impostor.go", `package authhttp

func runImpostor() {
	release := func() {}
	defer release()
}
`)
	requireViolation(t, dir, "dispatch")
}

// TestBoundaryRejectsNestedContainerCallback: a callback reachable only
// through nested exported struct fields is still detected.
func TestBoundaryRejectsNestedContainerCallback(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_nested.go", `package authhttp

type QaOuter struct {
	Inner struct {
		Handler func() error
	}
}

var QaNested QaOuter
`)
	requireViolation(t, dir, "callback-exposure")
}

// TestBoundaryFailsClosedOnUnparseableFile: a production file that does not
// parse must fail CLOSED (the discovery/type-check path errors), never be
// silently accepted. This asserts the fail-closed behavior of the SAME
// discovery+analysis pipeline the guard invokes.
func TestBoundaryFailsClosedOnUnparseableFile(t *testing.T) {
	dir := copyProduction(t)
	inject(t, dir, "zz_broken.go", "package authhttp\nfunc Broken( {\n")
	if _, err := seamcheck.LoadPackage(dir); err == nil {
		t.Fatal("LoadPackage must fail closed on an unparseable production file")
	}
}
