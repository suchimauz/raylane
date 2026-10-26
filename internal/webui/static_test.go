package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// fixtureFS is a minimal embedded-bundle shape: the shell, the Vite build
// manifest that declares this build's referenced asset membership, the two
// referenced content-hashed assets, plus the kinds of files that must be
// rejected even though they sit below assets/.
func fixtureFS() fs.FS {
	return fstest.MapFS{
		"index.html":                &fstest.MapFile{Data: []byte("<!doctype html><div id=root></div>")},
		".vite/manifest.json":       &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/index-D0S6vb5b.js","css":["assets/index-D3b3cTyl.css"]}}`)},
		"assets/index-D0S6vb5b.js":  &fstest.MapFile{Data: []byte("console.log(1)")},
		"assets/index-D3b3cTyl.css": &fstest.MapFile{Data: []byte("body{margin:0}")},
		// Must be rejected even though present below assets/ (not referenced):
		"assets/index-D0S6vb5b.js.map":  &fstest.MapFile{Data: []byte("{}")},
		"assets/config.yaml":            &fstest.MapFile{Data: []byte("secret: 1")},
		"assets/.hidden":                &fstest.MapFile{Data: []byte("x")},
		"assets/app.db":                 &fstest.MapFile{Data: []byte("SQLite")},
		"assets/private.key":            &fstest.MapFile{Data: []byte("PRIVATE KEY")},
		"assets/notes.txt":              &fstest.MapFile{Data: []byte("hi")},
		"assets/stray-unreferenced.js":  &fstest.MapFile{Data: []byte("window.__strayJs=1")},
		"assets/stray-unreferenced.css": &fstest.MapFile{Data: []byte("body{color:red}")},
		"assets/stray-H4shL00king.js":   &fstest.MapFile{Data: []byte("window.__strayHash=1")},
	}
}

// mustNew builds a Handler from a valid fixture or fails the test.
func mustNew(t *testing.T, fsys fs.FS) *Handler {
	t.Helper()
	h, err := New(fsys)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func do(h *Handler, method, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	ok := h.ServeHTTP(rec, req)
	if !ok {
		rec.Code = http.StatusTeapot // sentinel so tests can detect fall-through
	}
	return rec
}

func TestShellServedAtExactRootOnly(t *testing.T) {
	h := mustNew(t, fixtureFS())

	for _, target := range []string{"/", "/?x=1"} {
		rec := do(h, http.MethodGet, target)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status=%d, want 200", target, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Fatalf("GET %s: Content-Type=%q", target, ct)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("GET %s: Cache-Control=%q, want no-store", target, cc)
		}
		csp := rec.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatalf("GET %s: missing CSP", target)
		}
		for _, banned := range []string{"unsafe-inline", "unsafe-eval", "data:", "http://", "https://"} {
			if strings.Contains(csp, banned) {
				t.Fatalf("GET %s: CSP contains banned %q: %s", target, banned, csp)
			}
		}
		for _, want := range []string{"script-src 'self'", "style-src 'self'", "connect-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, want) {
				t.Fatalf("GET %s: CSP missing %q: %s", target, want, csp)
			}
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("GET %s: missing nosniff", target)
		}
		if rec.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("GET %s: missing no-referrer", target)
		}
		if rec.Body.String() != "<!doctype html><div id=root></div>" {
			t.Fatalf("GET %s: unexpected body %q", target, rec.Body.String())
		}
	}

	// HEAD returns headers with an empty body.
	rec := do(h, http.MethodHead, "/")
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD /: status=%d bodylen=%d", rec.Code, rec.Body.Len())
	}

	// Sub-paths of root are NOT the shell (no SPA catch-all): the handler must
	// decline so the caller can answer the generic 403.
	for _, target := range []string{"/index.html", "/settings", "/login", "/a/b", "/assets"} {
		if rec := do(h, http.MethodGet, target); rec.Code != http.StatusTeapot {
			t.Fatalf("GET %s: handler served it (status=%d); want fall-through (no SPA catch-all)", target, rec.Code)
		}
	}

	// Non-read methods are declined (shell/assets are read-only).
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		if rec := do(h, m, "/"); rec.Code != http.StatusTeapot {
			t.Fatalf("%s /: status=%d; want fall-through", m, rec.Code)
		}
	}
}

func TestAllowlistedAssetServedWithImmutableCache(t *testing.T) {
	h := mustNew(t, fixtureFS())
	rec := do(h, http.MethodGet, "/assets/index-D0S6vb5b.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Fatalf("Content-Type=%q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Fatalf("Cache-Control=%q, want immutable content-hash caching", cc)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("missing CSP on asset")
	}
	if rec.Body.String() != "console.log(1)" {
		t.Fatalf("body=%q", rec.Body.String())
	}

	css := do(h, http.MethodGet, "/assets/index-D3b3cTyl.css")
	if css.Header().Get("Content-Type") != "text/css; charset=utf-8" {
		t.Fatalf("css Content-Type=%q", css.Header().Get("Content-Type"))
	}
}

func TestDisallowedUnderAssetsRejected(t *testing.T) {
	h := mustNew(t, fixtureFS())
	// Each of these EXISTS below assets/ but must be rejected by the allowlist
	// with a plain text 404 — never HTML, never a listing, never served.
	cases := []string{
		"/assets/index-D0S6vb5b.js.map", // source map
		"/assets/config.yaml",           // config
		"/assets/app.db",                // database
		"/assets/private.key",           // key material
		"/assets/notes.txt",             // unexpected extension
		"/assets/.hidden",               // hidden file
		"/assets/secret.pem",            // cert, absent anyway
	}
	for _, target := range cases {
		rec := do(h, http.MethodGet, target)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s: status=%d, want 404 (allowlist reject)", target, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
			t.Fatalf("GET %s: Content-Type=%q, want text/plain (never HTML)", target, ct)
		}
		if body := rec.Body.String(); strings.Contains(body, "<") || strings.Contains(body, "root") {
			t.Fatalf("GET %s: body looks like HTML/markup: %q", target, body)
		}
	}
}

func TestHostilePathsRejectedBeforeNormalization(t *testing.T) {
	h := mustNew(t, fixtureFS())
	// None of these may serve a file, redirect, or fall through to HTML; each
	// is a plain 404. Encoded traversal and dot-segments are rejected on the
	// raw segment before any normalizing fallback.
	cases := []string{
		"/assets/..%2f..%2findex.html",
		"/assets/%2e%2e/%2e%2e/index.html",
		"/assets/..\\..\\index.html",
		"/assets/..",
		"/assets/.",
		"/assets/a%00.js",
		"/assets/%2ehidden",
		"/assets/sub/dir/index-D0S6vb5b.js",
		"/assets/a%2fb",
	}
	for _, target := range cases {
		rec := do(h, http.MethodGet, target)
		if rec.Code == http.StatusOK {
			t.Fatalf("GET %s: served content (status 200); must be rejected", target)
		}
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s: status=%d, want 404 (reject, not fall-through HTML)", target, rec.Code)
		}
	}
}

func TestUnknownAssetIs404Not403OrHtml(t *testing.T) {
	h := mustNew(t, fixtureFS())
	rec := do(h, http.MethodGet, "/assets/does-not-exist-D0S6vb5b.js")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", rec.Code)
	}
}

// TestUnreferencedAllowlistedAssetRejected (V4-T009-STATIC-ARTIFACT-MEMBERSHIP):
// a file under assets/ that this build did NOT reference — even one with an
// allowlisted extension and a content-hash-looking name — must be a plain 404,
// never served, never given immutable-success caching, and must not leak its
// canary body. Membership comes from the build manifest, not the extension.
func TestUnreferencedAllowlistedAssetRejected(t *testing.T) {
	h := mustNew(t, fixtureFS())
	for _, target := range []string{
		"/assets/stray-unreferenced.js",
		"/assets/stray-unreferenced.css",
		"/assets/stray-H4shL00king.js", // hash-shaped but NOT referenced
	} {
		rec := do(h, http.MethodGet, target)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s: status=%d, want 404 (unreferenced, not servable)", target, rec.Code)
		}
		if body := rec.Body.String(); strings.Contains(body, "stray") || strings.Contains(body, "__stray") {
			t.Fatalf("GET %s: leaked unreferenced canary body %q", target, body)
		}
		if cc := rec.Header().Get("Cache-Control"); cc == "public, max-age=31536000, immutable" {
			t.Fatalf("GET %s: unreferenced file got immutable-success caching", target)
		}
	}
	// Sanity: the REFERENCED assets still succeed with immutable caching.
	if rec := do(h, http.MethodGet, "/assets/index-D0S6vb5b.js"); rec.Code != http.StatusOK {
		t.Fatalf("referenced JS must still serve: status=%d", rec.Code)
	}
}

// TestIncompleteBundleFailsClosed (V4-T009-INCOMPLETE-BUNDLE-STARTUP): an
// index/manifest that references an asset absent from the filesystem must make
// New fail with one actionable error — before any listener is bound — never a
// successful broken shell. A manifest declaring nothing, or a missing manifest,
// also fails closed.
func TestIncompleteBundleFailsClosed(t *testing.T) {
	cases := map[string]fs.FS{
		"missing referenced js": fstest.MapFS{
			"index.html":          &fstest.MapFile{Data: []byte("<!doctype html>")},
			".vite/manifest.json": &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/gone-D0S6vb5b.js"}}`)},
		},
		"missing referenced css": fstest.MapFS{
			"index.html":               &fstest.MapFile{Data: []byte("<!doctype html>")},
			".vite/manifest.json":      &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/index-D0S6vb5b.js","css":["assets/gone-D3b3cTyl.css"]}}`)},
			"assets/index-D0S6vb5b.js": &fstest.MapFile{Data: []byte("x")},
		},
		"missing manifest": fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<!doctype html>")},
		},
		"missing index": fstest.MapFS{
			".vite/manifest.json":      &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/index-D0S6vb5b.js"}}`)},
			"assets/index-D0S6vb5b.js": &fstest.MapFile{Data: []byte("x")},
		},
		"empty membership": fstest.MapFS{
			"index.html":          &fstest.MapFile{Data: []byte("<!doctype html>")},
			".vite/manifest.json": &fstest.MapFile{Data: []byte(`{}`)},
		},
		"unparseable manifest": fstest.MapFS{
			"index.html":          &fstest.MapFile{Data: []byte("<!doctype html>")},
			".vite/manifest.json": &fstest.MapFile{Data: []byte(`{not json`)},
		},
	}
	for name, fsys := range cases {
		if _, err := New(fsys); err == nil {
			t.Fatalf("%s: New succeeded; want fail-closed error", name)
		} else if !strings.Contains(err.Error(), "npm --prefix web run build") {
			t.Fatalf("%s: error not actionable: %v", name, err)
		}
	}
}
