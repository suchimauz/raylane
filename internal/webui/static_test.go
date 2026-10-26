package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// fixtureFS is a minimal embedded-bundle shape: the shell plus a content-hashed
// JS asset, a content-hashed CSS asset, and the kinds of files the allowlist
// must reject even though they sit below assets/.
func fixtureFS() fs.FS {
	return fstest.MapFS{
		"index.html":                &fstest.MapFile{Data: []byte("<!doctype html><div id=root></div>")},
		"assets/index-D0S6vb5b.js":  &fstest.MapFile{Data: []byte("console.log(1)")},
		"assets/index-D3b3cTyl.css": &fstest.MapFile{Data: []byte("body{margin:0}")},
		// Must be rejected even though present below assets/:
		"assets/index-D0S6vb5b.js.map": &fstest.MapFile{Data: []byte("{}")},
		"assets/config.yaml":           &fstest.MapFile{Data: []byte("secret: 1")},
		"assets/.hidden":               &fstest.MapFile{Data: []byte("x")},
		"assets/app.db":                &fstest.MapFile{Data: []byte("SQLite")},
		"assets/private.key":           &fstest.MapFile{Data: []byte("PRIVATE KEY")},
		"assets/notes.txt":             &fstest.MapFile{Data: []byte("hi")},
	}
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
	h := New(fixtureFS())

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
	h := New(fixtureFS())
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
	h := New(fixtureFS())
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
	h := New(fixtureFS())
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
	h := New(fixtureFS())
	rec := do(h, http.MethodGet, "/assets/does-not-exist-D0S6vb5b.js")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", rec.Code)
	}
}
