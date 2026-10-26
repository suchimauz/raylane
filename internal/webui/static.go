// Package webui delivers the embedded production Vite bundle as the
// same-origin HTTPS application shell. It is deliberately independent of the
// authhttp package: the auth server mounts this handler at the exact root and
// the /assets/ subtree, and everything else keeps the settled generic-403
// behavior.
//
// Security contract (T009):
//   - Exact root GET/HEAD only serves the shell; there is NO SPA catch-all.
//   - /assets/{name} serves ONLY entries on an explicit allowlist of
//     content-hashed generated asset types (.js/.css and, when present,
//     needed image/font types). Source maps, hidden files, config, database,
//     cert/key material and any unexpected file are rejected EVEN IF they
//     happen to sit below assets/. There are no directory listings.
//   - Hostile paths (traversal, backslash, NUL, hostile encodings) are
//     rejected BEFORE any normalizing fallback could make them valid; a
//     rejected path never redirects to an allowed file.
//   - MIME is derived from a server-owned accept map, never from the request
//     URL or sniffing. Only content-hashed assets get long immutable caching;
//     the shell and errors are no-store.
//   - Strict CSP (self-only script/style/connect, object/base/frame none),
//     nosniff and no-referrer; no unsafe-inline/unsafe-eval.
package webui

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// assetTypes maps an accepted asset extension to its canonical MIME type. It
// is the complete allowlist: a file under assets/ is served only if its
// (lowercased) extension is present here. Unknown extensions, source maps and
// hidden/source/config/secret files are NOT in this map and are rejected.
var assetTypes = map[string]string{
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".webp":  "image/webp",
	".svg":   "image/svg+xml",
	".ico":   "image/x-icon",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
	".otf":   "font/otf",
}

const (
	// contentSecurityPolicy is strict and self-only. No unsafe-inline or
	// unsafe-eval: the Vite bundle is external modules + external CSS.
	contentSecurityPolicy = "default-src 'none'; " +
		"script-src 'self'; " +
		"style-src 'self'; " +
		"connect-src 'self'; " +
		"img-src 'self'; " +
		"font-src 'self'; " +
		"object-src 'none'; " +
		"base-uri 'none'; " +
		"frame-ancestors 'none'; " +
		"form-action 'self'"
)

// Handler serves the embedded shell and its allowlisted assets.
type Handler struct {
	fsys fs.FS
}

// New returns a Handler serving the given filesystem (normally webui.DistFS()).
func New(fsys fs.FS) *Handler {
	return &Handler{fsys: fsys}
}

// ServeHTTP serves only the exact root (shell) and /assets/{name} (allowlisted
// content-hashed assets). It returns ok=false for anything it does not serve,
// so the caller can fall through to the settled generic 403 (no existence
// oracle, no HTML for unknown paths).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (ok bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// The shell and assets are read-only; other methods are not ours.
		return false
	}
	p := r.URL.EscapedPath()
	switch {
	case p == "/":
		return h.serveShell(w, r)
	case strings.HasPrefix(p, "/assets/"):
		return h.serveAsset(w, r, strings.TrimPrefix(p, "/assets/"))
	default:
		return false
	}
}

// serveShell serves the exact root: the shell HTML with no-store caching and
// the strict security headers.
func (h *Handler) serveShell(w http.ResponseWriter, r *http.Request) bool {
	body, err := fs.ReadFile(h.fsys, "index.html")
	if err != nil {
		return false
	}
	setSecurityHeaders(w)
	// The shell is dynamic per release and must never be cached by an
	// intermediary: no-store, like every management response.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return true
}

// serveAsset serves a single allowlisted asset. Hostile and non-allowlisted
// paths are rejected with a plain 404 (NOT redirected to a file, NOT a
// listing, NOT HTML). Content-hashed generated assets are immutable, so they
// get a long cache; everything else here is still validated against the
// allowlist before caching is even considered.
func (h *Handler) serveAsset(w http.ResponseWriter, r *http.Request, name string) bool {
	clean, err := sanitizeAssetName(name)
	if err != nil {
		// Hostile or non-allowlisted: a plain not-found, indistinguishable
		// from an absent file. No oracle, no listing, no HTML.
		writeNotFound(w)
		return true // handled (rejected); caller must not fall through to 403 HTML
	}
	// Validate the entry exists AND is a real file in the embedded bundle.
	info, err := fs.Stat(h.fsys, path.Join("assets", clean))
	if err != nil || info.IsDir() {
		writeNotFound(w)
		return true
	}
	ext := strings.ToLower(path.Ext(clean))
	mime, allowed := assetTypes[ext]
	if !allowed {
		writeNotFound(w)
		return true
	}
	body, err := fs.ReadFile(h.fsys, path.Join("assets", clean))
	if err != nil {
		writeNotFound(w)
		return true
	}
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", mime)
	// Only a content-hashed filename (a stable build artifact with a hash
	// segment) is given immutable caching. Vite emits `name-HASH.ext`; a file
	// without a hash segment is not treated as immutable.
	if hasContentHash(clean) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return true
}

// sanitizeAssetName validates a single asset path segment before any
// normalization could make a hostile path valid. It rejects traversal,
// backslashes, NUL bytes, empty/hidden segments, anything that is not a plain
// basename, and any extension outside the allowlist. The returned string is a
// safe single path segment (no separators).
func sanitizeAssetName(raw string) (string, error) {
	// Reject the obviously hostile before decoding/trimming: NUL, backslash
	// (a Windows separator), and any "." segment. These are checked on the raw
	// input so no normalizing fallback can rescue them.
	if strings.ContainsRune(raw, 0) || strings.Contains(raw, `\`) {
		return "", errors.New("hostile path")
	}
	// URL-unescape is already done by EscapedPath→Path; operate on the decoded
	// form. Reject any residual encoded separator or dot-segment.
	if strings.Contains(raw, "/") || strings.Contains(raw, "%") {
		return "", errors.New("not a single segment")
	}
	// Reject hidden files and the traversal/dot segments explicitly.
	base := path.Base(raw)
	if base == "." || base == ".." || strings.HasPrefix(base, ".") {
		return "", errors.New("hidden or traversal segment")
	}
	if base != raw {
		return "", errors.New("not a plain basename")
	}
	ext := strings.ToLower(path.Ext(base))
	if _, allowed := assetTypes[ext]; !allowed {
		return "", errors.New("extension not allowlisted")
	}
	// The name must be a single safe filename: no remaining separators,
	// no leading dot, ASCII-safe characters only (build artifacts are ASCII).
	for _, c := range base {
		if c == '/' || c < 0x21 || c > 0x7e {
			return "", errors.New("unsafe character")
		}
	}
	return base, nil
}

// hasContentHash reports whether a build-artifact filename carries a Vite
// content hash segment (e.g. `index-D0S6vb5b.js`). Only these are immutable.
func hasContentHash(name string) bool {
	stem := strings.TrimSuffix(name, path.Ext(name))
	// A hashed artifact has a `-<hash>` tail; the hash is alphanumeric. We do
	// not require a specific length, only that a `-` separator introduces a
	// trailing hash-like token with no path separators.
	i := strings.LastIndex(stem, "-")
	if i <= 0 || i == len(stem)-1 {
		return false
	}
	tail := stem[i+1:]
	for _, c := range tail {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// setSecurityHeaders stamps the strict, self-only security policy on every
// delivered shell/asset response.
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// writeNotFound answers a rejected/missing asset with a plain text 404 (never
// HTML, never a listing, never a redirect to an allowed file).
func writeNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "not found")
}
