// Package webui delivers the embedded production Vite bundle as the
// same-origin HTTPS application shell. It is deliberately independent of the
// authhttp package: the auth server mounts this handler at the exact root and
// the /assets/ subtree, and everything else keeps the settled generic-403
// behavior.
//
// Security contract (T009):
//   - Exact root GET/HEAD only serves the shell; there is NO SPA catch-all.
//   - /assets/{name} serves ONLY build artifacts the produced index.html
//     actually references (its <script src> / <link href> asset URLs). This is
//     the declared membership of the build — NOT any file under assets/ whose
//     extension happens to look acceptable. A stray unreferenced file, even a
//     content-hashed .js/.css, is rejected. Source maps, hidden files,
//     config, database, cert/key material and any unexpected file are rejected
//     EVEN IF they happen to sit below assets/. There are no listings.
//   - Bundle completeness is validated ONCE at startup (index present and
//     every asset it references resolvable); an incomplete bundle fails
//     closed with one actionable error BEFORE the listener is bound or
//     readiness advertised — never a successful broken panel.
//   - Hostile paths (traversal, backslash, NUL, hostile encodings) are
//     rejected BEFORE any normalizing fallback could make them valid; a
//     rejected path never redirects to an allowed file.
//   - MIME is derived from a server-owned accept map, never from the request
//     URL or sniffing. Only content-hashed referenced assets get long
//     immutable caching; the shell and errors are no-store.
//   - Strict CSP (self-only script/style/connect, object/base/frame none),
//     nosniff and no-referrer; no unsafe-inline/unsafe-eval.
package webui

import (
	"encoding/json"
	"errors"
	"fmt"
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

// Handler serves the embedded shell and its build-referenced assets.
type Handler struct {
	fsys fs.FS
	// assets is the declared membership of THIS build: every asset file the
	// produced index.html references, taken from the Vite build manifest. An
	// asset is served only if its name is in this set — not merely because its
	// extension looks acceptable. Never nil after New succeeds.
	assets map[string]struct{}
}

// New returns a Handler serving the given filesystem (normally
// webui.DistFS()). It validates the bundle ONCE, up front, before any
// request is served or any listener bound: index.html must be present and
// every asset the build references (per the Vite manifest) must resolve in
// the filesystem. An incomplete bundle is a hard error with one actionable
// message — the process must fail closed, not serve a broken panel.
func New(fsys fs.FS) (*Handler, error) {
	assets, err := referencedAssets(fsys)
	if err != nil {
		return nil, err
	}
	return &Handler{fsys: fsys, assets: assets}, nil
}

// referencedAssets derives the servable asset set from the Vite build
// manifest and validates that index.html plus every referenced asset exists.
// The manifest is the tool-generated record of what this build emitted and
// the index references; we do not guess membership from extensions or
// hash-shaped names.
func referencedAssets(fsys fs.FS) (map[string]struct{}, error) {
	manifest, err := fs.ReadFile(fsys, ".vite/manifest.json")
	if err != nil {
		return nil, errors.New("frontend bundle incomplete: missing build manifest (.vite/manifest.json); run `npm --prefix web run build`")
	}
	var entries map[string]struct {
		File string   `json:"file"`
		CSS  []string `json:"css"`
	}
	if err := json.Unmarshal(manifest, &entries); err != nil {
		return nil, fmt.Errorf("frontend bundle invalid: build manifest is not parseable JSON (run `npm --prefix web run build`): %w", err)
	}
	assets := make(map[string]struct{})
	add := func(rel string) error {
		// Manifest file/css values are bundle-relative (e.g. "assets/x.js");
		// the servable name is the single basename under assets/.
		name, err := sanitizeAssetName(path.Base(rel))
		if err != nil {
			return fmt.Errorf("frontend bundle invalid: manifest references an unsafe asset path %q: %w", rel, err)
		}
		// Wrong-kind entries are rejected BEFORE the bundle is accepted: a
		// directory (or any non-regular special file) at a manifest-declared
		// asset path is an incomplete/corrupt bundle, not a servable artifact.
		// fs.Stat alone is not sufficient — it succeeds on a directory. We
		// check the file kind here, up front, so a wrong-kind entry fails
		// closed at startup without ever being opened (a pipe/device would
		// otherwise block or misbehave on read).
		info, err := fs.Stat(fsys, "assets/"+name)
		if err != nil {
			return fmt.Errorf("frontend bundle incomplete: missing referenced asset assets/%s; run `npm --prefix web run build`", name)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("frontend bundle invalid: referenced asset assets/%s is a %s, not a regular file; run `npm --prefix web run build`", name, fileKind(info.Mode()))
		}
		assets[name] = struct{}{}
		return nil
	}
	for _, e := range entries {
		if err := add(e.File); err != nil {
			return nil, err
		}
		for _, css := range e.CSS {
			if err := add(css); err != nil {
				return nil, err
			}
		}
	}
	if len(assets) == 0 {
		return nil, errors.New("frontend bundle invalid: build manifest declares no assets; run `npm --prefix web run build`")
	}
	// index.html must be present AND a regular file: a directory (or special
	// file) at the shell path is a corrupt bundle, rejected fail-closed before
	// any request is served.
	info, err := fs.Stat(fsys, "index.html")
	if err != nil {
		return nil, errors.New("frontend bundle incomplete: missing index.html; run `npm --prefix web run build`")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("frontend bundle invalid: index.html is a %s, not a regular file; run `npm --prefix web run build`", fileKind(info.Mode()))
	}
	return assets, nil
}

// fileKind returns a short human-readable name for a non-regular file mode,
// for an actionable startup error (e.g. "directory", "symlink", "pipe").
func fileKind(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return "directory"
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m&fs.ModeNamedPipe != 0:
		return "named pipe"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeDevice != 0:
		return "device"
	default:
		return "non-regular file"
	}
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

// serveAsset serves a single build-referenced asset. Hostile, non-allowlisted
// and UNREFERENCED paths are rejected with a plain 404 (NOT redirected to a
// file, NOT a listing, NOT HTML): only an artifact the produced index.html
// actually references is servable. A referenced content-hashed generated
// asset is immutable, so it gets a long cache; everything rejected is no-store.
func (h *Handler) serveAsset(w http.ResponseWriter, r *http.Request, name string) bool {
	clean, err := sanitizeAssetName(name)
	if err != nil {
		// Hostile or non-allowlisted: a plain not-found, indistinguishable
		// from an absent file. No oracle, no listing, no HTML.
		writeNotFound(w)
		return true // handled (rejected); caller must not fall through to 403 HTML
	}
	// Membership: the asset must be one THIS build declared (Vite manifest). A
	// stray unreferenced file with an allowlisted extension/hash shape is not
	// servable.
	if _, referenced := h.assets[clean]; !referenced {
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
