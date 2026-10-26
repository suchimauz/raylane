// Package webui embeds the production Vite bundle (web/dist) into the Go
// binary so the single Raylane process serves the same-origin HTTPS shell.
//
// T009 build dependency: `go:embed dist` makes the Go build FAIL at compile
// time when the bundle is absent. The canonical clean build always runs the
// frontend first (`npm --prefix web run build`), so a compile failure here is
// a clear signal that the bundle was not produced — never a silent fallback.
// The dist/ directory is build output and is never committed.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// DistFS returns the embedded production bundle as a rooted filesystem whose
// root is the dist directory (so "index.html" and "assets/…" are top-level).
func DistFS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// Unreachable: the pattern is a fixed subdirectory of the embed.
		panic(err)
	}
	return sub
}
