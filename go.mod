// Raylane — Go module for the control-plane and the restricted helper.
//
// Dependency pins are exact and come from packaging/versions.lock (T001, G1):
//   - toolchain: go1.27.3 (§2), matching the Xray-core v26.10.21 baseline (go 1.27)
//   - SQLite driver: modernc.org/sqlite v1.61.0 (§4), pure Go, no cgo
//
// No version range, no "latest", no indirect dependency left unpinned: the
// indirect requirements below are the exact versions selected by
// modernc.org/sqlite v1.61.0's own go.mod.
module github.com/suchimauz/raylane

go 1.27.3

require (
	golang.org/x/crypto v0.58.0
	modernc.org/sqlite v1.61.0
)

require (
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.49.0 // indirect
	modernc.org/libc v1.79.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
