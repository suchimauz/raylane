// Command raylane-net is the restricted privileged helper of Raylane.
//
// T002 scope: this is an inert build scaffold. The helper does not perform
// network operations, does not load kernel modules or rulesets, does not spawn
// engines and does not require any privilege to run. It states its intended
// role and refuses to act without an explicit, validated manifest.
//
// The real helper contract lives in
// specs/001-selected-connections/contracts/network-agent.md: helper-owned
// paths only, no traversal or symlink escape, no arbitrary executable,
// environment or command text, and no trust in the control plane.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	// The SQLite driver selected in packaging/versions.lock §4. It is linked in
	// here so that the pinned module stays part of the build list and the
	// closure is proven by the compiler. No storage behaviour is implemented
	// in this scaffold: the driver is registered but never opened.
	_ "modernc.org/sqlite"
)

// Version is the scaffold version. Release versioning is decided in T037.
const Version = "0.0.0-scaffold"

type info struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Role    string `json:"role"`
	Status  string `json:"status"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raylane-net", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the build version and exit")
	manifest := fs.String("manifest", "", "path to the validated helper manifest to act on")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "raylane-net %s — Raylane restricted helper (build scaffold)\n\n", Version)
		fmt.Fprintf(stderr, "Usage:\n  raylane-net [--version] [--manifest <path>]\n\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		// flag already reported the problem on stderr.
		return 2
	}

	if *showVersion {
		return emit(stdout, info{Name: "raylane-net", Version: Version, Role: "restricted-helper", Status: "scaffold"})
	}

	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "raylane-net: unsupported argument %q\n", fs.Arg(0))
		fs.Usage()
		return 2
	}

	if *manifest != "" {
		// Acting on a manifest is not implemented in this scaffold. The path
		// is checked so that a missing or unreadable file is reported instead
		// of being silently ignored, and nothing is created.
		if err := checkReadable(*manifest); err != nil {
			fmt.Fprintf(stderr, "raylane-net: %v\n", err)
			return 1
		}
		fmt.Fprintf(stderr, "raylane-net: manifest handling is not implemented in this scaffold (%s)\n", *manifest)
		return 1
	}

	return emit(stdout, info{Name: "raylane-net", Version: Version, Role: "restricted-helper", Status: "scaffold"})
}

// checkReadable reports why a manifest path cannot be used. It never creates,
// moves or modifies the path.
func checkReadable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("manifest file %q does not exist", path)
		}
		return fmt.Errorf("manifest file %q cannot be read: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("manifest path %q is a directory", path)
	}
	return nil
}

// emit writes one machine-readable line describing the running binary.
func emit(w io.Writer, i info) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(i); err != nil {
		fmt.Fprintf(os.Stderr, "raylane-net: %v\n", err)
		return 1
	}
	return 0
}
