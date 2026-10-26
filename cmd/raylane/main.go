// Command raylane is the Raylane control-plane entry point.
//
// T002 scope: this is an inert build scaffold. It performs no network I/O, it
// opens no listeners, it touches no files outside an explicitly requested
// configuration path, and it requires no privileges. The behaviour below only
// proves that the pinned toolchain builds and that argument and configuration
// handling fails safely.
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

// run dispatches the runnable subcommands first; when args do not name one,
// the scaffold flag handling below keeps --version/--config behaviour and
// exit codes exactly intact.
func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if code, ok := dispatchCommands(args, stdout, stderr, getenv); ok {
		return code
	}
	fs := flag.NewFlagSet("raylane", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the build version and exit")
	configPath := fs.String("config", "", "path to the Raylane configuration file")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "raylane %s — Raylane control plane (build scaffold)\n\n", Version)
		fmt.Fprintf(stderr, "Usage:\n  raylane [--version] [--config <path>]\n\nFlags:\n")
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
		return emit(stdout, info{Name: "raylane", Version: Version, Role: "control-plane", Status: "scaffold"})
	}

	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "raylane: unsupported argument %q\n", fs.Arg(0))
		fs.Usage()
		return 2
	}

	if *configPath != "" {
		// Reading a configuration is not implemented in this scaffold. The
		// path is checked so that a missing or unreadable file is reported
		// instead of being silently ignored, and nothing is created.
		if err := checkReadable(*configPath); err != nil {
			fmt.Fprintf(stderr, "raylane: %v\n", err)
			return 1
		}
		fmt.Fprintf(stderr, "raylane: configuration handling is not implemented in this scaffold (%s)\n", *configPath)
		return 1
	}

	return emit(stdout, info{Name: "raylane", Version: Version, Role: "control-plane", Status: "scaffold"})
}

// checkReadable reports why a configuration path cannot be used. It never
// creates, moves or modifies the path.
func checkReadable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("configuration file %q does not exist", path)
		}
		return fmt.Errorf("configuration file %q cannot be read: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("configuration path %q is a directory", path)
	}
	return nil
}

// emit writes one machine-readable line describing the running binary.
func emit(w io.Writer, i info) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(i); err != nil {
		fmt.Fprintf(os.Stderr, "raylane: %v\n", err)
		return 1
	}
	return 0
}
