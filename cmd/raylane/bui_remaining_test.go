package main

import (
	"os"
	"path/filepath"
	"testing"
)

// This independent probe asserts the original owner-path requirement, not
// current implementation behavior. Every object belongs to this test.
func TestBuiRemainingSocketDirectorySymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	ln, err := listenLocalSocket(link)
	if ln != nil {
		defer ln.Close()
	}
	st, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if err == nil || st.Mode().Perm() != 0755 {
		t.Fatalf("symlink path must be refused without modifying target: accepted=%t targetMode=%o err=%v", err == nil, st.Mode().Perm(), err)
	}
}
