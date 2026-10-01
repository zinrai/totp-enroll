package main

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
)

// pam_google_authenticator reads this file at every login. A layout it does not
// understand locks the user out, and the seed is the only second factor there is
func TestSeedFileIsWhatPamReads(t *testing.T) {
	dir := t.TempDir()
	if err := writeSeed(dir, "alice", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(seedPath(dir, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	want := "ABCDEFGHIJKLMNOPQRSTUVWXYZ\n\" TOTP_AUTH\n\" WINDOW_SIZE 3\n"
	if string(b) != want {
		t.Errorf("got %q, want %q", b, want)
	}

	fi, err := os.Stat(seedPath(dir, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode is %v", fi.Mode().Perm())
	}
}

// Two connections from the same user can both get past hasSeed. The one that
// finishes second must not replace the seed the first one saved
func TestSeedIsNotReplaced(t *testing.T) {
	dir := t.TempDir()
	if err := writeSeed(dir, "alice", "ABCDEFGH"); err != nil {
		t.Fatal(err)
	}

	err := writeSeed(dir, "alice", "IJKLMNOP")
	if !errors.Is(err, fs.ErrExist) {
		t.Errorf("second write: got %v, want %v", err, fs.ErrExist)
	}

	b, err := os.ReadFile(seedPath(dir, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "ABCDEFGH\n") {
		t.Errorf("the seed was replaced: %q", b)
	}

	// The temporary file is removed whether or not the link succeeded
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("left behind: %v", entries)
	}
}
