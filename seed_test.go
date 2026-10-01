package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// The file holds the seed and the options pam_google_authenticator reads, and
// only its owner can read it
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

// A second write for the same user is refused even when it got past hasSeed,
// and the first seed is left in place
func TestSeedIsNotReplaced(t *testing.T) {
	dir := t.TempDir()
	if err := writeSeed(dir, "alice", "ABCDEFGH"); err != nil {
		t.Fatal(err)
	}

	err := writeSeed(dir, "alice", "IJKLMNOP")
	if !errors.Is(err, errEnrolled) {
		t.Errorf("second write: got %v, want %v", err, errEnrolled)
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
