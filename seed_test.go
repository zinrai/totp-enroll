package main

import (
	"os"
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
