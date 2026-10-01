package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// The layout pam_google_authenticator reads. DISALLOW_REUSE and RATE_LIMIT are
// left out because they make the module write back to the file, which puts it
// outside what configuration management can hold
const seedFile = `%s
" TOTP_AUTH
" WINDOW_SIZE 3
`

func seedPath(dir, name string) string {
	return filepath.Join(dir, name)
}

// A directory the daemon can read but not write, such as one left out of
// ReadWritePaths under ProtectSystem=strict, would otherwise go unnoticed until
// a caller had scanned a code and was told the seed could not be saved
func checkSeedDir(dir string) error {
	tmp, err := os.CreateTemp(dir, ".enrol-")
	if err != nil {
		return err
	}
	tmp.Close()
	return os.Remove(tmp.Name())
}

func hasSeed(dir, name string) bool {
	_, err := os.Stat(seedPath(dir, name))
	return err == nil
}

// A half written seed would lock the user out on their next login, and there is
// no second factor to fall back on.
//
// The seed is put in place with a link rather than a rename. Two connections
// from the same user can both pass hasSeed, and a rename would let the later one
// replace the seed the earlier one saved, which is the second enrolment that is
// meant to be refused. A link fails if the name is taken
func writeSeed(dir, name, seed string) error {
	tmp, err := os.CreateTemp(dir, ".enrol-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := fmt.Fprintf(tmp, seedFile, seed); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Link(tmp.Name(), seedPath(dir, name))
}
