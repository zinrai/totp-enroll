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

func hasSeed(dir, name string) bool {
	_, err := os.Stat(seedPath(dir, name))
	return err == nil
}

// A half written seed would lock the user out on their next login, and there is
// no second factor to fall back on
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
	return os.Rename(tmp.Name(), seedPath(dir, name))
}
