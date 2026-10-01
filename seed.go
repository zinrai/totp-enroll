package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Without DISALLOW_REUSE and RATE_LIMIT: they make pam_google_authenticator
// write back to the file, which puts it outside what configuration management
// can hold
const seedFile = `%s
" TOTP_AUTH
" WINDOW_SIZE 3
`

var errEnrolled = errors.New("already enrolled")

func seedPath(dir, name string) string {
	return filepath.Join(dir, name)
}

// Not a Stat: it passes a directory the daemon can read but not write, such as
// one left out of ReadWritePaths under ProtectSystem=strict, and the mistake
// would surface only after a caller had scanned a code
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

func writeSeed(dir, name, seed string) error {
	// Not written under its own name: a crash part way would leave half a
	// seed, and the user locked out with no second factor to fall back on
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
	// Without this, a crash after the link can leave the name pointing at an
	// empty file
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Not a rename: a second connection from the same user that got past
	// hasSeed would replace the seed the first one saved. A link fails instead
	if err := os.Link(tmp.Name(), seedPath(dir, name)); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errEnrolled
		}
		return err
	}
	// Without this, the name can be lost after the caller was told they
	// enrolled
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
