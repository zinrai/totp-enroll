// totp-enroll lets a user register their own TOTP seed on a host where the
// seeds are kept outside their reach.
//
// The seed has to land in a directory only root can write, so something
// privileged has to do the writing. A daemon behind a socket is used rather
// than a setuid binary: the kernel names the peer on a unix socket, and no
// program on the host gains the ability to raise its own privileges
package main

import (
	"flag"
	"log"
	"os"
	"strings"
)

// Not directly in /run: under ProtectSystem=strict the daemon can write only
// its RuntimeDirectory there, which systemd also removes when the service stops
const defaultSocket = "/run/totp-enroll/socket"

func main() {
	log.SetFlags(0)

	socket := flag.String("socket", defaultSocket, "unix socket to use")
	serve := flag.Bool("daemon", false, "serve enrolment requests")
	seedDir := flag.String("seed-dir", "", "where seeds are kept")
	issuer := flag.String("issuer", "", "name shown in the authenticator app")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}

	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}

	if !*serve {
		if err := enrol(*socket); err != nil {
			log.Fatal(err)
		}
		return
	}

	// A default would let the daemon write somewhere pam is not reading, and
	// the enrolment would look like it worked
	if *issuer == "" || *seedDir == "" {
		log.Fatal("-issuer and -seed-dir are required")
	}
	// Refused rather than escaped: the app splits the label on the first colon
	// after decoding it, so even %3A would move the rest of the issuer into the
	// account name
	if strings.Contains(*issuer, ":") {
		log.Fatal("-issuer cannot contain a colon")
	}
	if err := checkSeedDir(*seedDir); err != nil {
		log.Fatal(err)
	}
	l, err := listen(*socket)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", *socket)
	log.Fatal(daemon{seedDir: *seedDir, issuer: *issuer}.serve(l))
}
