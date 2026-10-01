package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Without a deadline, a caller who walks away mid-enrolment would hold the
// connection open for as long as the daemon runs
const enrolTimeout = 5 * time.Minute

const enrolledMessage = "already enrolled; ask an operator to reset it"

type daemon struct {
	seedDir string
	issuer  string
}

// Not part of serve: binding there would leave a caller unable to tell a socket
// that could not be bound from one that stopped accepting, and a connection made
// right after serve was started could race the bind
func listen(path string) (net.Listener, error) {
	// A socket left over from a killed daemon would keep the new one from
	// binding, and there is nothing to preserve in it
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}

	// The kernel names the peer, so the socket does not have to keep anyone
	// out. A caller can only ever enrol themselves
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (d daemon) serve(l net.Listener) error {
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go d.handle(conn.(*net.UnixConn))
	}
}

func (d daemon) handle(conn *net.UnixConn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(enrolTimeout))

	enc := json.NewEncoder(conn)
	name, err := d.enrol(conn, enc)
	if err != nil {
		log.Printf("%s: %v", name, err)
		return
	}
	log.Printf("%s: enrolled", name)
}

func (d daemon) enrol(conn *net.UnixConn, enc *json.Encoder) (string, error) {
	name, err := peerUser(conn)
	if err != nil {
		enc.Encode(offer{Error: "cannot tell who you are"})
		return "?", err
	}

	if hasSeed(d.seedDir, name) {
		enc.Encode(offer{Error: enrolledMessage})
		return name, errEnrolled
	}

	seed, err := newSeed()
	if err != nil {
		enc.Encode(offer{Error: "cannot make a seed"})
		return name, err
	}

	uri := otpauthURI(d.issuer, name, seed)

	// Not fatal: the address below the picture is all the app needs, so a host
	// without qrencode can still enrol
	qr, err := qrcode(uri)
	if err != nil {
		log.Printf("%s: no qr code: %v", name, err)
	}
	if err := enc.Encode(offer{QR: qr, URI: uri}); err != nil {
		return name, err
	}

	var a answer
	if err := json.NewDecoder(conn).Decode(&a); err != nil {
		return name, err
	}

	ok, err := verify(seed, a.Code, time.Now())
	if err != nil || !ok {
		enc.Encode(result{Error: "that code does not match; nothing was saved"})
		return name, fmt.Errorf("code rejected")
	}

	if err := writeSeed(d.seedDir, name, seed); err != nil {
		if errors.Is(err, errEnrolled) {
			enc.Encode(result{Error: enrolledMessage})
			return name, err
		}
		enc.Encode(result{Error: "cannot save the seed"})
		return name, err
	}
	return name, enc.Encode(result{})
}

func otpauthURI(issuer, name, seed string) string {
	i, n := uriEscape(issuer), uriEscape(name)
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", i, n, seed, i)
}

// Not QueryEscape alone: it writes a space as +, which the key URI format does
// not read as a space. A + in the input is already %2B by then, so the two
// cannot be confused
func uriEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// Drawn here rather than by the caller so that the shell the caller is given
// does not need qrencode on its allowlist.
//
// Not UTF8: it draws the light modules in the terminal's own text colour, so on
// a light background the code comes out inverted and with a dark border, which
// apps will not read. ANSIUTF8 sets both colours itself
func qrcode(uri string) (string, error) {
	out, err := exec.Command("qrencode", "-t", "ANSIUTF8", "-m", "1", "--", uri).Output()
	return string(out), err
}
