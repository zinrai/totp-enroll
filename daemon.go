package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"time"
)

type daemon struct {
	seedDir string
	issuer  string
}

// Binding is kept apart from serving so that a caller can tell the two failures
// apart, and so that the socket is ready to accept before serve is reached
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
	// A caller who walks away mid-enrolment would otherwise hold the
	// connection open for as long as the daemon runs
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

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
		enc.Encode(offer{Error: "already enrolled; ask an operator to reset it"})
		return name, fmt.Errorf("already enrolled")
	}

	seed, err := newSeed()
	if err != nil {
		enc.Encode(offer{Error: "cannot make a seed"})
		return name, err
	}

	uri := otpauthURI(d.issuer, name, seed)

	// The picture is a convenience and the address below it is what the app
	// needs, so a host without qrencode can still enrol
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
		enc.Encode(result{Error: "cannot save the seed"})
		return name, err
	}
	return name, enc.Encode(result{})
}

func otpauthURI(issuer, name, seed string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, name, seed, issuer)
}

// Drawn here rather than by the caller so that the shell the caller is given
// does not need qrencode on its allowlist
func qrcode(uri string) (string, error) {
	out, err := exec.Command("qrencode", "-t", "UTF8", "-m", "1", "--", uri).Output()
	return string(out), err
}
