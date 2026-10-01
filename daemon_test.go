package main

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The whole exchange, over a real socket, because the caller is identified by
// the kernel and not by anything the protocol carries
func TestEnrolmentWritesTheSeedForThePeer(t *testing.T) {
	me := self(t)

	seedDir := t.TempDir()
	conn := serving(t, seedDir)
	defer conn.Close()

	dec := json.NewDecoder(conn)
	var o offer
	if err := dec.Decode(&o); err != nil {
		t.Fatal(err)
	}
	if o.Error != "" {
		t.Fatal(o.Error)
	}

	seed := secretOf(t, o.URI)
	now := time.Now()
	c, err := code(seed, now.Unix()/30)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(conn).Encode(answer{Code: c}); err != nil {
		t.Fatal(err)
	}

	var r result
	if err := dec.Decode(&r); err != nil {
		t.Fatal(err)
	}
	if r.Error != "" {
		t.Fatal(r.Error)
	}
	if !hasSeed(seedDir, me) {
		t.Errorf("no seed for %s", me)
	}
}

// Nothing is written until a code comes back, so a caller who gets it wrong is
// left able to try again rather than locked out
func TestRejectedCodeLeavesNoSeed(t *testing.T) {
	me := self(t)

	seedDir := t.TempDir()
	conn := serving(t, seedDir)
	defer conn.Close()

	dec := json.NewDecoder(conn)
	var o offer
	if err := dec.Decode(&o); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(conn).Encode(answer{Code: "000000"}); err != nil {
		t.Fatal(err)
	}

	var r result
	if err := dec.Decode(&r); err != nil {
		t.Fatal(err)
	}
	if r.Error == "" {
		t.Error("accepted a wrong code")
	}
	if hasSeed(seedDir, me) {
		t.Error("wrote a seed anyway")
	}
}

// Someone who took over a live session could otherwise move the second factor
// to a phone of their own, and the real user would never know
func TestSecondEnrolmentIsRefused(t *testing.T) {
	me := self(t)

	seedDir := t.TempDir()
	if err := writeSeed(seedDir, me, "ABCDEFGH"); err != nil {
		t.Fatal(err)
	}

	conn := serving(t, seedDir)
	defer conn.Close()

	var o offer
	if err := json.NewDecoder(conn).Decode(&o); err != nil {
		t.Fatal(err)
	}
	if o.Error == "" {
		t.Error("offered a second seed")
	}

	b, err := os.ReadFile(seedPath(seedDir, me))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "ABCDEFGH\n") {
		t.Errorf("the seed was replaced: %q", b)
	}
}

// The name the daemon gives this process, found the way the daemon finds it.
// os/user reads /etc/passwd alone in a build without cgo, so a user who comes
// from a directory through nsswitch would be named differently or not at all
func self(t *testing.T) string {
	t.Helper()
	name, err := userName(uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	return name
}

// The socket is bound before serve is reached, so a connection made here is
// never racing the daemon
func serving(t *testing.T, seedDir string) net.Conn {
	t.Helper()
	l, err := listen(filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	go daemon{seedDir: seedDir, issuer: "test"}.serve(l)

	conn, err := net.Dial("unix", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func secretOf(t *testing.T, uri string) string {
	t.Helper()
	_, rest, ok := strings.Cut(uri, "secret=")
	if !ok {
		t.Fatalf("no secret in %q", uri)
	}
	secret, _, _ := strings.Cut(rest, "&")
	return secret
}

// The issuer and the name are what the app shows, and either can hold
// characters that mean something in a URI
func TestURIEscapesTheLabel(t *testing.T) {
	got := otpauthURI("gw example", "alice@corp+1", "ABCDEFGH")
	want := "otpauth://totp/gw%20example:alice%40corp%2B1?secret=ABCDEFGH&issuer=gw%20example"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/gw example:alice@corp+1" {
		t.Errorf("label reads back as %q", u.Path)
	}
	if q := u.Query(); q.Get("secret") != "ABCDEFGH" || q.Get("issuer") != "gw example" {
		t.Errorf("parameters read back as %v", q)
	}
}
