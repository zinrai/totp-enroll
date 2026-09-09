package main

import (
	"encoding/json"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The whole exchange, over a real socket, because the caller is identified by
// the kernel and not by anything the protocol carries
func TestEnrolmentWritesTheSeedForThePeer(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

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
	if !hasSeed(seedDir, me.Username) {
		t.Errorf("no seed for %s", me.Username)
	}
}

// Nothing is written until a code comes back, so a caller who gets it wrong is
// left able to try again rather than locked out
func TestRejectedCodeLeavesNoSeed(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

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
	if hasSeed(seedDir, me.Username) {
		t.Error("wrote a seed anyway")
	}
}

// The socket is bound before serve is reached, so a connection made here is
// never racing the daemon
// Someone who took over a live session could otherwise move the second factor
// to a phone of their own, and the real user would never know
func TestSecondEnrolmentIsRefused(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	seedDir := t.TempDir()
	if err := writeSeed(seedDir, me.Username, "ABCDEFGH"); err != nil {
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

	b, err := os.ReadFile(seedPath(seedDir, me.Username))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "ABCDEFGH\n") {
		t.Errorf("the seed was replaced: %q", b)
	}
}

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
