package main

import (
	"encoding/base32"
	"testing"
	"time"
)

// The SHA-1 test vectors from RFC 6238 appendix B
func TestCodesMatchTheStandard(t *testing.T) {
	seed := base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString([]byte("12345678901234567890"))

	for _, c := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	} {
		got, err := code(seed, c.unix/30)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("at %d: got %s, want %s", c.unix, got, c.want)
		}
	}
}

// Codes that are wrong, empty, too short, not digits or too long are refused
func TestWrongCodeIsRejected(t *testing.T) {
	seed, err := newSeed()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1111111109, 0)

	for _, given := range []string{"000000", "", "12345", "abcdef", "0000000"} {
		ok, _ := verify(seed, given, now)
		if ok {
			t.Errorf("accepted %q", given)
		}
	}
}

// A code from the step before or after the current one is accepted, the window
// pam_google_authenticator uses with WINDOW_SIZE 3, and one from further away
// is refused
func TestCodeIsAcceptedAcrossTheWindow(t *testing.T) {
	seed, err := newSeed()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1111111109, 0)

	for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		want, err := code(seed, now.Add(offset).Unix()/30)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := verify(seed, want, now)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("refused the code from %v away", offset)
		}
	}

	for _, offset := range []time.Duration{-60 * time.Second, 60 * time.Second} {
		far, err := code(seed, now.Add(offset).Unix()/30)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := verify(seed, far, now)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("accepted the code from %v away", offset)
		}
	}
}
