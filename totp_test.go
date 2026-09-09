package main

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 appendix B. A code this tool accepts has to be the one the
// authenticator app produced and the one pam_google_authenticator will expect
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

// The seed is written only once a code comes back. Accepting a wrong one would
// leave the user with a seed their phone cannot produce codes for, and no
// second factor to fall back on
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

// The seed pam_google_authenticator is given has to accept the same codes over
// the same window, or a clock that drifts one step enrols and then locks out
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
}
