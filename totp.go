package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"time"
)

// RFC 4226 puts the floor for a shared secret at 128 bits
const seedBytes = 16

const (
	period = 30 * time.Second
	// pam_google_authenticator is deployed with WINDOW_SIZE 3, which accepts
	// the step before and after the current one. Verifying over a narrower
	// window would enrol a user whose clock the host later rejects
	steps = 1
)

func newSeed() (string, error) {
	b := make([]byte, seedBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func code(seed string, counter int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
	if err != nil {
		return "", err
	}

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000), nil
}

func verify(seed, given string, now time.Time) (bool, error) {
	counter := now.Unix() / int64(period.Seconds())
	for i := -steps; i <= steps; i++ {
		want, err := code(seed, counter+int64(i))
		if err != nil {
			return false, err
		}
		if hmac.Equal([]byte(want), []byte(given)) {
			return true, nil
		}
	}
	return false, nil
}
