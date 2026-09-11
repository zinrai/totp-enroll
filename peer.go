package main

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// Nothing the caller sends is used to name them. A name in the protocol, an
// environment variable or an argument would all let one user enrol a seed
// against another user's account
func peerUser(conn *net.UnixConn) (string, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return "", err
	}

	var ucred *syscall.Ucred
	var soErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, soErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return "", err
	}
	if soErr != nil {
		return "", soErr
	}

	name, err := userName(ucred.Uid)
	if err != nil {
		return "", fmt.Errorf("uid %d: %w", ucred.Uid, err)
	}
	return name, nil
}

// os/user parses /etc/passwd itself unless the binary is built with cgo, so a
// directory reached through nsswitch.conf is invisible to it
func userName(uid uint32) (string, error) {
	out, err := exec.Command("getent", "passwd", strconv.FormatUint(uint64(uid), 10)).Output()
	if err != nil {
		return "", err
	}

	name, _, ok := strings.Cut(string(out), ":")
	if !ok || name == "" {
		return "", fmt.Errorf("getent gave no name")
	}
	return name, nil
}
