package main

import (
	"fmt"
	"net"
	"os/user"
	"strconv"
	"syscall"
)

// Nothing the caller sends is used to name them. A name in the protocol, an
// environment variable or an argument would all let one user enrol a seed
// against another user's account
func peerUser(conn *net.UnixConn) (*user.User, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var ucred *syscall.Ucred
	var soErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, soErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if soErr != nil {
		return nil, soErr
	}

	u, err := user.LookupId(strconv.FormatUint(uint64(ucred.Uid), 10))
	if err != nil {
		return nil, fmt.Errorf("uid %d: %w", ucred.Uid, err)
	}
	return u, nil
}
