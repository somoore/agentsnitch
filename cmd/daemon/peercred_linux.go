//go:build linux

package main

import (
	"net"
	"syscall"
)

func peerPIDForConn(conn net.Conn) (int, bool) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, false
	}
	var pid int
	var sysErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			sysErr = err
			return
		}
		pid = int(cred.Pid)
	}); err != nil || sysErr != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
