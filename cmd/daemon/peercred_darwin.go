//go:build darwin

package main

import (
	"net"
	"syscall"
)

const (
	solLocal     = 0
	localPeerPID = 0x002
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
		pid, sysErr = syscall.GetsockoptInt(int(fd), solLocal, localPeerPID)
	}); err != nil || sysErr != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
