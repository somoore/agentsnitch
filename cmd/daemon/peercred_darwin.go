//go:build darwin

package main

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// resolvePeerExePath returns the kernel-reported executable path for pid.
// On darwin `ps -o comm=` yields the absolute executable path (not argv), which
// argv cannot forge.
func resolvePeerExePath(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	cmd := exec.Command("/bin/ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	path := strings.TrimSpace(string(out))
	if path == "" || !strings.HasPrefix(path, "/") {
		return "", false
	}
	return path, true
}

const (
	solLocal      = 0
	localPeerPID  = 0x002
	localPeerEPID = 0x003
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
		if sysErr != nil || pid <= 0 {
			pid, sysErr = syscall.GetsockoptInt(int(fd), solLocal, localPeerEPID)
		}
	}); err != nil || sysErr != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
