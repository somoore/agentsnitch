//go:build linux

package main

import (
	"net"
	"os"
	"strconv"
	"syscall"
)

// resolvePeerExePath returns the kernel-reported executable path for pid.
// On Linux, /proc/<pid>/exe is a symlink to the actual executable image (argv
// cannot forge it). `ps -o comm=` is unsuitable here: it returns only the
// truncated command name, not an absolute path.
func resolvePeerExePath(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	path, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil || path == "" {
		return "", false
	}
	return path, true
}

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
