//go:build darwin

package main

/*
#include <libproc.h>
*/
import "C"

import (
	"net"
	"strings"
	"syscall"
	"unsafe"
)

// resolvePeerExePath returns the kernel-reported executable path for pid.
//
// SECURITY: `ps -o comm=` is NOT usable here. On darwin it prints argv[0] for
// the process, so `execve("/bin/sleep", ["<trusted path>", ...])` forges it.
// (That is the whole SEC-01 bug: the value was compared to the installed path
// and then codesigned, so the genuine on-disk file was validated instead of the
// connecting process.)
//
// `lsof -d txt` is NOT usable either. Darwin lsof labels every mapped vnode
// " txt" and enumerates the mappings in virtual-address order, so the first
// non-dyld text entry is not necessarily the process executable: a same-user
// process that maps a trusted binary below its own image would make this
// resolver return the trusted file while the process runs attacker-controlled
// code, and the signature check would validate the mapped, genuine file.
//
// proc_pidpath(3) asks the kernel specifically for the executable the process
// was launched from, independent of mapped-file ordering. It needs no special
// privileges for same-user peers, which are the only peers this daemon (or the
// UI) ever accepts. Fail closed when the path cannot be resolved.
func resolvePeerExePath(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	buf := make([]C.char, C.PROC_PIDPATHINFO_MAXSIZE)
	n, err := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if err != nil || n <= 0 {
		return "", false
	}
	// SECURITY: the kernel-reported path is returned byte-for-byte. Do NOT
	// trim whitespace: a same-user attacker can install a lookalike executable
	// named "emitter " (trailing space) beside the genuine installed emitter,
	// and trimming would make this resolver report the genuine emitter's path
	// for the attacker's process — passing both the installed-path check and
	// the signature check against the genuine file. Whitespace is valid
	// filename data.
	path := C.GoStringN(&buf[0], C.int(n))
	if !strings.HasPrefix(path, "/") {
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
