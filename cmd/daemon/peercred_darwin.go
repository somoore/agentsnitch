//go:build darwin

package main

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// resolvePeerExePath returns the kernel-reported executable path for pid.
//
// SECURITY: `ps -o comm=` is NOT usable here. On darwin it prints argv[0] for
// the process, so `execve("/bin/sleep", ["<trusted path>", ...])` forges it.
// (That is the whole SEC-01 bug: the value was compared to the installed path
// and then codesigned, so the genuine on-disk file was validated instead of the
// connecting process.)
//
// We ask the kernel via lsof's file-descriptor table instead: the `txt` entry
// for the first executable mapping (excluding the shared dyld cache) is the
// real image the process is running, which argv cannot change. lsof is already
// a daemon dependency; no cgo/libproc or new Go module is needed.
//
// Failure is reported as (\"\", false); callers must fail closed.
func resolvePeerExePath(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	cmd := exec.Command("/usr/sbin/lsof", "-a", "-p", strconv.Itoa(pid), "-d", "txt", "-Fn")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	out, err := cmd.Output()
	// lsof exits non-zero when the process disappears between the peer-cred
	// read and the lookup. Parse whatever it managed to print, then fail closed
	// if there is no usable path.
	if len(out) == 0 {
		_ = err
		return "", false
	}
	if path, ok := parseLsofTextImage(out); ok {
		return path, true
	}
	return "", false
}

// parseLsofTextImage extracts the first executable image from `lsof -Fn -d txt`
// output. The format is a sequence of field lines: "p<pid>", "ftxt", "n<path>".
// The same file description can be listed twice (the executable and
// /usr/lib/dyld), so skip dyld and any non-absolute result.
func parseLsofTextImage(out []byte) (string, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	// Executable paths can be long; allow a generous line size.
	scanner.Buffer(make([]byte, 4096), 64*1024)
	inText := false
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		switch line[0] {
		case 'f':
			inText = line == "ftxt"
		case 'n':
			if !inText {
				continue
			}
			path := line[1:]
			if !strings.HasPrefix(path, "/") {
				continue
			}
			// The dyld shared cache is mapped as text but is not the program.
			if path == "/usr/lib/dyld" || strings.HasPrefix(path, "/usr/lib/dyld") {
				continue
			}
			return path, true
		}
	}
	return "", false
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
