//go:build !darwin && !linux

package main

import "net"

func peerPIDForConn(_ net.Conn) (int, bool) {
	return 0, false
}

// resolvePeerExePath has no portable implementation here; peer trust fails open
// on unsupported platforms (consistent with peerPIDForConn returning false).
func resolvePeerExePath(_ int) (string, bool) {
	return "", false
}
