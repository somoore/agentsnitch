//go:build !darwin && !linux

package main

import "net"

func peerPIDForConn(_ net.Conn) (int, bool) {
	return 0, false
}
