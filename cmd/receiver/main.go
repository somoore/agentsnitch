// Receiver is a tiny development helper that listens on the AgentSnitch
// unix domain socket and prints every SemanticEvent it receives as
// pretty JSON + the human String() summary.
//
// Usage:
//
//	go run ./cmd/receiver
//	# in another terminal, run Claude Code normally with hooks installed.
//
// It is not part of the production surface.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
)

var socketPath = func() string {
	home, err := os.UserHomeDir()
	if err == nil {
		dir := filepath.Join(home, ".agentsnitch")
		_ = os.MkdirAll(dir, 0o700)
		return filepath.Join(dir, "events.sock")
	}
	return "/tmp/agentsnitch-dev.sock"
}()

func main() {
	// Remove stale socket if present.
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen %s: %v", socketPath, err)
	}
	defer ln.Close()
	defer os.Remove(socketPath)

	log.Printf("dev-receiver listening on %s", socketPath)
	log.Printf("run Claude Code normally with hooks installed; this helper prints real hook events")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	// Short read timeout so hung clients don't wedge us.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := sc.Bytes()
		var sem event.SemanticEvent
		if err := json.Unmarshal(line, &sem); err != nil {
			log.Printf("bad json: %v\nraw: %s", err, line)
			continue
		}
		// Pretty print + summary
		b, _ := json.MarshalIndent(sem, "", "  ")
		fmt.Printf("=== EVENT @ %s ===\n%s\nsummary: %s\n\n", sem.TS.Format(time.RFC3339Nano), b, sem.String())
	}
	if err := sc.Err(); err != nil {
		log.Printf("scan err: %v", err)
	}
}
