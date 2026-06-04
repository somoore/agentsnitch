package runtime

import (
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultUIUDSSocket = "ui.sock"
)

func SocketPath() string {
	for _, k := range []string{"AGENTSNITCH_SOCK", "AGENTSNITCH_SOCKET"} {
		if p := os.Getenv(k); p != "" {
			return p
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dir := filepath.Join(home, ".agentsnitch")
		_ = os.MkdirAll(dir, 0o700)
		return filepath.Join(dir, "events.sock")
	}
	return "/tmp/agentsnitch-dev.sock"
}

func DefaultEmitterPath() string {
	if p := os.Getenv("AGENTSNITCH_EMITTER"); p != "" {
		return p
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidate := filepath.Join(dir, "emitter")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		return filepath.Join(cwd, "bin", "emitter")
	}
	return "emitter"
}

func EmitterLogPath() string {
	if p := os.Getenv("AGENTSNITCH_EMITTER_LOG"); p != "" {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dir := filepath.Join(home, ".agentsnitch")
		_ = os.MkdirAll(dir, 0o700)
		return filepath.Join(dir, "emitter.log")
	}
	return "/tmp/agentsnitch-emitter.log"
}

func DialDaemon(timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", SocketPath(), timeout)
}

func UISocketPath() string {
	if p := os.Getenv("AGENTSNITCH_UI_SOCK"); p != "" {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dir := filepath.Join(home, ".agentsnitch")
		_ = os.MkdirAll(dir, 0o700)
		return filepath.Join(dir, DefaultUIUDSSocket)
	}
	return "/tmp/agentsnitch-ui.sock"
}

func DialUI(timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", UISocketPath(), timeout)
}
