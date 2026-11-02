package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

// SEC-A11: an install created with `mkdir -p` (umask 022) left ~/.agentsnitch
// at 0755. Resolving any state path must tighten it to 0700, even when the
// directory already exists.
func TestSocketPathTightensExistingSupportDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENTSNITCH_SOCK", "")
	t.Setenv("AGENTSNITCH_SOCKET", "")

	dir := filepath.Join(home, ".agentsnitch")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir support dir: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod support dir: %v", err)
	}

	if got := SocketPath(); got != filepath.Join(dir, "events.sock") {
		t.Fatalf("SocketPath() = %q", got)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat support dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("support dir mode = %04o, want 0700", perm)
	}
}
