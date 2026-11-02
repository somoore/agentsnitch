//go:build darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestParseLsofTextImage(t *testing.T) {
	out := []byte("p4242\nftxt\nn/usr/lib/dyld\nftxt\nn/Applications/AgentSnitch.app/Contents/MacOS/agentsnitch-ui\n")
	got, ok := parseLsofTextImage(out)
	if !ok {
		t.Fatal("expected a text image")
	}
	if want := "/Applications/AgentSnitch.app/Contents/MacOS/agentsnitch-ui"; got != want {
		t.Fatalf("parseLsofTextImage() = %q, want %q", got, want)
	}
	if _, ok := parseLsofTextImage([]byte("p1\nftxt\nn/usr/lib/dyld\n")); ok {
		t.Fatal("dyld cache must not be treated as the peer executable")
	}
	if _, ok := parseLsofTextImage([]byte("relative/path\n")); ok {
		t.Fatal("relative paths must be rejected")
	}
}

// TestResolvePeerExePathIgnoresArgv0 is the SEC-01 regression test: on darwin a
// process can set argv[0] to the installed emitter path while running /bin/sleep.
// The resolver must report the real image, so the forged path can never satisfy
// the emitter trust check.
func TestResolvePeerExePathIgnoresArgv0(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/lsof"); err != nil {
		t.Skip("lsof not available")
	}
	if _, err := os.Stat("/bin/sleep"); err != nil {
		t.Skip("/bin/sleep not available")
	}

	forged := filepath.Join(t.TempDir(), "bin", "emitter")
	t.Setenv("AGENTSNITCH_SUPPORT_DIR", filepath.Dir(filepath.Dir(forged)))

	cmd := exec.Command("/bin/sleep", "30")
	cmd.Args[0] = forged // forge argv[0] exactly as execve permits
	if err := cmd.Start(); err != nil {
		t.Fatalf("start forged peer: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	got, ok := resolvePeerExePath(cmd.Process.Pid)
	if !ok {
		t.Fatal("resolvePeerExePath failed; trust must fail closed, but the resolver should see a live process")
	}
	if got == forged {
		t.Fatalf("resolver returned forged argv[0] %q (SEC-01 regression)", forged)
	}
	if filepath.Base(got) != "sleep" {
		t.Fatalf("resolver returned %q, want the real /bin/sleep image", got)
	}
	if isTrustedEmitterExe(got) {
		t.Fatalf("forged peer image %q must not be trusted as the emitter", got)
	}
	if trustedSemanticSocketPeer(cmd.Process.Pid, nil) {
		t.Fatal("forged-argv peer must not be trusted for semantic events")
	}
}
