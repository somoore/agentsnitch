//go:build darwin

package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Helper-process entry point: file-maps a caller-supplied binary and then
// sleeps, so the parent test can ask the resolver about this process while a
// trusted-looking file is mapped into its address space. Declared in init()
// because TestMain lives in main_test.go, which is platform-neutral.
func init() {
	if os.Getenv("AGENTSNITCH_TEST_MMAP_HELPER") != "1" {
		return
	}
	mmapHelperMain()
}

func mmapHelperMain() {
	path := os.Getenv("AGENTSNITCH_TEST_MMAP_PATH")
	if path == "" {
		os.Exit(2)
	}
	f, err := os.Open(path)
	if err != nil {
		os.Exit(2)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() <= 0 {
		os.Exit(2)
	}
	// File-map the trusted-looking binary. Darwin lsof reports every mapped
	// vnode as a " txt" entry; when the mapping lands at an address below the
	// main executable image, the old lsof-based resolver (which walked txt
	// entries in virtual-address order) returned the mapped file instead of
	// the running executable. The kernel chooses the address, so retry until
	// the mapped file is actually enumerated before our own image; if this
	// host will not cooperate, proceed anyway — the parent only skips the
	// strict ordering assertion when lsof cannot see the mapping at all.
	for attempt := 0; attempt < 10; attempt++ {
		if _, err := syscall.Mmap(int(f.Fd()), 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_SHARED); err != nil {
			os.Exit(3)
		}
		if mappedBeforeOwnImage(path) {
			break
		}
		// Leave earlier mappings in place (address space is plentiful) so the
		// final mapping is guaranteed to be visible to the parent.
	}
	os.Stdout.WriteString("READY\n")
	time.Sleep(2 * time.Minute)
}

// mappedBeforeOwnImage reports whether lsof enumerates path before this
// process's own executable in its txt table, i.e. whether the staged mapping
// sits at a lower virtual address than the running image.
func mappedBeforeOwnImage(path string) bool {
	ownPath, err := filepath.EvalSymlinks(os.Args[0])
	if err != nil {
		ownPath = os.Args[0]
	}
	entries := lsofTxtEntries(os.Getpid())
	if entries == nil {
		return true // cannot verify; let the parent decide
	}
	mappedIdx, ownIdx := -1, -1
	for i, entry := range entries {
		switch entry {
		case path:
			mappedIdx = i
		case ownPath:
			ownIdx = i
		}
	}
	return mappedIdx != -1 && ownIdx != -1 && mappedIdx < ownIdx
}

// TestResolvePeerExePathIgnoresArgv0 is the SEC-01 regression test: on darwin a
// process can set argv[0] to the installed emitter path while running /bin/sleep.
// The resolver must report the real image, so the forged path can never satisfy
// the emitter trust check.
func TestResolvePeerExePathIgnoresArgv0(t *testing.T) {
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

// TestResolvePeerExePathIgnoresMappedTrustedBinary is the mapped-image
// regression test: a same-user process that file-maps a trusted binary (as
// lsof's txt table shows it) must not make the resolver return the mapped file
// instead of the executable the process is actually running. The old
// lsof-based resolver walked txt entries in virtual-address order, so a
// mapping placed below the main image was returned first and then validated
// against the genuine trusted binary.
func TestResolvePeerExePathIgnoresMappedTrustedBinary(t *testing.T) {
	const mapped = "/bin/ls"
	if _, err := os.Stat(mapped); err != nil {
		t.Skip("/bin/ls not available")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		"AGENTSNITCH_TEST_MMAP_HELPER=1",
		"AGENTSNITCH_TEST_MMAP_PATH="+mapped,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start mapped peer: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	reader := bufio.NewReader(stdout)
	ready := make(chan error, 1)
	go func() {
		line, err := reader.ReadString('\n')
		if err != nil {
			ready <- err
			return
		}
		if strings.TrimSpace(line) == "READY" {
			ready <- nil
			return
		}
		ready <- exec.ErrNotFound
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("mapped-image helper did not signal ready: %v", err)
		}
	case err := <-waitExit(cmd):
		t.Skipf("helper could not stage the trusted-file mapping on this host: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for mapped-image helper")
	}

	// The staged mapping must actually be visible in the peer's txt table;
	// otherwise this host cannot exercise the lsof-ordering scenario at all.
	if lsofTxtEntries(cmd.Process.Pid) != nil && !lsofTxtContains(cmd.Process.Pid, mapped) {
		t.Skip("lsof does not list the staged mapping on this host")
	}

	got, ok := resolvePeerExePath(cmd.Process.Pid)
	if !ok {
		t.Fatal("resolvePeerExePath failed while the helper process was live")
	}
	if got == mapped {
		t.Fatalf("resolver returned mapped trusted file %q instead of the real executable (regression)", got)
	}
	if filepath.Base(got) == "ls" {
		t.Fatalf("resolver returned the mapped /bin/ls image %q (regression)", got)
	}
	if !strings.Contains(got, filepath.Base(os.Args[0])) {
		t.Fatalf("resolver returned %q, want the helper's real executable image (test binary %q)", got, os.Args[0])
	}
}

// lsofTxtEntries returns the txt-table image paths lsof reports for pid, or
// nil when lsof is unavailable. Used only to confirm that a test actually
// staged a mapping before asserting on resolver behavior.
func lsofTxtEntries(pid int) []string {
	cmd := exec.Command("/usr/sbin/lsof", "-a", "-p", strconv.Itoa(pid), "-d", "txt", "-Fn")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	var paths []string
	inText := false
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		switch line[0] {
		case 'f':
			inText = line == "ftxt"
		case 'n':
			if inText {
				paths = append(paths, line[1:])
			}
		}
	}
	return paths
}

func lsofTxtContains(pid int, path string) bool {
	for _, entry := range lsofTxtEntries(pid) {
		if entry == path {
			return true
		}
	}
	return false
}

func waitExit(cmd *exec.Cmd) <-chan error {
	ch := make(chan error, 1)
	go func() {
		ch <- cmd.Wait()
	}()
	return ch
}

// TestResolvePeerExePathSelf verifies the resolver returns this test binary's
// own image for the running process.
func TestResolvePeerExePathSelf(t *testing.T) {
	got, ok := resolvePeerExePath(os.Getpid())
	if !ok {
		t.Fatal("resolvePeerExePath must resolve the running process")
	}
	want, err := filepath.EvalSymlinks(os.Args[0])
	if err != nil {
		want = os.Args[0]
	}
	if got != want {
		t.Fatalf("resolvePeerExePath(self) = %q, want the test binary %q", got, want)
	}
}

// TestResolvePeerExePathPreservesTrailingWhitespace verifies the resolver does
// not normalise the kernel-reported path: a peer launched from "emitter " (with
// a trailing space) beside the genuine "emitter" must resolve to its own file,
// never to the trusted one.
func TestResolvePeerExePathPreservesTrailingWhitespace(t *testing.T) {
	if _, err := os.Stat("/bin/sleep"); err != nil {
		t.Skip("/bin/sleep not available")
	}
	src, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Skipf("read /bin/sleep: %v", err)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	genuine := filepath.Join(dir, "emitter")
	spoof := genuine + " "
	for _, p := range []string{genuine, spoof} {
		if err := os.WriteFile(p, src, 0o755); err != nil {
			t.Fatalf("stage %q: %v", p, err)
		}
	}

	cmd := exec.Command(spoof, "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("start copied sleep binary: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	got, ok := resolvePeerExePath(cmd.Process.Pid)
	if !ok {
		t.Fatal("resolvePeerExePath must resolve the live peer")
	}
	if got != spoof {
		t.Fatalf("resolvePeerExePath = %q, want exact executable path %q", got, spoof)
	}
}

// TestResolvePeerExePathFailsClosed verifies the resolver reports failure for
// an unusable pid instead of returning a guessable path.
func TestResolvePeerExePathFailsClosed(t *testing.T) {
	if _, ok := resolvePeerExePath(0); ok {
		t.Fatal("pid 0 must not resolve")
	}
	if _, ok := resolvePeerExePath(-1); ok {
		t.Fatal("negative pid must not resolve")
	}
}
