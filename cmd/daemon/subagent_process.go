package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/somoore/agentsnitch/internal/correlator"
)

func cleanCWD(cwd string) string {
	cwd = strings.TrimSpace(cwd)
	if cwd == "" {
		return ""
	}
	clean := filepath.Clean(cwd)
	if clean == "." {
		return ""
	}
	return clean
}

func isClaudeCLIBinary(name string) bool {
	agentID, kind, ok := correlator.IdentifyAgentProcess(name)
	return ok && agentID == "claude" && strings.HasSuffix(kind, "_cli")
}

func isTmuxProcess(proc correlator.ProcessInfo) bool {
	first := strings.Fields(strings.TrimSpace(proc.Name))
	if len(first) == 0 {
		return false
	}
	return strings.EqualFold(filepath.Base(first[0]), "tmux")
}

func hasProcessAncestor(processes map[int]correlator.ProcessInfo, pid int, pred func(correlator.ProcessInfo) bool) bool {
	seen := make(map[int]struct{})
	for depth := 0; depth < correlator.MaxAncestorDepth; depth++ {
		proc, ok := processes[pid]
		if !ok || proc.PPID <= 0 {
			return false
		}
		if _, ok := seen[proc.PPID]; ok {
			return false
		}
		seen[proc.PPID] = struct{}{}
		parent, ok := processes[proc.PPID]
		if !ok {
			return false
		}
		if pred(parent) {
			return true
		}
		pid = parent.PID
	}
	return false
}

func processHasAncestorPID(processes map[int]correlator.ProcessInfo, pid int, candidatePIDs ...int) bool {
	wanted := make(map[int]struct{})
	for _, candidate := range candidatePIDs {
		if candidate > 0 {
			wanted[candidate] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return false
	}
	seen := make(map[int]struct{})
	for depth := 0; depth < correlator.MaxAncestorDepth; depth++ {
		proc, ok := processes[pid]
		if !ok || proc.PPID <= 0 {
			return false
		}
		if _, ok := wanted[proc.PPID]; ok {
			return true
		}
		if _, ok := seen[proc.PPID]; ok {
			return false
		}
		seen[proc.PPID] = struct{}{}
		pid = proc.PPID
	}
	return false
}

func registeredAncestorPID(processes map[int]correlator.ProcessInfo, pid int, registered map[int]string) int {
	if pid <= 0 || len(processes) == 0 || len(registered) == 0 {
		return 0
	}
	if registered[pid] != "" {
		return pid
	}
	seen := make(map[int]struct{})
	for depth := 0; depth < correlator.MaxAncestorDepth; depth++ {
		proc, ok := processes[pid]
		if !ok || proc.PPID <= 0 {
			return 0
		}
		if registered[proc.PPID] != "" {
			return proc.PPID
		}
		if _, ok := seen[proc.PPID]; ok {
			return 0
		}
		seen[proc.PPID] = struct{}{}
		pid = proc.PPID
	}
	return 0
}

func claudeAncestorPID(processes map[int]correlator.ProcessInfo, pid int) int {
	if pid <= 0 || len(processes) == 0 {
		return 0
	}
	if proc, ok := processes[pid]; ok && isClaudeCLIBinary(proc.Name) {
		return pid
	}
	seen := make(map[int]struct{})
	for depth := 0; depth < correlator.MaxAncestorDepth; depth++ {
		proc, ok := processes[pid]
		if !ok || proc.PPID <= 0 {
			return 0
		}
		if _, ok := seen[proc.PPID]; ok {
			return 0
		}
		seen[proc.PPID] = struct{}{}
		parent, ok := processes[proc.PPID]
		if !ok {
			return 0
		}
		if isClaudeCLIBinary(parent.Name) {
			return parent.PID
		}
		pid = parent.PID
	}
	return 0
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func formatPIDs(pids []int) string {
	parts := make([]string, 0, len(pids))
	for _, pid := range pids {
		parts = append(parts, fmt.Sprint(pid))
	}
	return strings.Join(parts, ",")
}

// cwdForPID resolves a process's working directory. It is a package var so tests
// can inject a fake resolver (mirrors the peerExePath pattern); the default shells
// out to lsof.
var cwdForPID = func(pid int) string {
	if pid <= 0 {
		return ""
	}
	out, err := exec.Command("lsof", "-a", "-p", fmt.Sprint(pid), "-d", "cwd", "-Fn").Output()
	if err != nil {
		return ""
	}
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "n") && len(line) > 1 {
			return line[1:]
		}
	}
	return ""
}

func resolveProcessPath(command, fallbackName string) string {
	if path := executablePathFromCommand(command); path != "" {
		return path
	}
	if path := executablePathFromCommand(fallbackName); path != "" {
		return path
	}
	for _, candidate := range []string{firstField(command), firstField(fallbackName)} {
		if candidate == "" || strings.Contains(candidate, "/") {
			continue
		}
		if path := lookupExecutablePath(candidate); path != "" {
			return path
		}
	}
	return ""
}

func lookupExecutablePath(candidate string) string {
	if path, err := exec.LookPath(candidate); err == nil && strings.Contains(path, "/") {
		return path
	}
	for _, dir := range fallbackExecutableDirs() {
		path := filepath.Join(dir, candidate)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func fallbackExecutableDirs() []string {
	dirs := []string{"/opt/homebrew/bin", "/usr/local/bin"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append([]string{filepath.Join(home, ".local", "bin")}, dirs...)
	}
	return dirs
}

func executablePathFromCommand(command string) string {
	first := firstField(command)
	if strings.HasPrefix(first, "/") {
		if info, err := os.Stat(first); err == nil && !info.IsDir() {
			return first
		}
	}
	return ""
}

func firstField(s string) string {
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func looksLikeAgentProcess(name string) bool {
	_, kind, ok := correlator.IdentifyAgentProcess(name)
	return ok && strings.HasSuffix(kind, "_cli")
}
