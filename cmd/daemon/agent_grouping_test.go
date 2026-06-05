package main

import (
	"testing"
	"time"

	"github.com/somoore/agentsnitch/internal/correlator"
	"github.com/somoore/agentsnitch/internal/event"
)

// TestAnnotateNetworkResolvesMainCwd guards the agent-grouping fix: a network flow
// attributed to a claude CLI main must register that main WITH its project cwd
// (resolved via cwdForPID), not an empty cwd. The UI labels agents by project
// basename, so an empty cwd would render as "unknown project".
func TestAnnotateNetworkResolvesMainCwd(t *testing.T) {
	orig := cwdForPID
	t.Cleanup(func() { cwdForPID = orig })
	cwdForPID = func(pid int) string {
		if pid == 4242 {
			return "/Users/me/github/myproject"
		}
		return ""
	}

	monitor := newSubagentMonitor()
	nf := &event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          time.Now().UTC(),
		PID:         4242,
		ProcessPath: "claude",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
	}
	processes := map[int]correlator.ProcessInfo{
		4242: {PID: 4242, Name: "claude"},
	}

	monitor.annotateNetwork(nf, processes)

	if nf.Agent == nil {
		t.Fatal("expected the flow to be attributed to a main agent")
	}
	if nf.Agent.Type != "main" {
		t.Fatalf("expected main agent, got type %q", nf.Agent.Type)
	}
	if nf.Agent.Cwd != "/Users/me/github/myproject" {
		t.Fatalf("main agent cwd = %q, want the resolved project path", nf.Agent.Cwd)
	}
}
