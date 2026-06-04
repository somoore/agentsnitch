package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
	asruntime "github.com/somoore/agentsnitch/internal/runtime"
)

func TestParseClaudeProcesses(t *testing.T) {
	raw := `
  100 Tue Jun  2 14:59:04 2026 claude --dangerously-skip-permissions
  101 Tue Jun  2 12:10:50 2026 /Users/scottmoore/.local/bin/claude
  102 Tue Jun  2 12:10:50 2026 /Applications/AgentSnitch.app/Contents/MacOS/agentsnitch-ui
  103 Tue Jun  2 12:10:50 2026 rg claude
`
	processes := parseClaudeProcesses(raw, time.UTC)
	if len(processes) != 2 {
		t.Fatalf("got %d Claude processes, want 2", len(processes))
	}
	if processes[0].PID != 100 || processes[1].PID != 101 {
		t.Fatalf("unexpected processes: %#v", processes)
	}
	if processes[0].Started.Format(time.RFC3339) != "2026-06-02T14:59:04Z" {
		t.Fatalf("unexpected parsed start: %s", processes[0].Started.Format(time.RFC3339))
	}
}

func TestIsClaudeCommand(t *testing.T) {
	for _, command := range []string{"claude", "claude --help", "/Users/me/.local/bin/claude --print"} {
		if !isClaudeCommand(command) {
			t.Fatalf("expected Claude command for %q", command)
		}
	}
	for _, command := range []string{"rg claude", "agentsnitch-ui", "/tmp/not-claude-helper"} {
		if isClaudeCommand(command) {
			t.Fatalf("did not expect Claude command for %q", command)
		}
	}
}

func TestMissingLinkedDetailExplainsLowSignalHook(t *testing.T) {
	base := time.Now().UTC()
	detail := missingLinkedDetail(asruntime.Status{
		LastSemantic: &event.SemanticEvent{
			Schema:    event.SchemaSemanticV0,
			TS:        base,
			Event:     "PreToolUse",
			Tool:      "Edit",
			PID:       10,
			PPID:      9,
			Tags:      []string{},
			ToolUseID: "toolu-edit",
		},
		LastNetwork: &event.NetworkFlowEvent{
			Schema:    event.SchemaNetworkV0,
			TS:        base.Add(time.Second),
			PID:       9,
			Remote:    "93.184.216.34:443",
			Protocol:  "tcp",
			Direction: "out",
			State:     "established",
		},
	})
	if !strings.Contains(detail, "last hook was Edit without sensitive/egress tags") {
		t.Fatalf("unexpected detail: %s", detail)
	}
}

func TestMissingLinkedDetailExplainsProcessMiss(t *testing.T) {
	base := time.Now().UTC()
	detail := missingLinkedDetail(asruntime.Status{
		LastSemantic: &event.SemanticEvent{
			Schema:    event.SchemaSemanticV0,
			TS:        base,
			Event:     "PreToolUse",
			Tool:      "Read",
			PID:       10,
			PPID:      9,
			Tags:      []string{"sensitive_read"},
			ToolUseID: "toolu-sensitive",
		},
		LastNetwork: &event.NetworkFlowEvent{
			Schema:    event.SchemaNetworkV0,
			TS:        base.Add(time.Second),
			PID:       200,
			PPID:      199,
			Remote:    "93.184.216.34:443",
			Protocol:  "tcp",
			Direction: "out",
			State:     "established",
		},
	})
	if !strings.Contains(detail, "does not prove same process tree") {
		t.Fatalf("unexpected detail: %s", detail)
	}
}

func TestNetworkExtensionCheckReportsRealNEObserver(t *testing.T) {
	status := asruntime.Status{
		LastNetwork: &event.NetworkFlowEvent{
			Schema:    event.SchemaNetworkV0,
			TS:        time.Now().UTC(),
			Observer:  "network_extension",
			PID:       100,
			Remote:    "93.184.216.34:443",
			Protocol:  "tcp",
			Direction: "out",
			State:     "established",
		},
	}
	got := networkExtensionCheckForStatus(status, false, nil)
	if got.status != "" || !strings.Contains(got.detail, "real NE flow observed") {
		t.Fatalf("unexpected check: %#v", got)
	}
}

func TestNetworkSensorDisabledInSettingsDefaultsToDisabled(t *testing.T) {
	t.Setenv("AGENTSNITCH_UI_SETTINGS", filepath.Join(t.TempDir(), "missing-settings.json"))
	if !networkSensorDisabledInSettings() {
		t.Fatal("missing settings should default Network Sensor to disabled")
	}
}

func TestNetworkSensorDisabledInSettingsReadsOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ui-settings.json")
	if err := os.WriteFile(path, []byte(`{"schema":"agentsnitch.ui_settings.v0","network_sensor_disabled":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTSNITCH_UI_SETTINGS", path)
	if networkSensorDisabledInSettings() {
		t.Fatal("network_sensor_disabled=false should report Network Sensor enabled")
	}
}

func TestNetworkExtensionCheckWarnsOnLsofOnly(t *testing.T) {
	status := asruntime.Status{
		LastNetwork: &event.NetworkFlowEvent{
			Schema:    event.SchemaNetworkV0,
			TS:        time.Now().UTC(),
			Observer:  "lsof",
			PID:       100,
			Remote:    "93.184.216.34:443",
			Protocol:  "tcp",
			Direction: "out",
			State:     "established",
		},
	}
	got := networkExtensionCheckForStatus(status, false, nil)
	if got.status != "WARN" || !strings.Contains(got.detail, "lsof fallback only") {
		t.Fatalf("unexpected check: %#v", got)
	}
}
