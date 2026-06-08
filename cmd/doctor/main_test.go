package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
	"github.com/somoore/agentsnitch/internal/inspect"
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

func TestPreferredEmitterPathUsesInstalledSupportEmitter(t *testing.T) {
	dir := t.TempDir()
	support := filepath.Join(dir, "support")
	bin := filepath.Join(support, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	emitter := filepath.Join(bin, "emitter")
	if err := os.WriteFile(emitter, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTSNITCH_SUPPORT_DIR", support)
	t.Setenv("AGENTSNITCH_EMITTER", "")

	if got := preferredEmitterPath(); got != emitter {
		t.Fatalf("preferredEmitterPath() = %q, want %q", got, emitter)
	}
}

func TestPreferredEmitterPathHonorsExplicitEmitterOverride(t *testing.T) {
	dir := t.TempDir()
	override := filepath.Join(dir, "custom-emitter")
	t.Setenv("AGENTSNITCH_EMITTER", override)
	t.Setenv("AGENTSNITCH_SUPPORT_DIR", filepath.Join(dir, "missing"))

	if got := preferredEmitterPath(); got != override {
		t.Fatalf("preferredEmitterPath() = %q, want %q", got, override)
	}
}

func TestCurrentInspectStatusUsesLiveDaemonProxy(t *testing.T) {
	base := t.TempDir()
	t.Setenv("AGENTSNITCH_UI_SETTINGS", filepath.Join(base, "settings.json"))
	t.Setenv("AGENTSNITCH_INSPECT_DIR", filepath.Join(base, "inspect"))
	t.Setenv("AGENTSNITCH_STATUS", filepath.Join(base, "status.json"))

	settings := inspect.DefaultSettings()
	settings.HTTPSInspectEnabled = true
	if err := inspect.SaveSettings(settings); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	if _, err := inspect.NewCertManager(inspect.DefaultPaths()).EnsureCA(); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if err := asruntime.WriteStatus(asruntime.Status{
		UpdatedAt: time.Now().UTC(),
		Inspect: inspect.Status{
			Proxy: inspect.ProxyStatus{
				Enabled:   true,
				Listening: true,
				Address:   "127.0.0.1:49152",
			},
			ProcessEnv: map[string]string{"HTTPS_PROXY": "http://agentsnitch:token@127.0.0.1:49152"},
		},
		LastInspectedHTTP: &event.InspectedHTTPExchange{
			Request: event.InspectedHTTPRequest{Host: "api.example.com"},
		},
	}); err != nil {
		t.Fatalf("WriteStatus: %v", err)
	}

	got := currentInspectStatus()
	if !got.Proxy.Listening || got.Proxy.Address != "127.0.0.1:49152" {
		t.Fatalf("live proxy status not used: %+v", got.Proxy)
	}
	if got.ProcessEnv["HTTPS_PROXY"] == "" {
		t.Fatalf("process env not preserved: %+v", got.ProcessEnv)
	}
	if got.LastInspection != "api.example.com" {
		t.Fatalf("last inspection = %q", got.LastInspection)
	}
	if len(got.Warnings) != 0 {
		t.Fatalf("unexpected warnings from live proxy status: %+v", got.Warnings)
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

func TestNetworkExtensionCheckPrefersActiveObserverMode(t *testing.T) {
	status := asruntime.Status{
		ObserverMode:    "high_assurance_active",
		ObserverSources: []string{"network_extension", "network_statistics"},
		LastNetwork: &event.NetworkFlowEvent{
			Schema:    event.SchemaNetworkV0,
			TS:        time.Now().UTC(),
			Observer:  "network_statistics",
			PID:       100,
			Remote:    "93.184.216.34:443",
			Protocol:  "tcp",
			Direction: "out",
			State:     "established",
		},
	}
	got := networkExtensionCheckForStatus(status, true, nil)
	if got.status != "" || !strings.Contains(got.detail, "OS-backed flow telemetry has been observed") {
		t.Fatalf("unexpected check: %#v", got)
	}
}

func TestNetworkSensorDisabledInSettingsDefaultsToDisabled(t *testing.T) {
	t.Setenv("AGENTSNITCH_UI_SETTINGS", filepath.Join(t.TempDir(), "missing-settings.json"))
	if !networkSensorDisabledInSettings() {
		t.Fatal("missing settings should default OS Sensor to off")
	}
}

func TestNetworkSensorDisabledInSettingsReadsOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ui-settings.json")
	if err := os.WriteFile(path, []byte(`{"schema":"agentsnitch.ui_settings.v0","network_sensor_disabled":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTSNITCH_UI_SETTINGS", path)
	if networkSensorDisabledInSettings() {
		t.Fatal("network_sensor_disabled=false should report OS Sensor requested")
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
