package event

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNormalizeNetworkFlowDefaultsAndCanonicalizes(t *testing.T) {
	flow := NetworkFlowEvent{
		PID:         123,
		Observer:    " LSOF ",
		ProcessPath: " /opt/homebrew/bin/claude ",
		Remote:      " 93.184.216.34:443 ",
		Protocol:    "TCP",
		Direction:   "OUT",
		State:       "ESTABLISHED",
		SigningInfo: map[string]interface{}{
			"identifier": " com.anthropic.claude ",
			"team":       " TEAMID ",
		},
	}

	NormalizeNetworkFlow(&flow)

	if flow.Schema != SchemaNetworkV0 {
		t.Fatalf("schema = %q, want %q", flow.Schema, SchemaNetworkV0)
	}
	if flow.TS.IsZero() || time.Since(flow.TS) > time.Second {
		t.Fatalf("ts was not defaulted near now: %v", flow.TS)
	}
	if flow.Remote != "93.184.216.34:443" {
		t.Fatalf("remote = %q", flow.Remote)
	}
	if flow.Observer != "lsof" {
		t.Fatalf("observer = %q", flow.Observer)
	}
	if flow.ProcessPath != "/opt/homebrew/bin/claude" {
		t.Fatalf("process path = %q", flow.ProcessPath)
	}
	if flow.ProcessBundleID != "com.anthropic.claude" || flow.ProcessTeamID != "TEAMID" {
		t.Fatalf("process identity = %q / %q", flow.ProcessBundleID, flow.ProcessTeamID)
	}
	if flow.Protocol != "tcp" || flow.Direction != "out" || flow.State != "established" {
		t.Fatalf("canonical fields = %q %q %q", flow.Protocol, flow.Direction, flow.State)
	}
}

func TestValidateNetworkFlowAcceptsMinimumContract(t *testing.T) {
	flow := NetworkFlowEvent{
		Schema:      SchemaNetworkV0,
		TS:          time.Now().UTC(),
		PID:         123,
		ProcessPath: "/opt/homebrew/bin/claude",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "new",
	}

	if err := ValidateNetworkFlow(flow); err != nil {
		t.Fatalf("ValidateNetworkFlow returned error: %v", err)
	}
}

func TestNetworkFlowMarshalIncludesAgentMetadata(t *testing.T) {
	flow := NetworkFlowEvent{
		Schema:      SchemaNetworkV0,
		TS:          time.Now().UTC(),
		Agent:       &AgentInfo{ID: "sub_200", Type: "sub", Name: "claude", PID: 200, ParentAgentID: "main_100", SpawnMethod: "direct", Cwd: "/tmp/project"},
		PID:         300,
		ProcessPath: "/opt/homebrew/bin/claude",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "new",
	}

	raw, err := json.Marshal(flow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"id":"sub_200"`) || !strings.Contains(string(raw), `"parent_agent_id":"main_100"`) {
		t.Fatalf("network flow JSON missing agent metadata: %s", raw)
	}
}

func TestValidateNetworkFlowAcceptsBundleIDAsProcessIdentity(t *testing.T) {
	flow := NetworkFlowEvent{
		Schema:          SchemaNetworkV0,
		TS:              time.Now().UTC(),
		PID:             123,
		ProcessBundleID: "com.anthropic.claude",
		Remote:          "93.184.216.34:443",
		Protocol:        "tcp",
		Direction:       "out",
		State:           "new",
	}

	if err := ValidateNetworkFlow(flow); err != nil {
		t.Fatalf("ValidateNetworkFlow returned error: %v", err)
	}
}

func TestValidateNetworkFlowAcceptsNetworkStatisticsProcessLabel(t *testing.T) {
	flow := NetworkFlowEvent{
		Schema:      SchemaNetworkV0,
		TS:          time.Now().UTC(),
		Observer:    "network_statistics",
		PID:         123,
		ProcessPath: "curl",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "closed",
	}

	if err := ValidateNetworkFlow(flow); err != nil {
		t.Fatalf("ValidateNetworkFlow returned error: %v", err)
	}
}

func TestNetworkFlowAcceptsNetworkExtensionSigningInfoNulls(t *testing.T) {
	raw := []byte(`{
		"schema": "agentsnitch.network.v0",
		"ts": "2026-06-02T21:15:00Z",
		"flow_id": "ne-flow-1",
		"observer": "network_extension",
		"pid": 123,
		"process_path": null,
		"process_bundle_id": null,
		"process_team_id": null,
		"signing_info": {
			"team": null,
			"identifier": null,
			"path": "/opt/homebrew/bin/claude"
		},
		"remote": "93.184.216.34:443",
		"protocol": "tcp",
		"direction": "out",
		"bytes_out": 0,
		"bytes_in": 0,
		"state": "new"
	}`)
	var flow NetworkFlowEvent
	if err := json.Unmarshal(raw, &flow); err != nil {
		t.Fatalf("NE-style flow JSON should unmarshal: %v", err)
	}
	NormalizeNetworkFlow(&flow)
	if err := ValidateNetworkFlow(flow); err != nil {
		t.Fatalf("ValidateNetworkFlow returned error: %v", err)
	}
	if flow.ProcessPath != "/opt/homebrew/bin/claude" {
		t.Fatalf("process path fallback = %q", flow.ProcessPath)
	}
	if flow.Observer != "network_extension" {
		t.Fatalf("observer = %q", flow.Observer)
	}
}

func TestValidateNetworkFlowRejectsMalformedEvents(t *testing.T) {
	cases := []struct {
		name string
		flow NetworkFlowEvent
		want string
	}{
		{
			name: "wrong schema",
			flow: NetworkFlowEvent{
				Schema:      "agentsnitch.network.v9",
				PID:         123,
				ProcessPath: "/opt/homebrew/bin/claude",
				Remote:      "93.184.216.34:443",
				Protocol:    "tcp",
				Direction:   "out",
				State:       "new",
				Observer:    "pcap",
			},
			want: "unsupported network schema",
		},
		{
			name: "missing pid",
			flow: NetworkFlowEvent{
				Schema:      SchemaNetworkV0,
				ProcessPath: "/opt/homebrew/bin/claude",
				Remote:      "93.184.216.34:443",
				Protocol:    "tcp",
				Direction:   "out",
				State:       "new",
			},
			want: "missing positive pid",
		},
		{
			name: "missing process identity",
			flow: NetworkFlowEvent{
				Schema:    SchemaNetworkV0,
				PID:       123,
				Remote:    "93.184.216.34:443",
				Protocol:  "tcp",
				Direction: "out",
				State:     "new",
			},
			want: "process path or bundle id",
		},
		{
			name: "process label is not path identity",
			flow: NetworkFlowEvent{
				Schema:      SchemaNetworkV0,
				PID:         123,
				ProcessPath: "Google Chrome Helper",
				Remote:      "93.184.216.34:443",
				Protocol:    "tcp",
				Direction:   "out",
				State:       "new",
			},
			want: "process path or bundle id",
		},
		{
			name: "missing remote",
			flow: NetworkFlowEvent{
				Schema:      SchemaNetworkV0,
				PID:         123,
				ProcessPath: "/opt/homebrew/bin/claude",
				Protocol:    "tcp",
				Direction:   "out",
				State:       "new",
			},
			want: "missing remote",
		},
		{
			name: "negative bytes",
			flow: NetworkFlowEvent{
				Schema:      SchemaNetworkV0,
				PID:         123,
				ProcessPath: "/opt/homebrew/bin/claude",
				Remote:      "93.184.216.34:443",
				Protocol:    "tcp",
				Direction:   "out",
				State:       "new",
				BytesOut:    -1,
			},
			want: "byte counts",
		},
		{
			name: "unsupported observer",
			flow: NetworkFlowEvent{
				Schema:      SchemaNetworkV0,
				PID:         123,
				ProcessPath: "/opt/homebrew/bin/claude",
				Remote:      "93.184.216.34:443",
				Protocol:    "tcp",
				Direction:   "out",
				State:       "new",
				Observer:    "pcap",
			},
			want: "unsupported network observer",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNetworkFlow(tc.flow)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}
