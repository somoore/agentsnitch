package event

import (
	"strings"
	"testing"
	"time"
)

func TestValidateCorrelatedEventAcceptsLinkedEvidenceContract(t *testing.T) {
	corr := validCorrelatedEvent()
	if err := ValidateCorrelatedEvent(corr); err != nil {
		t.Fatalf("ValidateCorrelatedEvent returned error: %v", err)
	}
}

func TestValidateCorrelatedEventRejectsIncompleteEvidence(t *testing.T) {
	cases := []struct {
		name string
		edit func(*CorrelatedEvent)
		want string
	}{
		{
			name: "wrong schema",
			edit: func(c *CorrelatedEvent) { c.Schema = "agentsnitch.correlated.v9" },
			want: "unsupported correlated schema",
		},
		{
			name: "missing timestamp",
			edit: func(c *CorrelatedEvent) { c.TS = time.Time{} },
			want: "missing timestamp",
		},
		{
			name: "missing reasons",
			edit: func(c *CorrelatedEvent) { c.Reasons = nil },
			want: "missing reasons",
		},
		{
			name: "bad confidence",
			edit: func(c *CorrelatedEvent) { c.Confidence = "certain" },
			want: "unsupported correlated confidence",
		},
		{
			name: "missing semantic",
			edit: func(c *CorrelatedEvent) { c.Semantics = nil },
			want: "embedded semantic",
		},
		{
			name: "missing flow",
			edit: func(c *CorrelatedEvent) { c.Flows = nil },
			want: "embedded network flow",
		},
		{
			name: "overclaim",
			edit: func(c *CorrelatedEvent) { c.Summary = "Secret exfiltrated to 93.184.216.34" },
			want: "overclaiming",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			corr := validCorrelatedEvent()
			tc.edit(&corr)
			err := ValidateCorrelatedEvent(corr)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func validCorrelatedEvent() CorrelatedEvent {
	now := time.Now().UTC()
	sem := SemanticEvent{
		Schema:       SchemaSemanticV0,
		TS:           now.Add(-2 * time.Second),
		Agent:        AgentInfo{ID: "claude", Name: "Claude Code"},
		Session:      SessionInfo{ID: "session-1"},
		Event:        "PreToolUse",
		Tool:         "Read",
		Target:       "/tmp/project/.env",
		CWD:          "/tmp/project",
		PID:          123,
		PPID:         122,
		Tags:         []string{"sensitive_read"},
		ToolUseID:    "toolu-1",
		InputSummary: map[string]interface{}{"file_path": "/tmp/project/.env"},
	}
	flow := NetworkFlowEvent{
		Schema:      SchemaNetworkV0,
		TS:          now,
		FlowID:      "flow-1",
		PID:         123,
		PPID:        122,
		ProcessPath: "/opt/homebrew/bin/claude",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "established",
	}
	return CorrelatedEvent{
		Schema:      SchemaCorrelatedV0,
		TS:          now,
		SemanticIDs: []string{"toolu-1"},
		FlowIDs:     []string{"flow-1"},
		Score:       1,
		Confidence:  "high",
		Reasons:     []string{"within_10s", "pid_match", "after_sensitive_read"},
		Summary:     "Sensitive read -> outbound connection: Claude Code read /tmp/project/.env; 2.0s later: PID 123 connected to 93.184.216.34:443. Why linked: within_10s, pid_match, after_sensitive_read",
		Semantics:   []SemanticEvent{sem},
		Flows:       []NetworkFlowEvent{flow},
	}
}
