package event

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSemanticEventMarshalIncludesCoreHookFields(t *testing.T) {
	ev := SemanticEvent{
		Schema:    SchemaSemanticV0,
		TS:        time.Date(2026, 6, 2, 14, 23, 5, 0, time.UTC),
		Agent:     AgentInfo{ID: "claude", Name: "Claude Code"},
		Session:   SessionInfo{ID: "sess-1"},
		Event:     "PreToolUse",
		Tool:      "Read",
		Target:    "",
		CWD:       "/tmp/project",
		PID:       123,
		PPID:      122,
		ToolUseID: "toolu-1",
	}

	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"tool", "target", "cwd", "pid", "ppid", "tags", "tool_use_id", "input_summary"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("marshaled event missing %q: %s", key, raw)
		}
	}
	if tags, ok := got["tags"].([]interface{}); !ok || len(tags) != 0 {
		t.Fatalf("tags = %#v, want empty array", got["tags"])
	}
	if input, ok := got["input_summary"].(map[string]interface{}); !ok || len(input) != 0 {
		t.Fatalf("input_summary = %#v, want empty object", got["input_summary"])
	}
}

func TestValidateSemanticEventAcceptsRealHookContract(t *testing.T) {
	ev := SemanticEvent{
		Schema:       SchemaSemanticV0,
		TS:           time.Now().UTC(),
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

	if err := ValidateSemanticEvent(ev); err != nil {
		t.Fatalf("ValidateSemanticEvent returned error: %v", err)
	}
}

func TestValidateSemanticEventRejectsMissingCoreFacts(t *testing.T) {
	ev := SemanticEvent{
		Schema:       SchemaSemanticV0,
		TS:           time.Now().UTC(),
		Agent:        AgentInfo{ID: "claude", Name: "Claude Code"},
		Session:      SessionInfo{ID: "session-1"},
		Event:        "PreToolUse",
		Tool:         "Read",
		CWD:          "/tmp/project",
		PID:          123,
		PPID:         122,
		Tags:         []string{},
		InputSummary: map[string]interface{}{},
	}

	if err := ValidateSemanticEvent(ev); err == nil {
		t.Fatal("expected missing tool_use_id validation error")
	}
}

func TestSemanticEventIsEgressLikeRequiresExplicitSignal(t *testing.T) {
	for _, tool := range []string{"Bash", "Write", "Edit"} {
		ev := SemanticEvent{Tool: tool, Tags: []string{}}
		if ev.IsEgressLike() {
			t.Fatalf("%s without egress tag should not be egress-like", tool)
		}
	}

	for _, ev := range []SemanticEvent{
		{Tool: "Bash", Tags: []string{"external_egress_attempt"}},
		{Tool: "mcp__github__search_repositories", Tags: []string{}},
		{Tool: "WebFetch", Tags: []string{}},
		{Tool: "WebSearch", Tags: []string{}},
	} {
		if !ev.IsEgressLike() {
			t.Fatalf("expected egress-like event: tool=%q tags=%v", ev.Tool, ev.Tags)
		}
	}
}
