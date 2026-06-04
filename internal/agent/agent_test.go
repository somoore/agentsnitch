package agent

import (
	"bytes"
	"strings"
	"testing"
)

func TestClaudeParsePreToolUse_Sample(t *testing.T) {
	raw := []byte(`{
		"hookEventName": "PreToolUse",
		"session_id": "s1",
		"cwd": "/tmp/proj",
		"tool_name": "Read",
		"tool_input": {"file_path": "/tmp/.env"},
		"tool_use_id": "t1"
	}`)
	a := NewClaudeAgent()
	p, err := a.ParsePreToolUse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.ToolName != "Read" || p.HookEventName != "PreToolUse" {
		t.Errorf("parsed wrong: %+v", p)
	}
}

func TestClaudeParseHandlesSnakeFallback(t *testing.T) {
	raw := []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`)
	a := NewClaudeAgent()
	p, err := a.ParsePostToolUse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.HookEventName != "PostToolUse" {
		t.Error("fallback parse failed")
	}
}

func TestFormatProceed_Pre(t *testing.T) {
	a := NewClaudeAgent()
	b, err := a.FormatProceedResponse("PreToolUse")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"permissionDecision":"allow"`)) {
		t.Errorf("proceed missing allow: %s", b)
	}
	if !strings.Contains(string(b), "hookEventName") {
		t.Error("missing hookEventName in response")
	}
}

func TestMustProceed(t *testing.T) {
	b := MustProceed("PostToolUse")
	// may be nil or {}, either ok
	_ = b
}
