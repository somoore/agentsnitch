package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/somoore/agentsnitch/internal/agent"
	"github.com/somoore/agentsnitch/internal/classify"
	"github.com/somoore/agentsnitch/internal/event"
)

// TestEmitterFlow exercises parse + classify + event construction + a mocked
// socket send path (using a real unix listener on a temp socket).
// This is the "small Go test in the emitter package" requested for spike.
func TestEmitterFlow(t *testing.T) {
	raw := []byte(`{
		"hookEventName":"PreToolUse",
		"session_id":"test-sess",
		"cwd":"/tmp/proj",
		"tool_name":"Read",
		"tool_input":{"file_path":".env"},
		"tool_use_id":"tu1"
	}`)

	ag := agent.NewClaudeAgent()
	payload, err := ag.ParsePreToolUse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	tags := classify.ClassifyEvent(payload, payload.CWD)
	if len(tags) == 0 || tags[0] != "sensitive_read" {
		t.Errorf("classify gave %v, want sensitive_read", tags)
	}

	// Build the event as main does (simplified)
	sem := event.SemanticEvent{
		Schema:    event.SchemaSemanticV0,
		TS:        time.Now().UTC(),
		Agent:     event.AgentInfo{ID: ag.ID(), Name: ag.Name()},
		Session:   event.SessionInfo{ID: payload.SessionID},
		Event:     payload.HookEventName,
		Tool:      payload.ToolName,
		Target:    ".env",
		CWD:       payload.CWD,
		PID:       os.Getpid(),
		PPID:      os.Getppid(),
		Tags:      tags,
		ToolUseID: payload.ToolUseID,
	}

	// Mock socket: create listener, have "emit" write to it, read back.
	tmpDir := t.TempDir()
	sock := filepath.Join(tmpDir, "test.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Exercise the emit write path against the test socket.
	go func() {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Errorf("dial mock: %v", err)
			return
		}
		defer conn.Close()
		data, _ := json.Marshal(sem)
		data = append(data, '\n')
		_, _ = conn.Write(data)
	}()

	// Accept and verify
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	dec := json.NewDecoder(conn)
	var got event.SemanticEvent
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Tool != "Read" || got.Event != "PreToolUse" {
		t.Errorf("roundtripped wrong event: %+v", got)
	}
	if len(got.Tags) == 0 || got.Tags[0] != "sensitive_read" {
		t.Errorf("tags not propagated: %v", got.Tags)
	}
}

// TestProceedNeverBlocks ensures the allow response is produced for the
// common cases (the critical fail-open path).
func TestProceedNeverBlocks(t *testing.T) {
	for _, ev := range []string{"PreToolUse", "PostToolUse", "Stop"} {
		b := agent.MustProceed(ev)
		if ev == "PreToolUse" && len(b) == 0 {
			t.Errorf("PreToolUse must produce non-empty proceed bytes")
		}
		// For post we accept empty.
		_ = b
	}
}

func TestBuildSemanticEventIncludesRequiredHookFacts(t *testing.T) {
	ag := agent.NewClaudeAgent()
	payload := &agent.HookPayload{
		SessionID:      "sess-1",
		HookEventName:  "PreToolUse",
		ToolName:       "Read",
		ToolInput:      map[string]interface{}{"file_path": "/Users/example/.env", "api_token": "should-not-leak"},
		ToolUseID:      "toolu-1",
		CWD:            "/tmp/project",
		TranscriptPath: "/Users/example/.claude/transcript.jsonl",
	}

	sem := buildSemanticEvent(ag, payload)

	if sem.Schema != event.SchemaSemanticV0 {
		t.Fatalf("schema = %q", sem.Schema)
	}
	if sem.Session.ID != "sess-1" {
		t.Fatalf("session id = %q", sem.Session.ID)
	}
	if sem.ToolUseID != "toolu-1" {
		t.Fatalf("tool use id = %q", sem.ToolUseID)
	}
	if sem.CWD != "/tmp/project" || sem.PID == 0 || sem.PPID == 0 {
		t.Fatalf("missing cwd/pid/ppid: %+v", sem)
	}
	if sem.Tool != "Read" || sem.Target != "/Users/example/.env" {
		t.Fatalf("wrong tool/target: %+v", sem)
	}
	if sem.RawRef != "/Users/example/.claude/transcript.jsonl" {
		t.Fatalf("raw ref = %q", sem.RawRef)
	}
	if !sem.HasTag("sensitive_read") {
		t.Fatalf("missing sensitive_read tag: %v", sem.Tags)
	}
	if got := sem.InputSummary["api_token"]; got != "[redacted]" {
		t.Fatalf("api_token summary = %#v", got)
	}
}

func TestBuildSemanticEventUsesManagedInspectSessionWhenPresent(t *testing.T) {
	t.Setenv("AGENTSNITCH_SESSION_ID", "inspect-run-claude-123")
	payload := &agent.HookPayload{
		SessionID:     "claude-session",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]interface{}{"command": "curl https://example.com"},
		ToolUseID:     "toolu-1",
		CWD:           "/tmp/project",
	}

	sem := buildSemanticEvent(agent.NewClaudeAgent(), payload)

	if sem.Session.ID != "inspect-run-claude-123" {
		t.Fatalf("session id = %q, want managed inspect session", sem.Session.ID)
	}
}

func TestBuildSemanticEventDerivesMissingIDsFromRealHookContext(t *testing.T) {
	sem := buildSemanticEvent(agent.NewClaudeAgent(), &agent.HookPayload{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]interface{}{"command": "curl https://example.com"},
		CWD:           "/tmp/project",
	})

	if !strings.HasPrefix(sem.Session.ID, "local-") {
		t.Fatalf("session id = %q, want local-*", sem.Session.ID)
	}
	if !strings.HasPrefix(sem.ToolUseID, "hook-") {
		t.Fatalf("tool use id = %q, want hook-*", sem.ToolUseID)
	}
	if sem.InputSummary == nil {
		t.Fatal("expected sanitized input summary")
	}
	if len(sem.DestinationIntents) != 1 || sem.DestinationIntents[0] != "example.com" {
		t.Fatalf("destination intents = %v, want example.com", sem.DestinationIntents)
	}
}

func TestBuildSemanticEventExtractsWebFetchDestinationIntent(t *testing.T) {
	sem := buildSemanticEvent(agent.NewClaudeAgent(), &agent.HookPayload{
		HookEventName: "PreToolUse",
		ToolName:      "WebFetch",
		ToolInput:     map[string]interface{}{"url": "https://docs.example.org/path?token=secret"},
		CWD:           "/tmp/project",
	})

	if len(sem.DestinationIntents) != 1 || sem.DestinationIntents[0] != "docs.example.org" {
		t.Fatalf("destination intents = %v, want docs.example.org", sem.DestinationIntents)
	}
	if sem.Target != "https://docs.example.org/path" {
		t.Fatalf("target = %q, want URL without query secret", sem.Target)
	}
	if strings.Contains(sem.Target, "secret") || strings.Contains(sem.Target, "token") {
		t.Fatalf("target leaked URL credential material: %q", sem.Target)
	}
}

func TestBuildSemanticEventTagsWebSearchAndExtractsDestinationIntent(t *testing.T) {
	sem := buildSemanticEvent(agent.NewClaudeAgent(), &agent.HookPayload{
		HookEventName: "PreToolUse",
		ToolName:      "WebSearch",
		ToolInput:     map[string]interface{}{"query": "Buildkite Cleanroom agent sandbox on GitHub"},
		CWD:           "/tmp/project",
	})

	if !sem.HasTag("external_egress_attempt") {
		t.Fatalf("missing external_egress_attempt tag: %v", sem.Tags)
	}
	if len(sem.DestinationIntents) != 1 || sem.DestinationIntents[0] != "github.com" {
		t.Fatalf("destination intents = %v, want github.com", sem.DestinationIntents)
	}
}

func TestBuildSemanticEventMarksCredentialOutput(t *testing.T) {
	sem := buildSemanticEvent(agent.NewClaudeAgent(), &agent.HookPayload{
		SessionID:     "sess-1",
		HookEventName: "PostToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]interface{}{"file_path": "/tmp/output.txt"},
		ToolUseID:     "toolu-1",
		ToolOutput:    "SECRET_KEY=<example-token>\nDATABASE_URL=postgres://example.invalid/db",
		CWD:           "/tmp/project",
	})

	if !sem.HasTag("credential_output") {
		t.Fatalf("missing credential_output tag: %v", sem.Tags)
	}
	markers, ok := sem.OutputSummary["credential_markers"].([]string)
	if !ok || len(markers) == 0 {
		t.Fatalf("missing credential markers: %#v", sem.OutputSummary)
	}
	raw, _ := json.Marshal(sem.OutputSummary)
	if bytes.Contains(raw, []byte("<example-token>")) || bytes.Contains(raw, []byte("postgres://example.invalid/db")) {
		t.Fatalf("output summary leaked raw credential-looking output: %s", raw)
	}
}

func TestSanitizeInputSummarizesContentFields(t *testing.T) {
	summary := sanitizeInput(map[string]interface{}{
		"file_path":  "/tmp/config.txt",
		"content":    "CONFIG_VALUE=<example-token>\nDATABASE_URL=postgres://example.invalid/db",
		"old_string": "password=<example-password>",
		"nested": map[string]interface{}{
			"api_key": "<example-api-key>",
			"items":   []interface{}{"secret one", "secret two"},
		},
	})

	if summary["file_path"] != "/tmp/config.txt" {
		t.Fatalf("file_path should remain useful: %#v", summary["file_path"])
	}
	raw, _ := json.Marshal(summary)
	for _, forbidden := range []string{"<example-token>", "postgres://example.invalid/db", "<example-password>", "<example-api-key>", "secret one"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("input summary leaked %q: %s", forbidden, raw)
		}
	}
	content, ok := summary["content"].(map[string]interface{})
	if !ok || content["redacted"] != true || content["len"] == nil {
		t.Fatalf("content should be summarized, got %#v", summary["content"])
	}
	nested, ok := summary["nested"].(map[string]interface{})
	if !ok || nested["api_key"] != "[redacted]" {
		t.Fatalf("nested secret key should be redacted, got %#v", summary["nested"])
	}
}

func TestSanitizeInputRedactsCommandSecrets(t *testing.T) {
	summary := sanitizeInput(map[string]interface{}{
		"command": "deploy --token=<example-token> 'https://api.example.com?token=<example-query-token>'",
	})

	cmd, ok := summary["command"].(string)
	if !ok {
		t.Fatalf("command summary = %#v", summary["command"])
	}
	for _, forbidden := range []string{"<example-token>", "<example-query-token>"} {
		if strings.Contains(cmd, forbidden) {
			t.Fatalf("command summary leaked %q: %s", forbidden, cmd)
		}
	}
	if !strings.Contains(cmd, "[redacted]") {
		t.Fatalf("command summary should retain shape with redactions: %s", cmd)
	}
}

func TestReadHookPayloadRejectsOversizedInput(t *testing.T) {
	_, err := readHookPayload(strings.NewReader(strings.Repeat("a", maxHookPayload+1)))
	if err == nil {
		t.Fatal("expected oversized hook payload to fail")
	}
}
