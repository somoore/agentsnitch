package agent

import "encoding/json"

// HookPayload is the minimal normalized representation of a hook event
// payload for the emitter. Derived from SIR's design but stripped to only
// what the thin emitter needs for Pre/PostToolUse on Claude Code (the
// reference implementation).
//
// No policy, no full support matrix.
type HookPayload struct {
	SessionID      string
	HookEventName  string
	ToolName       string
	ToolInput      map[string]interface{}
	ToolUseID      string
	ToolOutput     string // for PostToolUse
	CWD            string
	TranscriptPath string
}

// Agent is the minimal interface needed by the emitter.
// Only Parse + the hardcoded "proceed" response for Claude.
type Agent interface {
	// ID returns stable id, e.g. "claude".
	ID() string

	// Name returns human name.
	Name() string

	ParsePreToolUse(raw []byte) (*HookPayload, error)
	ParsePostToolUse(raw []byte) (*HookPayload, error)

	// FormatProceedResponse returns the exact bytes to write to stdout
	// so the agent hook proceeds without blocking. For Claude PreToolUse
	// this is the hookSpecificOutput allow envelope. For PostToolUse
	// Claude ignores stdout (return nil/empty is fine).
	FormatProceedResponse(eventName string) ([]byte, error)
}

// ClaudeAgent is the reference implementation for Claude Code.
type ClaudeAgent struct{}

// compile-time check
var _ Agent = (*ClaudeAgent)(nil)

// NewClaudeAgent returns the Claude Code adapter (the only one needed for spike 1).
func NewClaudeAgent() *ClaudeAgent { return &ClaudeAgent{} }

func (c *ClaudeAgent) ID() string   { return "claude" }
func (c *ClaudeAgent) Name() string { return "Claude Code" }

// wirePayload is the union shape we accept from Claude hook stdin.
// We support both camelCase (hookEventName) and snake_case seen in some
// fixtures/docs for forward compatibility with the real Claude Code wire format.
type wirePayload struct {
	// Primary shape used by live Claude Code hook payloads.
	HookEventName string `json:"hookEventName"`

	// Fallback / alternate seen in some SIR fixtures and older notes
	HookEventNameAlt string `json:"hook_event_name"`

	SessionID      string                 `json:"session_id"`
	ToolName       string                 `json:"tool_name"`
	ToolInput      map[string]interface{} `json:"tool_input"`
	ToolUseID      string                 `json:"tool_use_id"`
	ToolOutput     string                 `json:"tool_output,omitempty"`
	CWD            string                 `json:"cwd"`
	TranscriptPath string                 `json:"transcript_path,omitempty"`
}

func (w wirePayload) effectiveEventName() string {
	if w.HookEventName != "" {
		return w.HookEventName
	}
	return w.HookEventNameAlt
}

func parseWire(raw []byte) (*HookPayload, error) {
	var w wirePayload
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, err
	}
	return &HookPayload{
		SessionID:      w.SessionID,
		HookEventName:  w.effectiveEventName(),
		ToolName:       w.ToolName,
		ToolInput:      w.ToolInput,
		ToolUseID:      w.ToolUseID,
		ToolOutput:     w.ToolOutput,
		CWD:            w.CWD,
		TranscriptPath: w.TranscriptPath,
	}, nil
}

func (c *ClaudeAgent) ParsePreToolUse(raw []byte) (*HookPayload, error) {
	return parseWire(raw)
}

func (c *ClaudeAgent) ParsePostToolUse(raw []byte) (*HookPayload, error) {
	return parseWire(raw)
}

// claudeProceedPre is the minimal allow response for PreToolUse.
// Claude Code proceeds on "allow" (or absent decision in some paths).
// We emit the smallest correct envelope; reason omitted for allow.
var claudeProceedPre = []byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`)

// FormatProceedResponse returns the bytes the hook must emit on stdout
// (for Pre) or can be empty (Post falls through to stderr or nothing).
func (c *ClaudeAgent) FormatProceedResponse(eventName string) ([]byte, error) {
	switch eventName {
	case "PreToolUse":
		return append([]byte(nil), claudeProceedPre...), nil
	case "PostToolUse":
		// Claude PostToolUse does not use stdout permissionDecision for control.
		// Emit nothing (or "{}" is also tolerated); returning nil/empty is fine.
		return nil, nil
	default:
		// For other lifecycle events in future, Claude often accepts {} or specific.
		// For emitter spike we are focused on tool events; return minimal {}.
		return []byte("{}"), nil
	}
}

// MustProceed is a convenience that ignores error (never errors for our impl)
// and returns the proceed bytes or a safe default.
func MustProceed(eventName string) []byte {
	a := NewClaudeAgent()
	b, err := a.FormatProceedResponse(eventName)
	if err != nil || len(b) == 0 {
		if eventName == "PreToolUse" {
			return append([]byte(nil), claudeProceedPre...)
		}
		return []byte("{}")
	}
	return b
}
