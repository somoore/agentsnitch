package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/somoore/agentsnitch/internal/agent"
	"github.com/somoore/agentsnitch/internal/classify"
	"github.com/somoore/agentsnitch/internal/destinationintent"
	"github.com/somoore/agentsnitch/internal/event"
	asruntime "github.com/somoore/agentsnitch/internal/runtime"
)

// socketPath is the hardcoded dev socket. We prefer a user-writable path under
// ~/.agentsnitch but fall back to /tmp for environments without HOME.
var socketPath = func() string {
	return asruntime.SocketPath()
}()

const (
	connectTimeout = 75 * time.Millisecond // keep emitter fast; fail open
	writeTimeout   = 50 * time.Millisecond
	ackTimeout     = 150 * time.Millisecond
	maxHookPayload = 1 << 20 // 1 MiB; hook payloads should be compact metadata.
)

func main() {
	initLocalLog()

	// Accept subcommand style: "emitter pretooluse" or just "pretooluse" as arg[1].
	// We also accept the full event name.
	flag.Parse()
	args := flag.Args()

	eventType := "PreToolUse"
	if len(args) > 0 {
		et := normalizeEventType(args[0])
		if et != "" {
			eventType = et
		}
	}

	// Always ensure we emit the proceed response, even on panic or error.
	// This is the "fail open" contract.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("emitter panic: %v (failing open)", r)
			writeProceed(eventType)
			os.Exit(0)
		}
		writeProceed(eventType)
	}()

	raw, err := readHookPayload(os.Stdin)
	if err != nil {
		log.Printf("emitter: read stdin: %v", err)
		return // defer will write proceed
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		log.Printf("emitter: empty stdin payload")
		return
	}

	ag := agent.NewClaudeAgent()
	var payload *agent.HookPayload
	switch eventType {
	case "PostToolUse":
		payload, err = ag.ParsePostToolUse(raw)
	default:
		payload, err = ag.ParsePreToolUse(raw)
	}
	if err != nil {
		log.Printf("emitter: parse %s payload: %v (raw head: %.120s)", eventType, err, raw)
		// still proceed
		return
	}

	sem := buildSemanticEvent(ag, payload)
	event.NormalizeSemanticEvent(&sem)
	if err := event.ValidateSemanticEvent(sem); err != nil {
		log.Printf("emitter: semantic event incomplete: %v (event dropped, failing open)", err)
		return
	}

	// Emit to socket (best effort, short timeout, never block the agent)
	emitToSocket(sem)

	// The defer will write the proceed response to stdout.
}

func initLocalLog() {
	path := asruntime.EmitterLogPath()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("emitter: local log unavailable at %s: %v", path, err)
		return
	}
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags)
}

func readHookPayload(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, maxHookPayload+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxHookPayload {
		return nil, fmt.Errorf("hook payload exceeded %d bytes", maxHookPayload)
	}
	return raw, nil
}

// normalizeEventType accepts "pretooluse", "pre-tool-use", "PreToolUse", etc.
func normalizeEventType(s string) string {
	ls := strings.ToLower(strings.TrimSpace(s))
	switch ls {
	case "pretooluse", "pre-tool-use", "pre_tool_use", "pre":
		return "PreToolUse"
	case "posttooluse", "post-tool-use", "post_tool_use", "post":
		return "PostToolUse"
	case "pretool", "posttool":
		return strings.Title(ls) // best effort
	}
	// Pass through common others
	if strings.Contains(ls, "tooluse") || ls == "stop" || ls == "sessionstart" {
		// simple title without importing x/text
		return simpleTitle(strings.ReplaceAll(ls, "_", " "))
	}
	return s // use as-is
}

func sanitizeInput(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = sanitizeInputValue(k, v, 0)
	}
	return out
}

func sanitizeInputValue(key string, value interface{}, depth int) interface{} {
	if isSensitiveKey(key) {
		return "[redacted]"
	}
	if depth > 2 {
		return summaryForValue(value)
	}

	switch v := value.(type) {
	case string:
		return sanitizeStringValue(key, v)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for childKey, childValue := range v {
			out[childKey] = sanitizeInputValue(childKey, childValue, depth+1)
		}
		return out
	case []interface{}:
		return map[string]interface{}{
			"type": "array",
			"len":  len(v),
		}
	default:
		return v
	}
}

func sanitizeStringValue(key, value string) interface{} {
	switch key {
	case "file_path", "path":
		return value
	case "command", "description", "pattern", "url":
		return truncate(redactSecretPatterns(value), 256)
	case "prompt":
		return stringSummary(value)
	case "content", "old_string", "new_string", "result", "output":
		return stringSummary(value)
	default:
		if len(value) > 128 || len(credentialMarkers(value)) > 0 {
			return stringSummary(value)
		}
		return redactSecretPatterns(value)
	}
}

func summaryForValue(value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		return stringSummary(v)
	case map[string]interface{}:
		return map[string]interface{}{"type": "object", "keys": len(v)}
	case []interface{}:
		return map[string]interface{}{"type": "array", "len": len(v)}
	default:
		return v
	}
}

func stringSummary(value string) map[string]interface{} {
	summary := map[string]interface{}{
		"len":      len(value),
		"redacted": true,
	}
	if markers := credentialMarkers(value); len(markers) > 0 {
		summary["credential_markers"] = markers
	}
	return summary
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}

var secretRedactionPatterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)(bearer\s+)(?:[A-Za-z0-9._~+/=-]+|<[^>\s]+>)`), `${1}[redacted]`},
	{regexp.MustCompile(`(?i)((?:api[_-]?key|token|password|secret|access[_-]?key)\s*[:=]\s*)[^\s&;]+`), `${1}[redacted]`},
	{regexp.MustCompile(`(?i)([?&](?:api_key|apikey|token|key|password|secret|access_key)=)[^&\s]+`), `${1}[redacted]`},
	{regexp.MustCompile(`sk-[A-Za-z0-9_-]{8,}`), `sk-[redacted]`},
	{regexp.MustCompile(`ghp_[A-Za-z0-9_]{8,}`), `ghp_[redacted]`},
	{regexp.MustCompile(`AKIA[A-Z0-9]{8,}`), `AKIA[redacted]`},
}

func redactSecretPatterns(value string) string {
	out := value
	for _, pattern := range secretRedactionPatterns {
		out = pattern.re.ReplaceAllString(out, pattern.replacement)
	}
	return out
}

func buildSemanticEvent(ag agent.Agent, payload *agent.HookPayload) event.SemanticEvent {
	now := time.Now().UTC()
	pid := os.Getpid()
	ppid := os.Getppid()
	cwd := payload.CWD
	if cwd == "" {
		if d, err := os.Getwd(); err == nil {
			cwd = d
		}
	}

	target, command := extractTargetAndCommand(payload.ToolInput)
	tags := classify.ClassifyForPayload(payload.ToolName, target, command)
	destinationIntents := destinationintent.Extract(payload.ToolName, target, command, payload.ToolInput)

	sessionID := strings.TrimSpace(payload.SessionID)
	if managedSession := strings.TrimSpace(os.Getenv("AGENTSNITCH_SESSION_ID")); managedSession != "" {
		sessionID = managedSession
	}
	if sessionID == "" {
		sessionID = derivedSessionID(cwd, ppid)
	}
	toolUseID := strings.TrimSpace(payload.ToolUseID)
	if toolUseID == "" {
		toolUseID = derivedToolUseID(payload.HookEventName, payload.ToolName, pid, now)
	}

	sem := event.SemanticEvent{
		Schema:             event.SchemaSemanticV0,
		TS:                 now,
		Agent:              event.AgentInfo{ID: ag.ID(), Name: ag.Name()},
		Session:            event.SessionInfo{ID: sessionID},
		Event:              payload.HookEventName,
		Tool:               payload.ToolName,
		Target:             sanitizeTarget(target),
		CWD:                cwd,
		PID:                pid,
		PPID:               ppid,
		Tags:               tags,
		DestinationIntents: destinationIntents,
		ToolUseID:          toolUseID,
		InputSummary:       sanitizeInput(payload.ToolInput),
		RawRef:             payload.TranscriptPath,
	}

	if sem.Event == "" {
		sem.Event = "Unknown"
	}
	if sem.Tool == "" {
		sem.Tool = "Unknown"
	}

	if payload.HookEventName == "PostToolUse" && payload.ToolOutput != "" {
		sem.OutputSummary = summarizeOutput(payload.ToolOutput)
		if markers, _ := sem.OutputSummary["credential_markers"].([]string); len(markers) > 0 {
			sem.Tags = appendUnique(sem.Tags, "credential_output")
		}
	}

	return sem
}

func sanitizeTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if parsed, err := url.Parse(target); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		return truncate(parsed.String(), 256)
	}
	return truncate(redactSecretPatterns(target), 256)
}

func extractTargetAndCommand(in map[string]interface{}) (target, command string) {
	if in == nil {
		return "", ""
	}
	if fp, ok := in["file_path"].(string); ok && fp != "" {
		return fp, ""
	}
	if path, ok := in["path"].(string); ok && path != "" {
		return path, ""
	}
	if cmd, ok := in["command"].(string); ok && cmd != "" {
		command = cmd
		fields := strings.Fields(cmd)
		for i, f := range fields {
			if i > 0 && !strings.HasPrefix(f, "-") {
				target = f
				break
			}
		}
	}
	if target == "" {
		if url, ok := in["url"].(string); ok {
			target = url
		}
	}
	return target, command
}

func summarizeOutput(out string) map[string]interface{} {
	summary := map[string]interface{}{
		"len": len(out),
	}
	lower := strings.ToLower(out)
	if strings.Contains(lower, "error") {
		summary["has_error"] = true
	}
	markers := credentialMarkers(out)
	if len(markers) > 0 {
		summary["credential_markers"] = markers
	}
	return summary
}

func credentialMarkers(s string) []string {
	lower := strings.ToLower(s)
	var markers []string
	for _, pair := range []struct {
		needle string
		marker string
	}{
		{"secret", "secret_keyword"},
		{"password", "password_keyword"},
		{"token", "token_keyword"},
		{"api_key", "api_key_keyword"},
		{"access_key", "access_key_keyword"},
		{"database_url", "database_url"},
		{"sk-", "openai_style_key"},
		{"ghp_", "github_token"},
		{"akia", "aws_access_key"},
		{"-----begin", "private_key_block"},
	} {
		if strings.Contains(lower, pair.needle) {
			markers = append(markers, pair.marker)
		}
	}
	return appendUnique(nil, markers...)
}

func isSensitiveKey(k string) bool {
	lower := strings.ToLower(k)
	for _, needle := range []string{"secret", "token", "password", "api_key", "apikey", "access_key", "private_key"} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func derivedSessionID(cwd string, ppid int) string {
	h := sha1.Sum([]byte(cwd + "|" + strconv.Itoa(ppid)))
	return "local-" + hex.EncodeToString(h[:])[:12]
}

func derivedToolUseID(eventName, toolName string, pid int, ts time.Time) string {
	seed := eventName + "|" + toolName + "|" + ts.UTC().Format(time.RFC3339Nano) + "|" + strconv.Itoa(pid)
	h := sha1.Sum([]byte(seed))
	return "hook-" + hex.EncodeToString(h[:])[:12]
}

func appendUnique(existing []string, values ...string) []string {
	seen := make(map[string]struct{}, len(existing)+len(values))
	out := make([]string, 0, len(existing)+len(values))
	for _, v := range existing {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func writeProceed(eventType string) {
	b := agent.MustProceed(eventType)
	if len(b) > 0 {
		_, _ = os.Stdout.Write(b)
		// Some agents also expect a trailing newline.
		_, _ = os.Stdout.Write([]byte("\n"))
	}
	// For PostToolUse the MustProceed may return nil — that's intentional.
}

func emitToSocket(sem event.SemanticEvent) {
	data, err := json.Marshal(sem)
	if err != nil {
		log.Printf("emitter: marshal event: %v", err)
		return
	}
	data = append(data, '\n')

	// Dial with short timeout.
	conn, err := net.DialTimeout("unix", socketPath, connectTimeout)
	if err != nil {
		// Common on dev before daemon/receiver is up — log at debug level only.
		log.Printf("emitter: socket dial %s: %v (event dropped, this is ok for sensor)", socketPath, err)
		return
	}
	defer conn.Close()

	// Set write deadline for the connection lifetime.
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))

	_, err = conn.Write(data)
	if err != nil {
		log.Printf("emitter: socket write: %v", err)
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(ackTimeout))
	_, _ = bufio.NewReader(conn).ReadString('\n')
}

// simpleTitle uppercases the first letter of each space-separated word.
// Minimal replacement for strings.Title for our limited use (event names).
func simpleTitle(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, "")
}
