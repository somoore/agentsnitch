package classify

import (
	"path/filepath"
	"strings"

	"github.com/somoore/agentsnitch/config"
	"github.com/somoore/agentsnitch/internal/agent"
)

const (
	TagSensitiveRead  = "sensitive_read"
	TagExternalEgress = "external_egress_attempt"
	TagMCP            = "mcp_tool_use"
	TagPostureChange  = "posture_change"
)

var heuristics = config.DefaultHeuristics()

// Classify is the primary entry point used by tests: accepts payload (HookPayload etc) + cwd.
func Classify(payload interface{}, cwd string) []string {
	tool, target, cmd := extract(payload)
	tags := classifyStrings(tool, target, cmd)
	_ = cwd
	return tags
}

// classifyStrings is the pure 3-arg implementation (not exported to avoid test confusion).
func classifyStrings(tool, target, command string) []string {
	var tags []string
	if isReadLikeTool(tool) || tool == "Bash" {
		if isSensitivePath(target) || (tool == "Bash" && commandReferencesSensitivePath(command)) {
			tags = append(tags, TagSensitiveRead)
		}
	}
	if isExplicitEgressTool(tool) {
		tags = append(tags, TagExternalEgress)
	}
	if tool == "Bash" {
		if isExternalEgressCommand(command) {
			tags = append(tags, TagExternalEgress)
		}
	}
	if strings.HasPrefix(tool, "mcp__") || strings.HasPrefix(tool, "MCP") {
		tags = append(tags, TagMCP)
	}
	if tool == "Edit" || tool == "Write" {
		if isPostureFile(target) {
			tags = append(tags, TagPostureChange)
		}
	}
	return tags
}

func isExplicitEgressTool(tool string) bool {
	return strings.EqualFold(tool, "WebFetch") || strings.EqualFold(tool, "WebSearch")
}

func isReadLikeTool(tool string) bool {
	if tool == "Read" {
		return true
	}
	lt := strings.ToLower(tool)
	return strings.Contains(lt, "read")
}

// ClassifyStrings is the public pure version for direct string use (emitter paths).
func ClassifyStrings(tool, target, command string) []string {
	return classifyStrings(tool, target, command)
}

// Classify(payload, cwd) — the form used by tests and emitter convenience.
func ClassifyPayload(payload interface{}, cwd string) []string {
	tool, target, cmd := extract(payload)
	tags := ClassifyStrings(tool, target, cmd)
	_ = cwd
	return tags
}

func ClassifyForPayload(toolName, target, command string) []string {
	return ClassifyStrings(toolName, target, command)
}

func ClassifyEvent(payload interface{}, cwd string) []string {
	return ClassifyPayload(payload, cwd)
}

func extract(payload interface{}) (tool, target, cmd string) {
	switch p := payload.(type) {
	case *agent.HookPayload:
		tool = p.ToolName
		if p.ToolInput != nil {
			if fp, ok := p.ToolInput["file_path"].(string); ok && fp != "" {
				target = fp
			}
			if target == "" {
				if path, ok := p.ToolInput["path"].(string); ok && path != "" {
					target = path
				}
			}
			if c, ok := p.ToolInput["command"].(string); ok && c != "" {
				cmd = c
			}
		}
	case map[string]interface{}:
		if t, ok := p["tool_name"].(string); ok {
			tool = t
		}
		if ti, ok := p["tool_input"].(map[string]interface{}); ok && ti != nil {
			if fp, ok := ti["file_path"].(string); ok {
				target = fp
			}
			if target == "" {
				if path, ok := ti["path"].(string); ok {
					target = path
				}
			}
			if c, ok := ti["command"].(string); ok {
				cmd = c
			}
		}
	}
	return
}

func NormalizeCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	for {
		parts := strings.Fields(cmd)
		if len(parts) == 0 || !strings.Contains(parts[0], "=") {
			break
		}
		cmd = strings.Join(parts[1:], " ")
	}
	return strings.TrimSpace(cmd)
}

func isExternalEgressCommand(command string) bool {
	normalized := NormalizeCommand(command)
	if normalized == "" {
		return false
	}
	lc := strings.ToLower(normalized)
	if isLocalOnlyCommand(lc) {
		return false
	}
	if strings.Contains(lc, "http://") || strings.Contains(lc, "https://") {
		return true
	}
	for _, token := range shellTokens(lc) {
		if isNetworkCommandToken(token) {
			return true
		}
	}
	return false
}

func isLocalOnlyCommand(command string) bool {
	for _, local := range heuristics.Classify.LocalOnlyHosts {
		if strings.Contains(command, local) {
			return true
		}
	}
	return false
}

func isNetworkCommandToken(token string) bool {
	token = strings.Trim(token, "'\"`")
	token = strings.TrimRight(token, ":;,&|()")
	base := filepath.Base(token)
	for _, networkToken := range heuristics.Classify.NetworkCommandTokens {
		if base == networkToken {
			return true
		}
	}
	return false
}

func commandReferencesSensitivePath(command string) bool {
	for _, token := range shellTokens(command) {
		if isSensitiveCommandToken(token) {
			return true
		}
	}
	return false
}

func isSensitiveCommandToken(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	token = strings.Trim(token, "'\"`")
	token = strings.Trim(token, "[]{}()<>;,")
	token = strings.TrimRight(token, ":")
	if token == "" {
		return false
	}
	if tokenLooksPathLike(token) && isSensitivePath(token) {
		return true
	}
	base := filepath.Base(token)
	if base != token && isSensitivePath(base) {
		return true
	}
	return isSensitiveStandaloneName(token)
}

func tokenLooksPathLike(token string) bool {
	return strings.ContainsAny(token, `/.`) || strings.HasPrefix(token, "~")
}

func isSensitiveStandaloneName(token string) bool {
	token = strings.ToLower(strings.Trim(token, "/\\"))
	for _, sensitive := range heuristics.Classify.SensitivePaths {
		sensitive = strings.ToLower(strings.Trim(sensitive, "/\\"))
		if strings.ContainsAny(sensitive, "*.") {
			continue
		}
		if token == sensitive {
			return true
		}
	}
	return false
}

func shellTokens(command string) []string {
	fields := strings.FieldsFunc(command, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ';', '|', '&', '(', ')', '<', '>', '=', ',':
			return true
		default:
			return false
		}
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

func IsSensitivePath(p, _ string) bool {
	return isSensitivePath(p)
}

func isSensitivePath(p string) bool {
	if p == "" {
		return false
	}
	lp := strings.ToLower(p)
	for _, s := range heuristics.Classify.SensitivePaths {
		if strings.Contains(lp, s) {
			return true
		}
	}
	return false
}

func isPostureFile(p string) bool {
	lp := strings.ToLower(p)
	return strings.HasSuffix(lp, "claude.md") ||
		strings.HasSuffix(lp, ".mcp.json") ||
		strings.Contains(lp, "settings.json")
}
