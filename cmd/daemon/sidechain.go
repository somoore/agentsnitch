package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/somoore/agentsnitch/internal/destinationintent"
	"github.com/somoore/agentsnitch/internal/event"
)

type sidechainRegistry interface {
	parentAgentIDForCWDLocked(cwd string) string
	registerTranscriptSubLocked(agentID, name, cwd, method, parentAgentID, launchToolUseID, subagentType string, now time.Time) (event.AgentInfo, bool)
	registerTranscriptHookSubLocked(toolUseID, name, subagentType, cwd, parentAgentID string, now time.Time) (event.AgentInfo, bool)
	shouldEmitSubagentLifecycleLocked(agent event.AgentInfo) bool
	rememberToolUseAgentLocked(toolUseID, agentID string)
	parentPIDLocked(parentAgentID string) int
}

type sidechainIndexer struct {
	transcriptSizes map[string]int64
	scanned         time.Time
}

func newSidechainIndexer() *sidechainIndexer {
	return &sidechainIndexer{
		transcriptSizes: make(map[string]int64),
	}
}

// claudeProjectsRoot is the only directory tree AgentSnitch will index sidechain
// transcripts from. It matches the root that discoverRecentLocked walks, so a
// hook-supplied transcript_path (se.RawRef) can never be indexed from anywhere
// the daemon would not already discover on its own.
func claudeProjectsRoot() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".claude", "projects")
}

// withinClaudeProjectsRoot reports whether path resolves to a location inside
// the Claude projects root. transcript_path arrives in the hook payload and can
// be influenced by a prompt-injected sub-agent or MCP server that has Write/Bash
// (an in-scope adversary per the PRD), so this guards two ways the path could
// escape the root:
//   - a sibling/parent reference (../../etc/passwd): rejected by resolving the
//     path and requiring it sit at or below the root on a component boundary;
//   - a planted symlink inside the root pointing outward
//     (ln -s / ~/.claude/projects/x): rejected by EvalSymlinks before comparing.
//
// It does NOT prevent an attacker from planting a fake transcript *inside* the
// root; the daemon already indexes everything under that root via discovery, so
// that is a pre-existing architectural property, not one this guard can change.
func withinClaudeProjectsRoot(path string) bool {
	root := claudeProjectsRoot()
	if root == "" || strings.TrimSpace(path) == "" {
		return false
	}
	// Resolve symlinks on both sides so a planted in-root symlink cannot escape.
	// The files exist at read time, so EvalSymlinks should succeed; if it does
	// not, fail closed.
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	if resolved == resolvedRoot {
		return true
	}
	rel, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

type claudeTranscriptLine struct {
	UUID        string `json:"uuid"`
	ParentUUID  string `json:"parentUuid"`
	IsSidechain bool   `json:"isSidechain"`
	AgentID     string `json:"agentId"`
	CWD         string `json:"cwd"`
	Timestamp   string `json:"timestamp"`
	Type        string `json:"type"`
	Message     struct {
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

type claudeContentBlock struct {
	Type  string                 `json:"type"`
	ID    string                 `json:"id"`
	Name  string                 `json:"name"`
	Input map[string]interface{} `json:"input"`
}

type claudeSidechainMeta struct {
	AgentType   string `json:"agentType"`
	Description string `json:"description"`
	ToolUseID   string `json:"toolUseId"`
}

func (x *sidechainIndexer) seedReferencedLocked(se event.SemanticEvent, parentAgentID string, now time.Time, registry sidechainRegistry) subagentEvents {
	if x == nil {
		return subagentEvents{}
	}
	path := strings.TrimSpace(se.RawRef)
	if path == "" {
		return subagentEvents{}
	}
	candidates := transcriptSeedCandidates(path)
	var detected subagentEvents
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		// transcript_path is hook-supplied; only index candidates that resolve
		// inside the Claude projects root (see withinClaudeProjectsRoot).
		if !withinClaudeProjectsRoot(candidate) {
			continue
		}
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if x.transcriptSizes[candidate] == info.Size() {
			continue
		}
		x.transcriptSizes[candidate] = info.Size()
		detected.append(x.indexClaudeTranscriptLocked(candidate, parentAgentID, now, false, registry))
	}
	return detected
}

func (x *sidechainIndexer) discoverRecentLocked(now time.Time, registry sidechainRegistry) subagentEvents {
	if x == nil || os.Getenv("AGENTSNITCH_DISABLE_SIDECHAIN_DISCOVERY") == "1" {
		return subagentEvents{}
	}
	if !x.scanned.IsZero() && now.Sub(x.scanned) < SidechainDiscoveryInterval {
		return subagentEvents{}
	}
	x.scanned = now
	var detected subagentEvents
	for _, path := range recentClaudeSidechainPaths(now) {
		cwd := firstSidechainCWD(path)
		if cwd == "" {
			continue
		}
		parentAgentID := registry.parentAgentIDForCWDLocked(cwd)
		if parentAgentID == "" {
			continue
		}
		detected.append(x.indexClaudeTranscriptLocked(path, parentAgentID, now, true, registry))
	}
	return detected
}

func (x *sidechainIndexer) indexClaudeTranscriptLocked(path, parentAgentID string, now time.Time, emitExisting bool, registry sidechainRegistry) subagentEvents {
	// Single chokepoint for every read path (RawRef seed and discovery): never
	// open a transcript that resolves outside the Claude projects root.
	if !withinClaudeProjectsRoot(path) {
		return subagentEvents{}
	}
	f, err := os.Open(path)
	if err != nil {
		return subagentEvents{}
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || info.Size() > SidechainTranscriptMaxBytes {
		return subagentEvents{}
	}

	var detected subagentEvents
	skipAgentToolSeeds := hasTranscriptSubagents(path)
	meta := readSidechainMeta(path)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), SidechainTranscriptMaxBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row claudeTranscriptLine
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		blocks := claudeContentBlocks(row.Message.Content)
		if row.IsSidechain && strings.TrimSpace(row.AgentID) != "" {
			name := sidechainAgentName(row, path)
			if strings.TrimSpace(meta.Description) != "" {
				name = strings.TrimSpace(meta.Description)
			}
			agent, isNew := registry.registerTranscriptSubLocked(row.AgentID, name, row.CWD, "claude_sidechain", parentAgentID, meta.ToolUseID, meta.AgentType, now)
			if (isNew || emitExisting) && registry.shouldEmitSubagentLifecycleLocked(agent) {
				detected.lifecycle = append(detected.lifecycle, newSubagentLifecycle(now, agent))
			}
			for _, block := range blocks {
				if toolUseID := strings.TrimSpace(block.ID); toolUseID != "" {
					registry.rememberToolUseAgentLocked(toolUseID, agent.ID)
				}
				if agent.PID > 0 {
					if semantic, ok := sidechainToolSemantic(path, row, block, agent, parentAgentID, now, registry); ok {
						detected.semantics = append(detected.semantics, semantic)
					}
				}
			}
			continue
		}
		if skipAgentToolSeeds {
			continue
		}
		for _, block := range blocks {
			if !strings.EqualFold(strings.TrimSpace(block.Name), "Agent") {
				continue
			}
			toolUseID := strings.TrimSpace(block.ID)
			if toolUseID == "" {
				continue
			}
			name := stringMapValue(block.Input, "description")
			if name == "" {
				name = "Claude Code sub-agent"
			}
			subagentType := stringMapValue(block.Input, "subagent_type")
			agent, isNew := registry.registerTranscriptHookSubLocked(toolUseID, name, subagentType, "", parentAgentID, now)
			if isNew && registry.shouldEmitSubagentLifecycleLocked(agent) {
				detected.lifecycle = append(detected.lifecycle, newSubagentLifecycle(now, agent))
			}
		}
	}
	return detected
}

func readSidechainMeta(path string) claudeSidechainMeta {
	metaPath := strings.TrimSuffix(filepath.Clean(path), ".jsonl") + ".meta.json"
	if !withinClaudeProjectsRoot(metaPath) {
		return claudeSidechainMeta{}
	}
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return claudeSidechainMeta{}
	}
	var meta claudeSidechainMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return claudeSidechainMeta{}
	}
	meta.AgentType = strings.TrimSpace(meta.AgentType)
	meta.Description = strings.TrimSpace(meta.Description)
	meta.ToolUseID = strings.TrimSpace(meta.ToolUseID)
	return meta
}

func transcriptSeedCandidates(path string) []string {
	clean := filepath.Clean(path)
	candidates := []string{clean}
	dir := filepath.Dir(clean)
	subagentsDir := filepath.Join(strings.TrimSuffix(clean, ".jsonl"), "subagents")
	if entries, err := os.ReadDir(subagentsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
				continue
			}
			candidates = append(candidates, filepath.Join(subagentsDir, entry.Name()))
		}
	}
	if filepath.Base(dir) != "subagents" {
		siblingDir := filepath.Join(dir, strings.TrimSuffix(filepath.Base(clean), ".jsonl"), "subagents")
		if entries, err := os.ReadDir(siblingDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
					continue
				}
				candidates = append(candidates, filepath.Join(siblingDir, entry.Name()))
			}
		}
	}
	return dedupeStrings(candidates)
}

func recentClaudeSidechainPaths(now time.Time) []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	root := filepath.Join(home, ".claude", "projects")
	cutoff := now.Add(-SidechainDiscoveryWindow)
	var paths []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".jsonl") || filepath.Base(filepath.Dir(path)) != "subagents" {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.ModTime().Before(cutoff) || info.Size() > SidechainTranscriptMaxBytes {
			return nil
		}
		paths = append(paths, path)
		if len(paths) >= SidechainDiscoveryMaxFiles {
			return filepath.SkipAll
		}
		return nil
	})
	return paths
}

func firstSidechainCWD(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || info.Size() > SidechainTranscriptMaxBytes {
		return ""
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var row claudeTranscriptLine
		if err := json.Unmarshal([]byte(scanner.Text()), &row); err != nil {
			continue
		}
		if cwd := cleanCWD(row.CWD); cwd != "" {
			return cwd
		}
	}
	return ""
}

func hasTranscriptSubagents(path string) bool {
	subagentsDir := filepath.Join(strings.TrimSuffix(filepath.Clean(path), ".jsonl"), "subagents")
	entries, err := os.ReadDir(subagentsDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".jsonl") {
			return true
		}
	}
	return false
}

func sidechainToolSemantic(path string, row claudeTranscriptLine, block claudeContentBlock, agent event.AgentInfo, parentAgentID string, now time.Time, registry sidechainRegistry) (event.SemanticEvent, bool) {
	if !strings.EqualFold(strings.TrimSpace(block.Type), "tool_use") {
		return event.SemanticEvent{}, false
	}
	tool := strings.TrimSpace(block.Name)
	if tool == "" {
		return event.SemanticEvent{}, false
	}
	toolUseID := strings.TrimSpace(block.ID)
	eventKey := sidechainEventKey(path, row, block)
	if eventKey == "" {
		return event.SemanticEvent{}, false
	}

	if agent.ParentAgentID == "" {
		agent.ParentAgentID = parentAgentID
	}
	target := sidechainToolTarget(block)
	command := ""
	if strings.EqualFold(tool, "Bash") {
		command = stringMapValue(block.Input, "command")
	}
	ts := sidechainEventTime(row.Timestamp, now)
	tags := []string{"claude_sidechain", "subagent_activity"}
	if strings.HasPrefix(tool, "mcp__") {
		tags = append(tags, "mcp_tool_use")
	}
	cwd := cleanCWD(row.CWD)
	if cwd == "" {
		cwd = agent.Cwd
	}
	pid := firstPositive(agent.PID)
	if pid == 0 {
		pid = registry.parentPIDLocked(parentAgentID)
	}
	return event.SemanticEvent{
		Schema:             event.SchemaSemanticV0,
		TS:                 ts,
		Agent:              agent,
		Session:            event.SessionInfo{ID: transcriptSessionID(path)},
		Event:              "SubagentToolUse",
		Tool:               tool,
		Target:             target,
		CWD:                cwd,
		PID:                pid,
		ToolUseID:          toolUseIDOrFallback(toolUseID, eventKey),
		Tags:               tags,
		DestinationIntents: destinationintent.Extract(tool, target, command, block.Input),
		InputSummary: map[string]interface{}{
			"source": "claude_sidechain",
			"row":    row.UUID,
		},
		RawRef: path,
	}, true
}

func sidechainEventKey(path string, row claudeTranscriptLine, block claudeContentBlock) string {
	parts := []string{filepath.Clean(path), strings.TrimSpace(row.AgentID)}
	if id := strings.TrimSpace(block.ID); id != "" {
		parts = append(parts, id)
	} else if uuid := strings.TrimSpace(row.UUID); uuid != "" {
		parts = append(parts, uuid, strings.TrimSpace(block.Name))
	} else {
		return ""
	}
	return strings.Join(parts, "|")
}

func sidechainEventTime(value string, fallback time.Time) time.Time {
	value = strings.TrimSpace(value)
	if value != "" {
		if ts, err := time.Parse(time.RFC3339Nano, value); err == nil {
			return ts.UTC()
		}
	}
	if fallback.IsZero() {
		return time.Now().UTC()
	}
	return fallback
}

func transcriptSessionID(path string) string {
	clean := filepath.Clean(path)
	if filepath.Base(filepath.Dir(clean)) == "subagents" {
		sessionDir := filepath.Dir(filepath.Dir(clean))
		if base := filepath.Base(sessionDir); base != "." && base != string(filepath.Separator) {
			return strings.TrimSuffix(base, ".jsonl")
		}
	}
	base := strings.TrimSuffix(filepath.Base(clean), ".jsonl")
	if strings.HasPrefix(base, "agent-") {
		return strings.TrimPrefix(base, "agent-")
	}
	return base
}

func sidechainToolTarget(block claudeContentBlock) string {
	for _, key := range []string{"file_path", "filepath", "path", "filename", "url", "command", "pattern", "query"} {
		if value := stringMapValue(block.Input, key); value != "" {
			return value
		}
	}
	return ""
}

func toolUseIDOrFallback(toolUseID, fallback string) string {
	if strings.TrimSpace(toolUseID) != "" {
		return strings.TrimSpace(toolUseID)
	}
	return "sidechain_" + agentIDComponent(fallback)
}

func claudeContentBlocks(raw json.RawMessage) []claudeContentBlock {
	if len(raw) == 0 {
		return nil
	}
	var blocks []claudeContentBlock
	if err := json.Unmarshal(raw, &blocks); err == nil {
		return blocks
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil || text == "" {
		return nil
	}
	return nil
}

func sidechainAgentName(row claudeTranscriptLine, path string) string {
	if name := sidechainScopeFromPrompt(row.Message.Content); name != "" {
		return name
	}
	if row.AgentID != "" {
		return "Claude subagent " + row.AgentID
	}
	base := strings.TrimSuffix(filepath.Base(path), ".jsonl")
	return "Claude subagent " + strings.TrimPrefix(base, "agent-")
}

func sidechainScopeFromPrompt(raw json.RawMessage) string {
	var prompt string
	if err := json.Unmarshal(raw, &prompt); err != nil {
		return ""
	}
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return ""
	}
	if scope := extractPromptScope(prompt); scope != "" {
		return scope
	}
	for _, line := range strings.Split(prompt, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- src/") || strings.Contains(line, "Route") || strings.Contains(line, "Artboard") {
			return truncateAgentName(line)
		}
	}
	return truncateAgentName(strings.Split(prompt, "\n")[0])
}

func extractPromptScope(prompt string) string {
	marker := "YOUR SCOPE"
	idx := strings.Index(strings.ToUpper(prompt), marker)
	if idx < 0 {
		return ""
	}
	lines := strings.Split(prompt[idx:], "\n")
	var parts []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "- ") {
			continue
		}
		item := strings.TrimSpace(strings.TrimPrefix(line, "- "))
		if !strings.HasPrefix(item, "src/pages/") {
			if len(parts) > 0 {
				break
			}
			continue
		}
		item = strings.TrimPrefix(item, "src/pages/")
		item = strings.TrimSuffix(item, ".tsx")
		if item != "" && !strings.Contains(strings.ToLower(item), "shared files") {
			parts = append(parts, item)
		}
		if len(parts) >= 4 {
			break
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "QA " + strings.Join(parts, "/")
}

func truncateAgentName(name string) string {
	name = strings.Join(strings.Fields(name), " ")
	if len(name) <= 80 {
		return name
	}
	return name[:77] + "..."
}

func stringMapValue(values map[string]interface{}, key string) string {
	if values == nil {
		return ""
	}
	value, ok := values[key]
	if !ok {
		return ""
	}
	return strings.TrimSpace(valueAsString(value))
}

func valueAsString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}
