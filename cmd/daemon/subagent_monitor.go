package main

import (
	"encoding/json"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/somoore/agentsnitch/internal/correlator"
	"github.com/somoore/agentsnitch/internal/event"
)

type delegationHook struct {
	ts      time.Time
	pid     int
	ppid    int
	cwd     string
	tool    string
	pattern string
}

type sessionHook struct {
	ts        time.Time
	pid       int
	ppid      int
	cwd       string
	tool      string
	sessionID string
	agentID   string
}

type claudeObservation struct {
	ts      time.Time
	pid     int
	ppid    int
	cwd     string
	command string
}

type subagentDetector struct {
	seen           map[int]struct{}
	baseline       map[int]struct{}
	recent         []delegationHook
	sessions       []sessionHook
	claudeRecent   []claudeObservation
	burstLogCounts map[string]int
}

type subagentRegistry struct {
	agents           map[string]event.AgentInfo
	pidToAgentID     map[int]string
	toolUseToAgentID map[string]string
	emittedAgentIDs  map[string]struct{}
	mainAgentID      string
}

type subagentMonitor struct {
	mu sync.Mutex
	*subagentDetector
	*subagentRegistry
	sidechains *sidechainIndexer
	logf       func(format string, args ...interface{})
}

const (
	subagentStaleAgentTTL = 15 * time.Minute
)

type subagentEvents struct {
	lifecycle []event.AgentLifecycleEvent
	semantics []event.SemanticEvent
}

func (e *subagentEvents) append(other subagentEvents) {
	e.lifecycle = append(e.lifecycle, other.lifecycle...)
	e.semantics = append(e.semantics, other.semantics...)
}

func newSubagentMonitor() *subagentMonitor {
	return &subagentMonitor{
		subagentDetector: &subagentDetector{
			seen:           make(map[int]struct{}),
			baseline:       make(map[int]struct{}),
			burstLogCounts: make(map[string]int),
		},
		subagentRegistry: &subagentRegistry{
			agents:           make(map[string]event.AgentInfo),
			pidToAgentID:     make(map[int]string),
			toolUseToAgentID: make(map[string]string),
			emittedAgentIDs:  make(map[string]struct{}),
		},
		sidechains: newSidechainIndexer(),
		logf:       log.Printf,
	}
}

func (m *subagentMonitor) markBaseline(processes map[int]correlator.ProcessInfo) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for pid, proc := range processes {
		if !isClaudeCLIBinary(proc.Name) {
			continue
		}
		m.seen[pid] = struct{}{}
		m.baseline[pid] = struct{}{}
		m.registerMainLocked(pid, "", time.Now().UTC())
	}
}

func (m *subagentMonitor) recordSemantic(se event.SemanticEvent) {
	if m == nil {
		return
	}
	ts := se.TS
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	session := sessionHook{
		ts:        ts,
		pid:       se.PID,
		ppid:      se.PPID,
		cwd:       cleanCWD(se.CWD),
		tool:      se.Tool,
		sessionID: se.Session.ID,
		agentID:   se.Agent.ID,
	}
	pattern := delegationPattern(se)
	hook := delegationHook{
		ts:      ts,
		pid:     se.PID,
		ppid:    se.PPID,
		cwd:     cleanCWD(se.CWD),
		tool:    se.Tool,
		pattern: pattern,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if isClaudeSemanticEvent(se) && (session.cwd != "" || session.pid > 0 || session.sessionID != "") {
		m.sessions = append(m.sessions, session)
	}
	if pattern == "" {
		m.pruneRecentLocked(time.Now().UTC())
		return
	}
	m.recent = append(m.recent, hook)
	m.pruneRecentLocked(time.Now().UTC())
	m.logf("[SUBAGENT-DELEGATION] pid=%d ppid=%d cwd=%s tool=%s pattern=%s", hook.pid, hook.ppid, hook.cwd, hook.tool, hook.pattern)
}

func (m *subagentMonitor) observe(processes map[int]correlator.ProcessInfo, cwdLookup func(int) string) subagentEvents {
	if m == nil || len(processes) == 0 {
		return subagentEvents{}
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneRecentLocked(now)
	m.pruneStateLocked(processes, now)

	var detected subagentEvents
	for pid, proc := range processes {
		if !isClaudeCLIBinary(proc.Name) {
			continue
		}
		cwd := ""
		if cwdLookup != nil {
			cwd = cleanCWD(cwdLookup(pid))
		}
		if agent, ok := m.agentForPIDLocked(pid); ok && agent.Type == "main" && cwd != "" {
			agent.Cwd = cwd
			agent.LastSeen = now
			m.agents[agent.ID] = agent
		}
		if _, ok := m.seen[pid]; ok {
			continue
		}
		m.seen[pid] = struct{}{}

		observation := claudeObservation{
			ts:      now,
			pid:     pid,
			ppid:    proc.PPID,
			cwd:     cwd,
			command: proc.Name,
		}
		m.claudeRecent = append(m.claudeRecent, observation)

		tmuxAncestor := hasProcessAncestor(processes, pid, isTmuxProcess)
		claudeAncestor := hasProcessAncestor(processes, pid, func(parent correlator.ProcessInfo) bool {
			return isClaudeCLIBinary(parent.Name)
		})
		hook, hookMatch := m.matchRecentDelegationLocked(now, cwd)
		session, sessionMatch := m.matchRecentSessionLocked(now, cwd)
		hookLineage := sessionMatch && processHasAncestorPID(processes, pid, session.pid, session.ppid)
		burstCount, burstPIDs := m.recentClaudeBurstLocked(now, cwd)
		burstMatch := burstCount >= SubagentBurstThreshold
		if burstMatch {
			m.logBurstLocked(cwd, burstCount, burstPIDs, session, sessionMatch)
		}

		methods := make([]string, 0, 6)
		if tmuxAncestor {
			methods = append(methods, "tmux")
		}
		if hookMatch {
			methods = append(methods, "hook")
		}
		if claudeAncestor {
			methods = append(methods, "claude_ancestor")
		}
		if hookLineage {
			methods = append(methods, "hook_lineage")
		}
		if sessionMatch && (claudeAncestor || hookLineage || burstMatch) {
			methods = append(methods, "session_cwd")
		}
		if burstMatch {
			methods = append(methods, "burst")
		}
		if len(methods) == 0 {
			continue
		}
		parentAgentID := m.parentAgentIDLocked(processes, pid, session, sessionMatch)
		agent, isNew := m.registerSubLocked(pid, proc.PPID, cwd, spawnMethod(methods), parentAgentID, now)
		if isNew && m.shouldEmitSubagentLifecycleLocked(agent) {
			detected.lifecycle = append(detected.lifecycle, newSubagentLifecycle(now, agent))
			m.logf("[SUBAGENT-DETECTED] id=%s pid=%d parent=%s spawn=%s cwd=%s", agent.ID, agent.PID, agent.ParentAgentID, agent.SpawnMethod, agent.Cwd)
		}
		directHookChild := hookMatch && (proc.PPID == hook.pid || proc.PPID == hook.ppid)
		hookAge := ""
		if hookMatch {
			hookAge = now.Sub(hook.ts).Round(time.Second).String()
		}
		sessionAge := ""
		if sessionMatch {
			sessionAge = now.Sub(session.ts).Round(time.Second).String()
		}
		m.logf(
			"[SUBAGENT?] pid=%d ppid=%d cwd=%s method=%s tmux_ancestor=%v claude_ancestor=%v recent_hook=%v hook_tool=%s hook_pattern=%s hook_age=%s hook_cwd=%s direct_child_of_hook=%v hook_lineage=%v recent_session=%v session_pid=%d session_age=%s burst_count=%d baseline=%v command=%q",
			pid,
			proc.PPID,
			cwd,
			strings.Join(methods, "|"),
			tmuxAncestor,
			claudeAncestor,
			hookMatch,
			hook.tool,
			hook.pattern,
			hookAge,
			hook.cwd,
			directHookChild,
			hookLineage,
			sessionMatch,
			session.pid,
			sessionAge,
			burstCount,
			false,
			proc.Name,
		)
	}
	detected.append(m.sidechains.discoverRecentLocked(now, m))
	return detected
}

func (m *subagentMonitor) pruneRecentLocked(now time.Time) {
	cutoff := now.Add(-SubagentDelegationWindow)
	kept := m.recent[:0]
	for _, hook := range m.recent {
		if hook.ts.After(cutoff) {
			kept = append(kept, hook)
		}
	}
	m.recent = kept

	sessionCutoff := now.Add(-SubagentSessionWindow)
	sessionKept := m.sessions[:0]
	for _, hook := range m.sessions {
		if hook.ts.After(sessionCutoff) {
			sessionKept = append(sessionKept, hook)
		}
	}
	m.sessions = sessionKept

	burstCutoff := now.Add(-SubagentBurstWindow)
	claudeKept := m.claudeRecent[:0]
	for _, obs := range m.claudeRecent {
		if obs.ts.After(burstCutoff) {
			claudeKept = append(claudeKept, obs)
		}
	}
	m.claudeRecent = claudeKept
}

func (m *subagentMonitor) pruneStateLocked(processes map[int]correlator.ProcessInfo, now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	livePIDs := make(map[int]struct{}, len(processes))
	for pid, proc := range processes {
		if isClaudeCLIBinary(proc.Name) {
			livePIDs[pid] = struct{}{}
		}
	}

	for pid := range m.seen {
		if _, ok := livePIDs[pid]; !ok {
			delete(m.seen, pid)
		}
	}
	for pid := range m.baseline {
		if _, ok := livePIDs[pid]; !ok {
			delete(m.baseline, pid)
		}
	}

	for pid, agentID := range m.pidToAgentID {
		agent, exists := m.agents[agentID]
		if _, isLive := livePIDs[pid]; isLive {
			if exists {
				continue
			}
		}
		if exists && agent.Type == "main" {
			if now.Sub(agent.LastSeen) <= subagentStaleAgentTTL {
				continue
			}
			if _, ok := livePIDs[agent.PID]; ok {
				continue
			}
		}
		delete(m.pidToAgentID, pid)
	}

	for agentID, agent := range m.agents {
		if agent.Type == "main" {
			if _, ok := livePIDs[agent.PID]; ok {
				continue
			}
			if now.Sub(agent.LastSeen) <= subagentStaleAgentTTL {
				continue
			}
			delete(m.agents, agentID)
			delete(m.emittedAgentIDs, agentID)
			continue
		}
		if agent.PID > 0 {
			if _, ok := livePIDs[agent.PID]; ok {
				continue
			}
			delete(m.agents, agentID)
			delete(m.emittedAgentIDs, agentID)
			continue
		}
		if now.Sub(agent.LastSeen) <= subagentStaleAgentTTL {
			continue
		}
		delete(m.agents, agentID)
		delete(m.emittedAgentIDs, agentID)
	}

	if m.mainAgentID != "" {
		if _, ok := m.agents[m.mainAgentID]; !ok {
			m.mainAgentID = ""
			for id, agent := range m.agents {
				if agent.Type == "main" {
					m.mainAgentID = id
					break
				}
			}
		}
	}

	for toolUseID, agentID := range m.toolUseToAgentID {
		if _, ok := m.agents[agentID]; !ok {
			delete(m.toolUseToAgentID, toolUseID)
		}
	}
}

func (m *subagentMonitor) matchRecentDelegationLocked(now time.Time, cwd string) (delegationHook, bool) {
	for i := len(m.recent) - 1; i >= 0; i-- {
		hook := m.recent[i]
		if now.Sub(hook.ts) > SubagentDelegationWindow {
			continue
		}
		if cwd != "" && hook.cwd != "" && filepath.Clean(cwd) != filepath.Clean(hook.cwd) {
			continue
		}
		return hook, true
	}
	return delegationHook{}, false
}

func (m *subagentMonitor) matchRecentSessionLocked(now time.Time, cwd string) (sessionHook, bool) {
	for i := len(m.sessions) - 1; i >= 0; i-- {
		hook := m.sessions[i]
		if now.Sub(hook.ts) > SubagentSessionWindow {
			continue
		}
		if cwd != "" && hook.cwd != "" && filepath.Clean(cwd) != filepath.Clean(hook.cwd) {
			continue
		}
		return hook, true
	}
	return sessionHook{}, false
}

func (m *subagentMonitor) recentClaudeBurstLocked(now time.Time, cwd string) (int, []int) {
	cwd = cleanCWD(cwd)
	if cwd == "" {
		return 0, nil
	}
	cutoff := now.Add(-SubagentBurstWindow)
	pids := make([]int, 0, len(m.claudeRecent))
	for _, obs := range m.claudeRecent {
		if obs.ts.Before(cutoff) || cleanCWD(obs.cwd) != cwd {
			continue
		}
		pids = append(pids, obs.pid)
	}
	return len(pids), pids
}

func (m *subagentMonitor) logBurstLocked(cwd string, count int, pids []int, session sessionHook, sessionMatch bool) {
	cwd = cleanCWD(cwd)
	if cwd == "" || count < SubagentBurstThreshold {
		return
	}
	last := m.burstLogCounts[cwd]
	if last != 0 && count-last < 10 {
		return
	}
	m.burstLogCounts[cwd] = count
	m.logf(
		"[SUBAGENT-BURST?] cwd=%s count=%d window=%s pids=%s recent_session=%v session_pid=%d session_tool=%s",
		cwd,
		count,
		SubagentBurstWindow,
		formatPIDs(pids),
		sessionMatch,
		session.pid,
		session.tool,
	)
}

func (m *subagentMonitor) annotateSemantic(se *event.SemanticEvent, processes map[int]correlator.ProcessInfo) subagentEvents {
	if m == nil || se == nil || !isClaudeSemanticEvent(*se) {
		return subagentEvents{}
	}
	now := se.TS
	if now.IsZero() {
		now = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var parent event.AgentInfo
	if agent, ok := m.agentForProcessLocked(processes, se.PID, se.PPID); ok {
		parent = agent
	} else {
		pid := firstPositive(claudeAncestorPID(processes, se.PID), claudeAncestorPID(processes, se.PPID), se.PPID, se.PID)
		if pid <= 0 {
			return subagentEvents{}
		}
		cwd := cleanCWD(se.CWD)
		parent = m.registerMainLocked(pid, cwd, now)
	}
	se.Agent = parent
	detected := m.sidechains.seedReferencedLocked(*se, parent.ID, now, m)
	if agent, shouldEmit, ok := m.transcriptInferredSubagentLocked(*se, parent.ID, now); ok {
		se.Agent = agent
		if shouldEmit {
			detected.lifecycle = append(detected.lifecycle, newSubagentLifecycle(now, agent))
		}
		return detected
	}
	if agent, isNew, ok := m.hookInferredSubagentLocked(*se, parent.ID, now); ok {
		se.Agent = agent
		if isNew && m.shouldEmitSubagentLifecycleLocked(agent) {
			m.logf("[SUBAGENT-HOOK] id=%s pid=%d parent=%s name=%q type=%s cwd=%s", agent.ID, agent.PID, agent.ParentAgentID, agent.Name, agent.Version, agent.Cwd)
			detected.lifecycle = append(detected.lifecycle, newSubagentLifecycle(now, agent))
		}
	}
	return detected
}

func (m *subagentMonitor) annotateNetwork(nf *event.NetworkFlowEvent, processes map[int]correlator.ProcessInfo) {
	if m == nil || nf == nil {
		return
	}
	now := nf.TS
	if now.IsZero() {
		now = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if agent, ok := m.agentForProcessLocked(processes, nf.PID, nf.PPID); ok {
		nf.Agent = &agent
		return
	}
	if !isClaudeCLIBinary(nf.ProcessPath) {
		return
	}
	pid := firstPositive(nf.PID, nf.PPID)
	if _, ok := m.pidToAgentID[pid]; !ok {
		// Resolve the cwd so a network-attributed main carries its project path
		// (the UI labels agents by project basename). Without this the main would
		// register with an empty cwd and render as "unknown project".
		cwd := cleanCWD(cwdForPID(pid))
		agent := m.registerMainLocked(pid, cwd, now)
		nf.Agent = &agent
		return
	}
}

func newSubagentLifecycle(now time.Time, agent event.AgentInfo) event.AgentLifecycleEvent {
	return event.AgentLifecycleEvent{
		Schema: event.SchemaAgentV0,
		TS:     now,
		Event:  "new_subagent",
		Agent:  agent,
	}
}

func spawnMethod(methods []string) string {
	joined := strings.Join(methods, "|")
	switch {
	case strings.Contains(joined, "tmux"):
		return "tmux"
	case strings.Contains(joined, "hook") || strings.Contains(joined, "session_cwd"):
		return "tool"
	case strings.Contains(joined, "claude_ancestor") || strings.Contains(joined, "burst"):
		return "direct"
	default:
		return "unknown"
	}
}

func delegationPattern(se event.SemanticEvent) string {
	if se.Tool == "" {
		return ""
	}
	haystackParts := []string{se.Tool, se.Target}
	if len(se.InputSummary) > 0 {
		if raw, err := json.Marshal(se.InputSummary); err == nil {
			haystackParts = append(haystackParts, string(raw))
		}
	}
	if len(se.OutputSummary) > 0 {
		if raw, err := json.Marshal(se.OutputSummary); err == nil {
			haystackParts = append(haystackParts, string(raw))
		}
	}
	haystack := strings.ToLower(strings.Join(haystackParts, " "))
	patterns := []string{
		"sub-agent",
		"sub agent",
		"new claude",
		"spawn claude",
		"another claude",
		"tmux",
		"claude ",
	}
	for _, pattern := range patterns {
		if strings.Contains(haystack, pattern) {
			return strings.TrimSpace(pattern)
		}
	}
	return ""
}

func isClaudeSemanticEvent(se event.SemanticEvent) bool {
	agentID := strings.ToLower(strings.TrimSpace(se.Agent.ID))
	agentName := strings.ToLower(strings.TrimSpace(se.Agent.Name))
	return agentID == "claude" || strings.Contains(agentName, "claude")
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
