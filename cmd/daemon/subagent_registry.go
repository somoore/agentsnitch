package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/somoore/agentsnitch/internal/correlator"
	"github.com/somoore/agentsnitch/internal/event"
)

func (m *subagentMonitor) agentForProcessLocked(processes map[int]correlator.ProcessInfo, pids ...int) (event.AgentInfo, bool) {
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		if agent, ok := m.agentForPIDLocked(pid); ok {
			return agent, true
		}
		ancestor := registeredAncestorPID(processes, pid, m.pidToAgentID)
		if ancestor > 0 {
			return m.agentForPIDLocked(ancestor)
		}
	}
	return event.AgentInfo{}, false
}

func (m *subagentMonitor) agentForPIDLocked(pid int) (event.AgentInfo, bool) {
	agentID, ok := m.pidToAgentID[pid]
	if !ok {
		return event.AgentInfo{}, false
	}
	agent, ok := m.agents[agentID]
	return agent, ok
}

func (m *subagentMonitor) registerMainLocked(pid int, cwd string, now time.Time) event.AgentInfo {
	if pid <= 0 {
		return event.AgentInfo{ID: "claude", Type: "main", Name: "claude", LastSeen: now}
	}
	if agent, ok := m.agentForPIDLocked(pid); ok {
		agent.LastSeen = now
		if agent.Cwd == "" {
			agent.Cwd = cleanCWD(cwd)
		}
		m.agents[agent.ID] = agent
		return agent
	}
	agentID := fmt.Sprintf("main_%d", pid)
	if m.mainAgentID == "" {
		m.mainAgentID = agentID
	}
	agent := event.AgentInfo{
		ID:          agentID,
		Type:        "main",
		Name:        "claude",
		PID:         pid,
		SpawnMethod: "direct",
		FirstSeen:   now,
		LastSeen:    now,
		Cwd:         cleanCWD(cwd),
	}
	m.agents[agentID] = agent
	m.pidToAgentID[pid] = agentID
	return agent
}

func (m *subagentMonitor) registerSubLocked(pid, _ int, cwd, method, parentAgentID string, now time.Time) (event.AgentInfo, bool) {
	if agent, ok := m.agentForPIDLocked(pid); ok {
		agent.LastSeen = now
		if agent.Cwd == "" {
			agent.Cwd = cleanCWD(cwd)
		}
		m.agents[agent.ID] = agent
		return agent, false
	}
	if parentAgentID == "" {
		parentAgentID = m.mainAgentID
	}
	if method == "" {
		method = "unknown"
	}
	agentID := fmt.Sprintf("sub_%d", pid)
	agent := event.AgentInfo{
		ID:            agentID,
		Type:          "sub",
		Name:          "claude",
		PID:           pid,
		ParentAgentID: parentAgentID,
		SpawnMethod:   method,
		FirstSeen:     now,
		LastSeen:      now,
		Cwd:           cleanCWD(cwd),
	}
	m.agents[agentID] = agent
	m.pidToAgentID[pid] = agentID
	return agent, true
}

func (m *subagentMonitor) hookInferredSubagentLocked(se event.SemanticEvent, parentAgentID string, now time.Time) (event.AgentInfo, bool, bool) {
	toolUseID := strings.TrimSpace(se.ToolUseID)
	if toolUseID != "" {
		if agentID := m.toolUseToAgentID[toolUseID]; agentID != "" {
			if agent, ok := m.agents[agentID]; ok {
				agent.LastSeen = now
				if agent.PID == 0 {
					agent.PID = se.PID
				}
				if agent.Cwd == "" {
					agent.Cwd = cleanCWD(se.CWD)
				}
				m.agents[agent.ID] = agent
				if se.PID > 0 {
					m.pidToAgentID[se.PID] = agent.ID
				}
				return agent, false, true
			}
		}
	}
	if !isAgentToolLaunch(se) {
		return event.AgentInfo{}, false, false
	}
	name := hookSubagentDescription(se)
	subagentType := hookSubagentType(se)
	agentID := hookSubagentID(se)
	if agentID == "" {
		return event.AgentInfo{}, false, false
	}
	if parentAgentID == "" {
		parentAgentID = m.mainAgentID
	}
	if agent, ok := m.agents[agentID]; ok {
		agent.LastSeen = now
		if agent.PID == 0 {
			agent.PID = se.PID
		}
		if agent.Cwd == "" {
			agent.Cwd = cleanCWD(se.CWD)
		}
		m.agents[agent.ID] = agent
		if toolUseID != "" {
			m.toolUseToAgentID[toolUseID] = agent.ID
		}
		if se.PID > 0 {
			m.pidToAgentID[se.PID] = agent.ID
		}
		return agent, false, true
	}
	agent := event.AgentInfo{
		ID:            agentID,
		Type:          "sub",
		Name:          name,
		PID:           se.PID,
		ParentAgentID: parentAgentID,
		SpawnMethod:   "hook",
		FirstSeen:     now,
		LastSeen:      now,
		Cwd:           cleanCWD(se.CWD),
		Version:       subagentType,
	}
	m.agents[agentID] = agent
	if toolUseID != "" {
		m.toolUseToAgentID[toolUseID] = agent.ID
	}
	if se.PID > 0 {
		m.pidToAgentID[se.PID] = agent.ID
	}
	return agent, true, true
}

func (m *subagentMonitor) parentAgentIDForCWDLocked(cwd string) string {
	cwd = cleanCWD(cwd)
	if cwd == "" {
		return ""
	}
	for _, agent := range m.agents {
		if agent.Type != "main" {
			continue
		}
		agentCWD := cleanCWD(agent.Cwd)
		if agentCWD == "" {
			continue
		}
		if cwd == agentCWD || strings.HasPrefix(cwd, agentCWD+"/") || strings.HasPrefix(agentCWD, cwd+"/") {
			return agent.ID
		}
	}
	return ""
}

func (m *subagentMonitor) rememberToolUseAgentLocked(toolUseID, agentID string) {
	toolUseID = strings.TrimSpace(toolUseID)
	agentID = strings.TrimSpace(agentID)
	if toolUseID == "" || agentID == "" {
		return
	}
	m.toolUseToAgentID[toolUseID] = agentID
}

func (m *subagentMonitor) parentPIDLocked(parentAgentID string) int {
	if parent, ok := m.agents[parentAgentID]; ok {
		return parent.PID
	}
	return 0
}

func (m *subagentMonitor) registerTranscriptSubLocked(agentID, name, cwd, method, parentAgentID, launchToolUseID, subagentType string, now time.Time) (event.AgentInfo, bool) {
	component := agentIDComponent(agentID)
	if component == "" {
		return event.AgentInfo{}, false
	}
	id := "subchain_" + component
	launchToolUseID = strings.TrimSpace(launchToolUseID)
	if launchToolUseID != "" {
		if existingID := m.toolUseToAgentID[launchToolUseID]; existingID != "" {
			id = existingID
		} else if launchComponent := agentIDComponent(launchToolUseID); launchComponent != "" {
			id = "subhook_" + launchComponent
		}
	}
	if parentAgentID == "" {
		parentAgentID = m.mainAgentID
	}
	if agent, ok := m.agents[id]; ok {
		agent.LastSeen = now
		if agent.Cwd == "" {
			agent.Cwd = cleanCWD(cwd)
		}
		if strings.TrimSpace(name) != "" {
			agent.Name = strings.TrimSpace(name)
		}
		if strings.TrimSpace(method) != "" {
			agent.SpawnMethod = strings.TrimSpace(method)
		}
		if strings.TrimSpace(subagentType) != "" {
			agent.Version = strings.TrimSpace(subagentType)
		} else if strings.TrimSpace(agentID) != "" {
			agent.Version = strings.TrimSpace(agentID)
		}
		m.agents[id] = agent
		if launchToolUseID != "" {
			m.toolUseToAgentID[launchToolUseID] = agent.ID
		}
		return agent, false
	}
	version := strings.TrimSpace(subagentType)
	if version == "" {
		version = strings.TrimSpace(agentID)
	}
	agent := event.AgentInfo{
		ID:            id,
		Type:          "sub",
		Name:          strings.TrimSpace(name),
		ParentAgentID: parentAgentID,
		SpawnMethod:   method,
		FirstSeen:     now,
		LastSeen:      now,
		Cwd:           cleanCWD(cwd),
		Version:       version,
	}
	if agent.Name == "" {
		agent.Name = "Claude Code sub-agent"
	}
	m.agents[id] = agent
	if launchToolUseID != "" {
		m.toolUseToAgentID[launchToolUseID] = agent.ID
	}
	return agent, true
}

func (m *subagentMonitor) registerTranscriptHookSubLocked(toolUseID, name, subagentType, cwd, parentAgentID string, now time.Time) (event.AgentInfo, bool) {
	component := agentIDComponent(toolUseID)
	if component == "" {
		return event.AgentInfo{}, false
	}
	id := "subhook_" + component
	if parentAgentID == "" {
		parentAgentID = m.mainAgentID
	}
	if agent, ok := m.agents[id]; ok {
		agent.LastSeen = now
		if agent.Cwd == "" {
			agent.Cwd = cleanCWD(cwd)
		}
		m.agents[id] = agent
		m.toolUseToAgentID[toolUseID] = agent.ID
		return agent, false
	}
	agent := event.AgentInfo{
		ID:            id,
		Type:          "sub",
		Name:          strings.TrimSpace(name),
		ParentAgentID: parentAgentID,
		SpawnMethod:   "hook",
		FirstSeen:     now,
		LastSeen:      now,
		Cwd:           cleanCWD(cwd),
		Version:       strings.TrimSpace(subagentType),
	}
	if agent.Name == "" {
		agent.Name = "Claude Code sub-agent"
	}
	m.agents[id] = agent
	m.toolUseToAgentID[toolUseID] = agent.ID
	return agent, true
}

func (m *subagentMonitor) transcriptInferredSubagentLocked(se event.SemanticEvent, parentAgentID string, now time.Time) (event.AgentInfo, bool, bool) {
	toolUseID := strings.TrimSpace(se.ToolUseID)
	if toolUseID == "" {
		return event.AgentInfo{}, false, false
	}
	agentID := m.toolUseToAgentID[toolUseID]
	if agentID == "" {
		return event.AgentInfo{}, false, false
	}
	agent, ok := m.agents[agentID]
	if !ok || agent.ID == parentAgentID {
		return event.AgentInfo{}, false, false
	}
	agent.LastSeen = now
	if se.PID > 0 {
		agent.PID = se.PID
	}
	if agent.Cwd == "" {
		agent.Cwd = cleanCWD(se.CWD)
	}
	m.agents[agent.ID] = agent
	if se.PID > 0 {
		m.pidToAgentID[se.PID] = agent.ID
	}
	return agent, m.shouldEmitSubagentLifecycleLocked(agent), true
}

func (m *subagentMonitor) shouldEmitSubagentLifecycleLocked(agent event.AgentInfo) bool {
	if agent.ID == "" || agent.Type != "sub" || agent.PID <= 0 {
		return false
	}
	if _, ok := m.emittedAgentIDs[agent.ID]; ok {
		return false
	}
	m.emittedAgentIDs[agent.ID] = struct{}{}
	return true
}

func (m *subagentMonitor) parentAgentIDLocked(processes map[int]correlator.ProcessInfo, pid int, session sessionHook, sessionMatch bool) string {
	ancestorPID := registeredAncestorPID(processes, pid, m.pidToAgentID)
	if ancestorPID > 0 {
		if agentID := m.pidToAgentID[ancestorPID]; agentID != "" {
			return agentID
		}
	}
	if sessionMatch && session.agentID != "" {
		return session.agentID
	}
	return m.mainAgentID
}

func isAgentToolLaunch(se event.SemanticEvent) bool {
	tool := strings.TrimSpace(se.Tool)
	if !strings.EqualFold(tool, "Agent") && !strings.EqualFold(tool, "TaskCreate") {
		return false
	}
	return strings.Contains(se.Event, "PreToolUse") || strings.Contains(se.Event, "PostToolUse")
}

func hookSubagentID(se event.SemanticEvent) string {
	if component := agentIDComponent(se.ToolUseID); component != "" {
		return "subhook_" + component
	}
	if se.PID > 0 {
		return fmt.Sprintf("subhook_pid_%d", se.PID)
	}
	return ""
}

func hookSubagentDescription(se event.SemanticEvent) string {
	if se.InputSummary != nil {
		for _, key := range []string{"activeForm", "subject", "description"} {
			if description, ok := se.InputSummary[key].(string); ok {
				description = strings.TrimSpace(description)
				if description != "" {
					return description
				}
			}
		}
	}
	return "Claude Code sub-agent"
}

func hookSubagentType(se event.SemanticEvent) string {
	if se.InputSummary != nil {
		if subagentType, ok := se.InputSummary["subagent_type"].(string); ok {
			return strings.TrimSpace(subagentType)
		}
	}
	return ""
}

func agentIDComponent(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, ch := range value {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			b.WriteRune(ch)
		} else if ch == '-' || ch == '_' {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}
