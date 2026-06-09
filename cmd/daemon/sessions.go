package main

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/somoore/agentsnitch/internal/correlator"
	"github.com/somoore/agentsnitch/internal/event"
	"github.com/somoore/agentsnitch/internal/inspect"
)

const (
	defaultDaemonSessionIdle = 90 * time.Second
	maxPendingNetworkFlows   = 100
)

type daemonSession struct {
	id             string
	state          *correlator.SessionState
	subagents      *subagentMonitor
	lastActivity   time.Time
	rawNetworkMu   sync.Mutex
	rawNetworkSeen map[string]time.Time
}

type daemonSessions struct {
	mu                  sync.Mutex
	sessions            map[string]*daemonSession
	pendingFlows        []event.NetworkFlowEvent
	rawNetworkMu        sync.Mutex
	unattributedRawSeen map[string]time.Time
}

func newDaemonSessions() *daemonSessions {
	return &daemonSessions{
		sessions:            make(map[string]*daemonSession),
		unattributedRawSeen: make(map[string]time.Time),
	}
}

func (s *daemonSessions) forSemantic(ev event.SemanticEvent) *daemonSession {
	return s.getOrCreate(ev.Session.ID)
}

func (s *daemonSessions) getOrCreate(sessionID string) *daemonSession {
	sessionID = normalizedSessionID(sessionID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[sessionID]; ok {
		return sess
	}
	sess := &daemonSession{
		id:             sessionID,
		state:          correlator.NewSessionState(),
		subagents:      newSubagentMonitor(),
		lastActivity:   time.Now(),
		rawNetworkSeen: make(map[string]time.Time),
	}
	s.sessions[sessionID] = sess
	return sess
}

func (s *daemonSessions) getExisting(sessionID string) (*daemonSession, bool) {
	if s == nil {
		return nil, false
	}
	sessionID = normalizedSessionID(sessionID)
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	return sess, ok
}

func (s *daemonSessions) recordActivity(sess *daemonSession, at time.Time) {
	if s == nil || sess == nil {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sessions[sess.id]
	if !ok {
		return
	}
	if current.lastActivity.IsZero() || at.After(current.lastActivity) {
		current.lastActivity = at
	}
}

func (s *daemonSessions) list() []*daemonSession {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*daemonSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	return out
}

func (s *daemonSessions) applyProcessSnapshot(processes map[int]correlator.ProcessInfo) subagentEvents {
	var out subagentEvents
	for _, sess := range s.list() {
		sess.state.ApplyProcessSnapshot(processes)
		out.append(sess.subagents.observe(processes, cwdForPID))
	}
	s.pruneIdle(time.Now(), processes, defaultDaemonSessionIdle)
	return out
}

func (s *daemonSessions) applyProcessSnapshotToStates(processes map[int]correlator.ProcessInfo) {
	for _, sess := range s.list() {
		sess.state.ApplyProcessSnapshot(processes)
	}
	s.pruneIdle(time.Now(), processes, defaultDaemonSessionIdle)
}

// applyProcessSnapshotAndMatch applies the process snapshot to every session and
// returns the candidates that own the flow, in a single pass over the session
// list. Network handling needs both, so this avoids walking the session slice
// (and re-pruning each session's process graph) twice per flow.
func (s *daemonSessions) applyProcessSnapshotAndMatch(processes map[int]correlator.ProcessInfo, nf event.NetworkFlowEvent) []*daemonSession {
	var out []*daemonSession
	for _, sess := range s.list() {
		sess.state.ApplyProcessSnapshot(processes)
		if sess.state.MatchesNetworkFlow(nf) {
			out = append(out, sess)
		}
	}
	s.pruneIdle(time.Now(), processes, defaultDaemonSessionIdle)
	return out
}

func (s *daemonSessions) candidatesForNetwork(nf event.NetworkFlowEvent) []*daemonSession {
	var out []*daemonSession
	for _, sess := range s.list() {
		if sess.state.MatchesNetworkFlow(nf) {
			out = append(out, sess)
		}
	}
	return out
}

func (s *daemonSessions) anySessionMatchesNetworkFlow(nf event.NetworkFlowEvent) bool {
	for _, sess := range s.list() {
		if sess.state.MatchesNetworkFlow(nf) {
			return true
		}
	}
	return false
}

func (s *daemonSessions) anyAgentPID(pid int) bool {
	if pid <= 0 {
		return false
	}
	for _, sess := range s.list() {
		if sess.state.IsAgentPID(pid) {
			return true
		}
	}
	return false
}

func (s *daemonSessions) holdPendingNetworkFlow(nf event.NetworkFlowEvent, now time.Time) {
	if s == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prunePendingFlowsLocked(now)
	s.pendingFlows = append(s.pendingFlows, nf)
	if len(s.pendingFlows) > maxPendingNetworkFlows {
		s.pendingFlows = s.pendingFlows[len(s.pendingFlows)-maxPendingNetworkFlows:]
	}
}

func (s *daemonSessions) drainPendingForSession(sess *daemonSession, now time.Time) []event.NetworkFlowEvent {
	if s == nil || sess == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var matched []event.NetworkFlowEvent
	kept := s.pendingFlows[:0]
	for _, flow := range s.pendingFlows {
		if pendingFlowExpired(flow, now) {
			continue
		}
		if sess.state.MatchesNetworkFlow(flow) {
			matched = append(matched, flow)
			continue
		}
		kept = append(kept, flow)
	}
	s.pendingFlows = kept
	return matched
}

func (s *daemonSessions) pruneIdle(now time.Time, processes map[int]correlator.ProcessInfo, idle time.Duration) {
	if s == nil || idle <= 0 {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var pruned []string
	for id, sess := range s.sessions {
		last := sess.lastActivity
		if last.IsZero() {
			last = sess.state.StartTime
		}
		if now.Sub(last) <= idle {
			continue
		}
		if sess.state.HasLiveAgentPID(processes) {
			continue
		}
		delete(s.sessions, id)
		pruned = append(pruned, id)
	}
	s.prunePendingFlowsLocked(now)
	if len(pruned) > 0 {
		go purgeInspectPayloadsForEndedSessions(pruned)
	}
}

func purgeInspectPayloadsForEndedSessions(sessionIDs []string) {
	if err := inspect.PurgePayloadsForEndedSessions(inspect.DefaultPaths(), sessionIDs); err != nil {
		log.Printf("inspect payload session-end retention purge failed: %v", err)
	}
}

func (s *daemonSessions) prunePendingFlowsLocked(now time.Time) {
	kept := s.pendingFlows[:0]
	for _, flow := range s.pendingFlows {
		if pendingFlowExpired(flow, now) {
			continue
		}
		kept = append(kept, flow)
	}
	s.pendingFlows = kept
}

func (s *daemonSessions) pendingCount() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pendingFlows)
}

func pendingFlowExpired(flow event.NetworkFlowEvent, now time.Time) bool {
	if flow.TS.IsZero() {
		return false
	}
	return now.Sub(flow.TS) > correlator.ExistingConnectionWindow
}

func normalizedSessionID(sessionID string) string {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return "unknown-session"
	}
	return sessionID
}
