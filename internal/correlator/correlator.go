package correlator

import (
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/somoore/agentsnitch/config"
	"github.com/somoore/agentsnitch/internal/event"
)

const (
	// MaxRecentEvents caps the semantic event ring buffer.
	MaxRecentEvents = 50
	// MaxRecentFlows caps the network flow ring buffer used for semantic-triggered
	// correlation against already-active connections.
	MaxRecentFlows = 100
)

var defaultHeuristics = config.DefaultHeuristics()

var (
	// CorrelationWindow is the default time window for naive joins.
	CorrelationWindow = time.Duration(defaultHeuristics.Correlation.CorrelationWindowSeconds) * time.Second
	// ExistingConnectionWindow is the short lookback for annotating an
	// established connection that was already active when sensitive context was
	// touched. This is lower confidence than a flow created after access.
	ExistingConnectionWindow = time.Duration(defaultHeuristics.Correlation.ExistingConnectionWindowSeconds) * time.Second
	// ProcessTTL avoids treating reused PIDs as part of an old agent session forever.
	ProcessTTL = time.Duration(defaultHeuristics.Correlation.ProcessTTLMinutes) * time.Minute
	// MaxAncestorDepth caps process graph walks.
	MaxAncestorDepth = defaultHeuristics.Correlation.MaxAncestorDepth
)

// ProcessInfo is the daemon's short-lived view of a local process.
type ProcessInfo struct {
	PID           int
	PPID          int
	Name          string
	StartedAt     time.Time
	Source        string
	AgentID       string
	AgentKind     string
	IsAgentBinary bool
	TrackAsAgent  bool
	LastSeen      time.Time
}

type ToolSpan struct {
	SessionID string
	SpanID    string
	ToolUseID string
	Tool      string
	Target    string
	StartedAt time.Time
	Egress    bool
}

// SessionState holds the in-memory view of the current agent session for
// correlation and basic process tracking. It is the core of the daemon's
// "current session" as described in architecture.md §3.3 and §4.
type SessionState struct {
	mu sync.Mutex

	// Events is a ring (slice trimmed to last N, oldest first).
	Events []event.SemanticEvent

	// Flows is a ring of recent network flows. It lets a later sensitive hook
	// annotate an established connection that was already active.
	Flows []event.NetworkFlowEvent

	// KnownPIDs tracks PIDs observed in this session (seeded by semantic events
	// and augmented by snapshots or future process tree walking).
	KnownPIDs map[int]struct{}

	// Processes tracks PID -> PPID edges for short-lived ancestry matching.
	Processes map[int]ProcessInfo

	// HasSensitive is a simple taint flag for the session.
	HasSensitive bool

	// CorrelatedKeys suppresses duplicate evidence cards for the same semantic
	// event(s) and stable flow identity while allowing later distinct hooks to
	// link to the same active connection.
	CorrelatedKeys map[string]time.Time

	// SemanticBestStrength tracks the strongest emitted relationship per
	// semantic tool-use. It prevents a correct direct PID match from being
	// followed by weaker sibling/ancestor cards for the same hook.
	SemanticBestStrength map[string]int

	// DestinationSeen tracks destinations already surfaced as linked evidence
	// in this session so first-time destinations can stay visible.
	DestinationSeen map[string]struct{}

	// NoisyPatternSeen tracks expected network-heavy tool patterns that have
	// already been surfaced once in this session.
	NoisyPatternSeen map[string]struct{}

	// ActiveToolSpans tracks egress-capable PreToolUse events that have not yet
	// reached their matching PostToolUse. It is used by the inspect proxy path to
	// avoid claiming active ToolSpan correlation from session membership alone.
	ActiveToolSpans map[string]ToolSpan

	// StartTime is when this session object was created (or first event).
	StartTime time.Time
}

// NewSessionState creates a fresh session state.
func NewSessionState() *SessionState {
	return &SessionState{
		Events:               make([]event.SemanticEvent, 0, MaxRecentEvents),
		Flows:                make([]event.NetworkFlowEvent, 0, MaxRecentFlows),
		KnownPIDs:            make(map[int]struct{}),
		Processes:            make(map[int]ProcessInfo),
		CorrelatedKeys:       make(map[string]time.Time),
		SemanticBestStrength: make(map[string]int),
		DestinationSeen:      make(map[string]struct{}),
		NoisyPatternSeen:     make(map[string]struct{}),
		ActiveToolSpans:      make(map[string]ToolSpan),
		StartTime:            time.Now(),
	}
}

// AddPID explicitly registers a PID as belonging to the current agent session.
func (s *SessionState) AddPID(pid int) {
	if pid <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addProcessLocked(ProcessInfo{PID: pid, Source: "manual", TrackAsAgent: true})
}

// IsAgentPID reports whether pid is known to belong to this session's process tree.
func (s *SessionState) IsAgentPID(pid int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredProcessesLocked(time.Now())
	_, ok := s.KnownPIDs[pid]
	return ok
}

// MatchesNetworkFlow reports whether a flow is plausibly inside this session's
// process graph. It intentionally uses broader process ancestry than direct
// KnownPIDs so daemon routing can over-include and leave evidentiary claims to
// TryCorrelate.
func (s *SessionState) MatchesNetworkFlow(flow event.NetworkFlowEvent) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredProcessesLocked(time.Now())
	if s.pidInSet(flow.PID) || s.pidInSet(flow.PPID) {
		return true
	}
	return len(s.trackedLineageLocked(flow.PID, flow.PPID)) > 0
}

// HasLiveAgentPID reports whether any currently-known session PID is still
// present in the supplied process snapshot.
func (s *SessionState) HasLiveAgentPID(processes map[int]ProcessInfo) bool {
	if len(processes) == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredProcessesLocked(time.Now())
	for pid := range s.KnownPIDs {
		if _, ok := processes[pid]; ok {
			return true
		}
	}
	return false
}

// AddProcess registers a process edge for ancestry matching.
func (s *SessionState) AddProcess(pid, ppid int, name, source string) {
	if pid <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addProcessLocked(ProcessInfo{PID: pid, PPID: ppid, Name: name, Source: source, TrackAsAgent: true})
}

// ApplyProcessSnapshot enriches the session process graph from a point-in-time
// process table. It learns ancestors and descendants of already-known agent
// PIDs, and marks recognized agent binaries separately from ordinary helpers.
func (s *SessionState) ApplyProcessSnapshot(processes map[int]ProcessInfo) {
	if len(processes) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.pruneExpiredProcessesLocked(now)

	children := make(map[int][]int, len(processes))
	for pid, info := range processes {
		info.PID = pid
		info.Source = joinSource(info.Source, "snapshot")
		annotateAgentProcess(&info)
		processes[pid] = info
		if info.PPID > 0 {
			children[info.PPID] = append(children[info.PPID], pid)
		}
	}

	seed := make(map[int]struct{}, len(s.Processes))
	for pid := range s.KnownPIDs {
		if info, ok := processes[pid]; ok {
			if processIdentityChanged(s.Processes[pid], info) {
				delete(s.KnownPIDs, pid)
				delete(s.Processes, pid)
				continue
			}
			seed[pid] = struct{}{}
		}
	}
	for pid, info := range processes {
		if info.IsAgentBinary && strings.HasSuffix(info.AgentKind, "_cli") {
			seed[pid] = struct{}{}
		}
	}

	for pid := range seed {
		s.addProcessLocked(withAgentTracking(processes[pid], "snapshot-seed"))
		s.learnAncestorsLocked(pid, processes)
		s.learnDescendantsLocked(pid, children, processes)
	}
}

// AddSemanticEvent ingests a semantic event, updates PID set, taint flags,
// and appends to the recent events ring (trimming as needed).
func (s *SessionState) AddSemanticEvent(e event.SemanticEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e.PID > 0 {
		s.addProcessLocked(ProcessInfo{PID: e.PID, PPID: e.PPID, Name: e.Tool, Source: "hook", TrackAsAgent: true})
	}
	if e.PPID > 0 {
		s.addProcessLocked(ProcessInfo{PID: e.PPID, Source: "hook-parent", TrackAsAgent: true})
	}

	for _, t := range e.Tags {
		if t == "sensitive_read" || t == "credential_output" || t == "structured_secret" {
			s.HasSensitive = true
			break
		}
	}
	s.updateActiveToolSpanLocked(e)

	s.Events = append(s.Events, e)
	if len(s.Events) > MaxRecentEvents {
		s.Events = s.Events[len(s.Events)-MaxRecentEvents:]
	}
}

// AddNetworkFlow ingests a network flow. It enriches the process graph but does
// not mark the flow PID as an agent-session member by itself.
func (s *SessionState) AddNetworkFlow(f event.NetworkFlowEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.PID > 0 {
		s.addProcessLocked(ProcessInfo{PID: f.PID, PPID: f.PPID, Name: f.ProcessPath, Source: "network"})
	}
	if f.PPID > 0 {
		s.addProcessLocked(ProcessInfo{PID: f.PPID, Source: "network-parent"})
	}
	s.Flows = append(s.Flows, f)
	if len(s.Flows) > MaxRecentFlows {
		s.Flows = s.Flows[len(s.Flows)-MaxRecentFlows:]
	}
}

// GetRecent returns a copy of the most recent semantic events (up to MaxRecentEvents).
func (s *SessionState) GetRecent() []event.SemanticEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]event.SemanticEvent, len(s.Events))
	copy(out, s.Events)
	return out
}

func (s *SessionState) ActiveToolSpan(toolUseID string) (ToolSpan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeToolSpanLocked(toolUseID)
}

func (s *SessionState) ActiveEgressToolSpan() (ToolSpan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeToolSpanLocked("")
}

func (s *SessionState) updateActiveToolSpanLocked(e event.SemanticEvent) {
	toolUseID := strings.TrimSpace(e.ToolUseID)
	if toolUseID == "" {
		return
	}
	switch strings.ToLower(strings.TrimSpace(e.Event)) {
	case "pretooluse":
		if !e.IsEgressLike() {
			return
		}
		started := e.TS
		if started.IsZero() {
			started = time.Now()
		}
		s.ActiveToolSpans[toolUseID] = ToolSpan{
			SessionID: e.Session.ID,
			SpanID:    toolUseID,
			ToolUseID: toolUseID,
			Tool:      e.Tool,
			Target:    e.Target,
			StartedAt: started,
			Egress:    true,
		}
	case "posttooluse", "posttoolusefailure":
		delete(s.ActiveToolSpans, toolUseID)
	}
}

func (s *SessionState) activeToolSpanLocked(toolUseID string) (ToolSpan, bool) {
	if toolUseID != "" {
		span, ok := s.ActiveToolSpans[toolUseID]
		return span, ok
	}
	var newest ToolSpan
	var ok bool
	for _, span := range s.ActiveToolSpans {
		if !span.Egress {
			continue
		}
		if !ok || span.StartedAt.After(newest.StartedAt) {
			newest = span
			ok = true
		}
	}
	return newest, ok
}

// TryCorrelate attempts a conservative time + process join for the given flow
// against recent semantic events. MVP correlation requires a direct PID/PPID
// relationship; broad session taint alone is not enough to highlight a flow.
func (s *SessionState) TryCorrelate(flow event.NetworkFlowEvent) []event.Correlation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tryCorrelateFlowLocked(flow)
}

// TryCorrelateSemantic attempts correlations caused by a newly-arrived semantic
// event, especially "existing_connection_active" links where the network flow
// was observed before sensitive context was touched.
func (s *SessionState) TryCorrelateSemantic(e event.SemanticEvent) []event.Correlation {
	if !hasSensitiveTag(e) && !isEgressLike(e) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := e.TS
	if now.IsZero() {
		now = time.Now()
	}
	s.pruneExpiredProcessesLocked(now)

	var out []event.Correlation
	seenFlows := make(map[string]struct{}, len(s.Flows))
	for i := len(s.Flows) - 1; i >= 0; i-- {
		flow := s.Flows[i]
		if flow.TS.IsZero() {
			continue
		}
		if flow.TS.After(now) {
			continue
		}
		if now.Sub(flow.TS) > ExistingConnectionWindow {
			break
		}
		flowKey := flowCorrelationKey(flow)
		if _, ok := seenFlows[flowKey]; ok {
			continue
		}
		seenFlows[flowKey] = struct{}{}
		corrs := s.tryCorrelateFlowLocked(flow)
		for _, corr := range corrs {
			if correlationIncludesToolUse(corr, e.ToolUseID) || semanticSameProcessAndTime(corr, e) {
				out = append(out, corr)
			}
		}
	}
	return out
}

func (s *SessionState) tryCorrelateFlowLocked(flow event.NetworkFlowEvent) []event.Correlation {
	if !flow.IsExternal() {
		return nil
	}

	now := flow.TS
	if now.IsZero() {
		now = time.Now()
	}
	s.pruneExpiredProcessesLocked(now)

	var related []event.SemanticEvent
	reasonSet := map[string]struct{}{}
	hasSensitiveRelated := false
	for i := len(s.Events) - 1; i >= 0; i-- {
		e := s.Events[i]
		intentMatch := destinationIntentMatchesFlow(e, flow)
		timingReasons := timingReasons(e, flow, now)
		if len(timingReasons) == 0 {
			timingReasons = destinationIntentTimingReasons(e, flow, now, intentMatch)
			if len(timingReasons) == 0 {
				continue
			}
		}

		matchReasons := s.processMatchReasonsLocked(e, flow)
		if isEgressLike(e) && !hasSensitiveTag(e) && len(e.DestinationIntents) > 0 && !intentMatch && flowHasStrongObservedHostname(flow) {
			continue
		}
		if len(matchReasons) == 0 && intentMatch && sameAgentSession(e.Agent, flow.Agent) {
			matchReasons = append(matchReasons, "same_agent_session")
		}
		if len(matchReasons) == 0 {
			continue
		}
		if hasSensitiveTag(e) || isEgressLike(e) {
			related = append(related, e)
			for _, r := range timingReasons {
				reasonSet[r] = struct{}{}
			}
			for _, r := range matchReasons {
				reasonSet[r] = struct{}{}
			}
			if intentMatch {
				reasonSet["destination_intent_match"] = struct{}{}
			}
			if hasSensitiveTag(e) {
				hasSensitiveRelated = true
			}
		}
	}

	if len(related) == 0 {
		return nil
	}

	if hasSensitiveRelated {
		reasonSet["after_sensitive_read"] = struct{}{}
	}
	firstDestination := s.isFirstCorrelationDestinationLocked(flow)
	if firstDestination {
		reasonSet["first_destination"] = struct{}{}
	}
	if isHighByteFlow(flow) && !hasReason(reasonSet, "existing_connection_active") {
		reasonSet["high_bytes"] = struct{}{}
	}
	reasons := make([]string, 0, len(reasonSet))
	for _, r := range []string{"within_10s", "existing_connection_active", "pid_match", "parent_match", "ancestor_match", "common_agent_ancestor", "same_agent_session", "known_agent_binary_match", "mcp_server_flow", "destination_intent_match", "first_destination", "high_bytes", "after_sensitive_read"} {
		if _, ok := reasonSet[r]; ok {
			reasons = append(reasons, r)
		}
	}
	confidence := confidenceForReasons(reasonSet)
	key := correlationKey(related, flow)
	if key != "" {
		if _, ok := s.CorrelatedKeys[key]; ok {
			return nil
		}
		s.CorrelatedKeys[key] = time.Now()
	}

	primary := primarySemanticEvent(related)
	corr := event.Correlation{
		Schema:      event.SchemaCorrelatedV0,
		TS:          time.Now().UTC(),
		Agent:       &primary.Agent,
		SemanticIDs: semanticIDs(related),
		FlowIDs:     flowIDs(flow),
		Reasons:     reasons,
		Score:       scoreForReasons(confidence, reasonSet),
		Confidence:  confidence,
		Summary:     evidenceSummary(related, flow, reasons),
		Semantics:   related,
		Flows:       []event.NetworkFlowEvent{flow},
		ProcessTree: s.processTreeEvidenceLocked(related, flow),
	}
	if !s.shouldEmitCorrelationLocked(corr, flow) {
		return nil
	}
	s.markCorrelationDestinationLocked(flow)
	return []event.Correlation{corr}
}

func (s *SessionState) shouldEmitCorrelationLocked(corr event.Correlation, flow event.NetworkFlowEvent) bool {
	keys := semanticSuppressionKeys(corr.Semantics)
	if len(keys) == 0 {
		return true
	}
	if s.shouldSuppressNoisyPatternLocked(corr, flow) {
		return false
	}
	strength := correlationStrength(corr.Reasons)
	allHaveStronger := true
	for _, key := range keys {
		if s.SemanticBestStrength[key] <= strength {
			allHaveStronger = false
			break
		}
	}
	if allHaveStronger {
		return false
	}
	for _, key := range keys {
		if strength > s.SemanticBestStrength[key] {
			s.SemanticBestStrength[key] = strength
		}
	}
	return true
}

func (s *SessionState) shouldSuppressNoisyPatternLocked(corr event.Correlation, flow event.NetworkFlowEvent) bool {
	if containsString(corr.Reasons, "after_sensitive_read") ||
		containsString(corr.Reasons, "high_bytes") {
		return false
	}
	primary := primarySemanticEvent(corr.Semantics)
	family := noisyAutomationFamily(primary)
	if family == "" {
		return false
	}
	dest := destinationKey(flow)
	if dest == "" {
		dest = "unknown"
	}
	key := family + "|" + dest
	_, seen := s.NoisyPatternSeen[key]
	s.NoisyPatternSeen[key] = struct{}{}
	if seen && !containsString(corr.Reasons, "first_destination") {
		return true
	}
	return false
}

func semanticSuppressionKeys(events []event.SemanticEvent) []string {
	keys := make([]string, 0, len(events))
	for _, ev := range events {
		if ev.ToolUseID != "" {
			keys = append(keys, ev.ToolUseID)
			continue
		}
		if !ev.TS.IsZero() || ev.PID > 0 || ev.Tool != "" {
			keys = append(keys, fmt.Sprintf("%s|%d|%s|%s", ev.TS.Format(time.RFC3339Nano), ev.PID, ev.Event, ev.Tool))
		}
	}
	return uniqueStrings(keys)
}

func correlationStrength(reasons []string) int {
	switch {
	case containsString(reasons, "pid_match"):
		return 50
	case containsString(reasons, "parent_match"):
		return 40
	case containsString(reasons, "ancestor_match"):
		return 30
	case containsString(reasons, "common_agent_ancestor"):
		return 20
	case containsString(reasons, "same_agent_session"):
		return 10
	case containsString(reasons, "known_agent_binary_match"):
		return 5
	default:
		return 1
	}
}

func semanticIDs(events []event.SemanticEvent) []string {
	ids := make([]string, 0, len(events))
	for _, ev := range events {
		if ev.ToolUseID != "" {
			ids = append(ids, ev.ToolUseID)
		}
	}
	return uniqueStrings(ids)
}

func correlationKey(events []event.SemanticEvent, flow event.NetworkFlowEvent) string {
	ids := semanticIDs(events)
	if len(ids) == 0 {
		return ""
	}
	return strings.Join(ids, ",") + "|" + flowCorrelationKey(flow)
}

func flowIDs(flow event.NetworkFlowEvent) []string {
	if flow.FlowID == "" {
		return nil
	}
	return []string{flow.FlowID}
}

func (s *SessionState) processTreeEvidenceLocked(related []event.SemanticEvent, flow event.NetworkFlowEvent) []event.ProcessNode {
	builder := processTreeBuilder{index: map[int]int{}}
	for _, sem := range related {
		builder.add(sem.PID, sem.PPID, sem.Tool, "hook", "hook")
		builder.add(sem.PPID, 0, "", "hook-parent", "hook_parent")
		s.addProcessAncestorsLocked(&builder, sem.PID, "hook_ancestor")
	}
	builder.add(flow.PID, flow.PPID, flow.ProcessPath, "network", "flow")
	builder.add(flow.PPID, 0, "", "network-parent", "flow_parent")
	s.addProcessAncestorsLocked(&builder, flow.PID, "flow_ancestor")
	if len(builder.nodes) == 0 {
		return nil
	}
	return builder.nodes
}

type processTreeBuilder struct {
	nodes []event.ProcessNode
	index map[int]int
}

func (b *processTreeBuilder) add(pid, ppid int, name, source, role string) {
	if pid <= 0 {
		return
	}
	if idx, ok := b.index[pid]; ok {
		node := &b.nodes[idx]
		if node.PPID == 0 {
			node.PPID = ppid
		}
		if node.Name == "" {
			node.Name = name
		}
		if node.Source == "" {
			node.Source = source
		}
		node.Role = appendRole(node.Role, role)
		return
	}
	b.index[pid] = len(b.nodes)
	b.nodes = append(b.nodes, event.ProcessNode{
		PID:    pid,
		PPID:   ppid,
		Name:   strings.TrimSpace(name),
		Source: strings.TrimSpace(source),
		Role:   strings.TrimSpace(role),
	})
}

func (s *SessionState) addProcessAncestorsLocked(builder *processTreeBuilder, pid int, role string) {
	current := pid
	for depth := 0; depth < MaxAncestorDepth; depth++ {
		info, ok := s.Processes[current]
		if !ok || info.PPID <= 0 {
			return
		}
		parent, ok := s.Processes[info.PPID]
		if !ok {
			builder.add(info.PPID, 0, "", "process-parent", role)
			return
		}
		builder.add(parent.PID, parent.PPID, parent.Name, parent.Source, role)
		current = parent.PID
	}
}

func appendRole(existing, next string) string {
	existing = strings.TrimSpace(existing)
	next = strings.TrimSpace(next)
	if next == "" {
		return existing
	}
	if existing == "" {
		return next
	}
	for _, role := range strings.Split(existing, ",") {
		if strings.TrimSpace(role) == next {
			return existing
		}
	}
	return existing + "," + next
}

func correlationIncludesToolUse(c event.Correlation, toolUseID string) bool {
	if toolUseID == "" {
		return false
	}
	for _, sem := range c.Semantics {
		if sem.ToolUseID == toolUseID {
			return true
		}
	}
	return false
}

func semanticSameProcessAndTime(c event.Correlation, target event.SemanticEvent) bool {
	if target.PID <= 0 || target.TS.IsZero() {
		return false
	}
	for _, sem := range c.Semantics {
		if sem.PID == target.PID && sem.TS.Equal(target.TS) && sem.Tool == target.Tool {
			return true
		}
	}
	return false
}

func flowCorrelationKey(flow event.NetworkFlowEvent) string {
	// Some development observers cannot provide a stable flow_id across samples.
	// PID/local/remote/protocol is the stable identity for one active socket.
	parts := []string{
		fmt.Sprintf("%d", flow.PID),
		flow.Local,
		flow.Remote,
		strings.ToLower(flow.Protocol),
	}
	return strings.Join(parts, "|")
}

func (s *SessionState) isFirstCorrelationDestinationLocked(flow event.NetworkFlowEvent) bool {
	dest := destinationKey(flow)
	if dest == "" {
		return false
	}
	_, seen := s.DestinationSeen[dest]
	return !seen
}

func (s *SessionState) markCorrelationDestinationLocked(flow event.NetworkFlowEvent) {
	dest := destinationKey(flow)
	if dest == "" {
		return
	}
	s.DestinationSeen[dest] = struct{}{}
}

func destinationKey(flow event.NetworkFlowEvent) string {
	if flow.SNI != "" {
		return strings.ToLower(strings.TrimSpace(flow.SNI))
	}
	if flow.Hostname != "" {
		return strings.ToLower(strings.TrimSpace(flow.Hostname))
	}
	remote := strings.TrimSpace(flow.Remote)
	if remote == "" {
		return ""
	}
	host := remote
	if strings.Count(remote, ":") == 1 {
		if before, _, ok := strings.Cut(remote, ":"); ok {
			host = before
		}
	} else {
		host = strings.Trim(remote, "[]")
	}
	return strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
}

func destinationIntentMatchesFlow(e event.SemanticEvent, flow event.NetworkFlowEvent) bool {
	if len(e.DestinationIntents) == 0 {
		return false
	}
	flowDestinations := flowDestinationCandidates(flow)
	if len(flowDestinations) == 0 {
		return false
	}
	for _, intent := range e.DestinationIntents {
		intent = normalizeDestinationHost(intent)
		if intent == "" {
			continue
		}
		for _, dest := range flowDestinations {
			if destinationHostMatches(intent, dest) {
				return true
			}
		}
	}
	return false
}

func flowHasStrongObservedHostname(flow event.NetworkFlowEvent) bool {
	if host := normalizeDestinationHost(flow.SNI); host != "" && net.ParseIP(host) == nil {
		return true
	}
	host := normalizeDestinationHost(flow.Hostname)
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(flow.HostnameSource)) {
	case "network_statistics", "ptr", "reverse_dns":
		return false
	default:
		return true
	}
}

func flowDestinationCandidates(flow event.NetworkFlowEvent) []string {
	candidates := []string{
		flow.SNI,
		flow.Hostname,
		destinationKey(event.NetworkFlowEvent{Remote: flow.Remote}),
	}
	out := make([]string, 0, len(candidates))
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		candidate = normalizeDestinationHost(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func normalizeDestinationHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	value = strings.Trim(value, "[]")
	if before, _, ok := strings.Cut(value, "/"); ok {
		value = before
	}
	if before, _, ok := strings.Cut(value, "?"); ok {
		value = before
	}
	if strings.Count(value, ":") == 1 {
		if before, _, ok := strings.Cut(value, ":"); ok {
			value = before
		}
	}
	return strings.Trim(value, ".")
}

func destinationHostMatches(intent, observed string) bool {
	if intent == "" || observed == "" {
		return false
	}
	return observed == intent || strings.HasSuffix(observed, "."+intent)
}

func sameAgentSession(a event.AgentInfo, b *event.AgentInfo) bool {
	if b == nil {
		return false
	}
	if a.ID != "" && b.ID != "" && a.ID == b.ID {
		return true
	}
	if a.PID > 0 && b.PID > 0 && a.PID == b.PID {
		return true
	}
	return false
}

func isHighByteFlow(flow event.NetworkFlowEvent) bool {
	threshold := defaultHeuristics.Correlation.HighByteThreshold
	return flow.BytesOut >= threshold || flow.BytesIn >= threshold
}

func timingReasons(e event.SemanticEvent, flow event.NetworkFlowEvent, now time.Time) []string {
	if e.TS.IsZero() {
		return nil
	}
	delta := now.Sub(e.TS)
	if delta >= 0 && delta <= CorrelationWindow {
		return []string{"within_10s"}
	}
	if delta < 0 && -delta <= ExistingConnectionWindow && (hasSensitiveTag(e) || isEgressLike(e)) && isActiveFlow(flow) {
		return []string{"existing_connection_active"}
	}
	return nil
}

func destinationIntentTimingReasons(e event.SemanticEvent, flow event.NetworkFlowEvent, now time.Time, intentMatch bool) []string {
	if !intentMatch || e.TS.IsZero() || !isEgressLike(e) || hasSensitiveTag(e) || !strings.EqualFold(flow.State, "new") {
		return nil
	}
	delta := now.Sub(e.TS)
	if delta >= 0 && delta <= CorrelationWindow {
		return []string{"within_10s"}
	}
	return nil
}

func (s *SessionState) processMatchReasonsLocked(e event.SemanticEvent, flow event.NetworkFlowEvent) []string {
	if flow.PID <= 0 {
		return nil
	}
	if s.semanticProcessStaleLocked(e, e.PID) || s.semanticProcessStaleLocked(e, e.PPID) {
		return nil
	}
	var reasons []string
	if e.PID > 0 && e.PID == flow.PID {
		if e.PPID > 0 && flow.PPID > 0 && e.PPID != flow.PPID {
			return nil
		}
		reasons = append(reasons, "pid_match")
	} else {
		if e.PPID > 0 && e.PPID == flow.PID {
			reasons = append(reasons, "parent_match")
		}
		if flow.PPID > 0 {
			if e.PID > 0 && e.PID == flow.PPID {
				reasons = append(reasons, "parent_match")
			} else if e.PPID > 0 && e.PPID == flow.PPID {
				reasons = append(reasons, "same_agent_session")
			}
		}
		if len(reasons) == 0 && e.PID > 0 && s.isAncestorLocked(e.PID, flow.PID) {
			reasons = append(reasons, "ancestor_match")
		}
		if len(reasons) == 0 && e.PPID > 0 && s.isAncestorLocked(e.PPID, flow.PID) {
			reasons = append(reasons, "ancestor_match")
		}
		if len(reasons) == 0 && flow.PID > 0 && s.isAncestorLocked(flow.PID, e.PID) {
			reasons = append(reasons, "ancestor_match")
		}
		if len(reasons) == 0 && s.commonTrackedAncestorLocked(e, flow) {
			reasons = append(reasons, "common_agent_ancestor")
		}
		if len(reasons) == 0 && e.PPID > 0 && flow.PPID > 0 && e.PPID == flow.PPID {
			reasons = append(reasons, "same_agent_session")
		}
	}
	if len(reasons) > 0 {
		if s.knownAgentBinaryMatchLocked(e, flow) {
			reasons = append(reasons, "known_agent_binary_match")
		}
		if isMCPToolEvent(e) && s.flowLooksLikeMCPServerLocked(flow) {
			reasons = append(reasons, "mcp_server_flow")
		}
	}
	return uniqueStrings(reasons)
}

func (s *SessionState) semanticProcessStaleLocked(e event.SemanticEvent, pid int) bool {
	if pid <= 0 || e.TS.IsZero() {
		return false
	}
	info, ok := s.Processes[pid]
	if !ok || info.StartedAt.IsZero() {
		return false
	}
	return info.StartedAt.After(e.TS)
}

func evidenceSummary(related []event.SemanticEvent, flow event.NetworkFlowEvent, reasons []string) string {
	primary := primarySemanticEvent(related)
	agentName := agentDisplayName(primary.Agent)
	if agentName == "" {
		agentName = "agent"
	}

	action := semanticAction(primary)
	delay := ""
	if !primary.TS.IsZero() && !flow.TS.IsZero() {
		delta := flow.TS.Sub(primary.TS)
		if delta < 0 {
			before := "tool event"
			if hasSensitiveTag(primary) {
				before = "access"
			}
			delay = fmt.Sprintf("; active %.1fs before %s", (-delta).Seconds(), before)
		} else {
			delay = fmt.Sprintf("; %.1fs later", delta.Seconds())
		}
	}

	remote := flow.Remote
	if remote == "" {
		remote = "unknown remote"
	}
	flowText := fmt.Sprintf("PID %d connected to %s", flow.PID, remote)
	if flow.SNI != "" {
		flowText += fmt.Sprintf(" (SNI: %s)", flow.SNI)
	} else if flow.Hostname != "" {
		source := strings.TrimSpace(flow.HostnameSource)
		if source == "" {
			source = "observer"
		}
		flowText += fmt.Sprintf(" (hostname: %s via %s)", flow.Hostname, source)
	} else if flow.PTRHostname != "" {
		flowText += fmt.Sprintf(" (PTR hint: %s)", flow.PTRHostname)
	}
	if flow.BytesOut > 0 {
		flowText += fmt.Sprintf(", %dB out", flow.BytesOut)
	}

	title := "Linked activity → outbound connection"
	if hasCredentialOutputTag(primary) {
		title = "Credential context → outbound connection"
	} else if hasSensitiveTag(primary) {
		title = "Sensitive read → outbound connection"
	} else if isLocalhostBridge(primary, flow) {
		title = "Local bridge → outbound connection"
	} else if containsString(reasons, "high_bytes") && isKnownClaudeFlow(flow) {
		title = "High-volume Claude service traffic"
	} else if containsString(reasons, "high_bytes") && isMCPToolEvent(primary) {
		title = "Large outbound flow after MCP tool"
	} else if containsString(reasons, "high_bytes") {
		title = "Large outbound flow after tool call"
	} else if isKnownClaudeFlow(flow) {
		title = "Claude service traffic"
	} else if isPlaywrightBridgeFlow(flow) {
		title = "Playwright bridge traffic"
	} else if containsString(reasons, "mcp_server_flow") {
		title = "Tool call → outbound connection"
	} else if isEgressLike(primary) {
		title = "Tool call → outbound connection"
	}

	return fmt.Sprintf("%s: %s %s%s: %s. Why linked: %s",
		title,
		agentName,
		action,
		delay,
		flowText,
		strings.Join(reasons, ", "),
	)
}

func agentDisplayName(agent event.AgentInfo) string {
	if agent.Name != "" {
		return agent.Name
	}
	switch strings.ToLower(agent.ID) {
	case "claude":
		return "Claude Code"
	case "codex":
		return "Codex"
	case "cursor":
		return "Cursor"
	case "gemini":
		return "Gemini"
	default:
		return agent.ID
	}
}

func primarySemanticEvent(events []event.SemanticEvent) event.SemanticEvent {
	for _, e := range events {
		if hasSensitiveTag(e) {
			return e
		}
	}
	if len(events) > 0 {
		return events[0]
	}
	return event.SemanticEvent{}
}

func semanticAction(e event.SemanticEvent) string {
	tool := e.Tool
	if tool == "" {
		tool = e.Event
	}
	target := e.Target
	if target == "" {
		if v, ok := e.InputSummary["file_path"].(string); ok {
			target = v
		} else if v, ok := e.InputSummary["command"].(string); ok {
			target = v
		}
	}
	if target == "" {
		return strings.TrimSpace(fmt.Sprintf("used %s", tool))
	}
	switch tool {
	case "Read":
		return "read " + target
	case "Bash":
		return "ran " + target
	default:
		return strings.TrimSpace(fmt.Sprintf("used %s %s", tool, target))
	}
}

func isLocalhostBridge(e event.SemanticEvent, flow event.NetworkFlowEvent) bool {
	if !flow.IsExternal() {
		return false
	}
	targets := []string{e.Target}
	if v, ok := e.InputSummary["url"].(string); ok {
		targets = append(targets, v)
	}
	if v, ok := e.InputSummary["command"].(string); ok {
		targets = append(targets, v)
	}
	for _, target := range targets {
		if looksLocalhost(target) {
			return true
		}
	}
	return false
}

func looksLocalhost(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(lower, "localhost") ||
		strings.Contains(lower, "127.0.0.1") ||
		strings.Contains(lower, "[::1]") ||
		strings.Contains(lower, "://::1")
}

func (s *SessionState) addProcessLocked(info ProcessInfo) {
	if info.PID <= 0 {
		return
	}
	now := time.Now()
	existing := s.Processes[info.PID]
	if processIdentityChanged(existing, info) {
		delete(s.KnownPIDs, info.PID)
		existing = ProcessInfo{}
	}
	if info.PPID == 0 {
		info.PPID = existing.PPID
	}
	if info.Name == "" {
		info.Name = existing.Name
	}
	if info.StartedAt.IsZero() {
		info.StartedAt = existing.StartedAt
	}
	if info.Source == "" {
		info.Source = existing.Source
	}
	if info.AgentID == "" {
		info.AgentID = existing.AgentID
	}
	if info.AgentKind == "" {
		info.AgentKind = existing.AgentKind
	}
	if !info.IsAgentBinary {
		info.IsAgentBinary = existing.IsAgentBinary
	}
	info.TrackAsAgent = info.TrackAsAgent || existing.TrackAsAgent
	annotateAgentProcess(&info)
	info.LastSeen = now
	s.Processes[info.PID] = info
	if shouldTrackAsAgentPID(info) {
		s.KnownPIDs[info.PID] = struct{}{}
	}
}

func processIdentityChanged(existing, incoming ProcessInfo) bool {
	if existing.PID <= 0 || incoming.PID <= 0 || existing.PID != incoming.PID {
		return false
	}
	if existingExec, incomingExec := processExecutableIdentity(existing.Name), processExecutableIdentity(incoming.Name); existingExec != "" && incomingExec != "" && existingExec != incomingExec {
		return true
	}
	if !existing.StartedAt.IsZero() && !incoming.StartedAt.IsZero() && !existing.StartedAt.Equal(incoming.StartedAt) {
		return true
	}
	if existing.PPID > 0 && incoming.PPID > 0 && existing.PPID != incoming.PPID && existing.Name != "" && incoming.Name != "" {
		return true
	}
	return false
}

func processExecutableIdentity(name string) string {
	first := strings.TrimSpace(name)
	if first == "" {
		return ""
	}
	fields := strings.Fields(first)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(filepath.Clean(fields[0]))
}

func (s *SessionState) learnAncestorsLocked(pid int, processes map[int]ProcessInfo) {
	current := pid
	for depth := 0; depth < MaxAncestorDepth; depth++ {
		info, ok := processes[current]
		if !ok || info.PPID <= 0 {
			return
		}
		parent, ok := processes[info.PPID]
		if !ok {
			return
		}
		s.addProcessLocked(withSource(parent, "snapshot-ancestor"))
		current = parent.PID
	}
}

func (s *SessionState) learnDescendantsLocked(root int, children map[int][]int, processes map[int]ProcessInfo) {
	queue := []int{root}
	seen := map[int]struct{}{root: {}}
	for depth := 0; depth < MaxAncestorDepth && len(queue) > 0; depth++ {
		current := queue[0]
		queue = queue[1:]
		for _, child := range children[current] {
			if _, ok := seen[child]; ok {
				continue
			}
			seen[child] = struct{}{}
			info, ok := processes[child]
			if !ok {
				continue
			}
			s.addProcessLocked(withAgentTracking(info, "snapshot-child"))
			queue = append(queue, child)
		}
	}
}

func (s *SessionState) pruneExpiredProcessesLocked(now time.Time) {
	cutoff := now.Add(-ProcessTTL)
	for pid, info := range s.Processes {
		if !info.LastSeen.IsZero() && info.LastSeen.Before(cutoff) {
			delete(s.Processes, pid)
			delete(s.KnownPIDs, pid)
		}
	}
}

func (s *SessionState) isAncestorLocked(ancestor, child int) bool {
	if ancestor <= 0 || child <= 0 || ancestor == child {
		return false
	}
	seen := map[int]struct{}{}
	current := child
	for depth := 0; depth < MaxAncestorDepth; depth++ {
		info, ok := s.Processes[current]
		if !ok || info.PPID <= 0 {
			return false
		}
		if info.PPID == ancestor {
			return true
		}
		if _, ok := seen[info.PPID]; ok {
			return false
		}
		seen[info.PPID] = struct{}{}
		current = info.PPID
	}
	return false
}

func (s *SessionState) commonTrackedAncestorLocked(e event.SemanticEvent, flow event.NetworkFlowEvent) bool {
	left := s.trackedLineageLocked(e.PID, e.PPID)
	if len(left) == 0 {
		return false
	}
	right := s.trackedLineageLocked(flow.PID, flow.PPID)
	for pid := range right {
		if _, ok := left[pid]; ok {
			return true
		}
	}
	return false
}

func (s *SessionState) trackedLineageLocked(pids ...int) map[int]struct{} {
	out := map[int]struct{}{}
	for _, pid := range pids {
		current := pid
		seen := map[int]struct{}{}
		for depth := 0; depth < MaxAncestorDepth && current > 0; depth++ {
			if _, ok := seen[current]; ok {
				break
			}
			seen[current] = struct{}{}
			if current > 1 && s.pidInSet(current) {
				out[current] = struct{}{}
			}
			info, ok := s.Processes[current]
			if !ok || info.PPID <= 0 {
				break
			}
			current = info.PPID
		}
	}
	return out
}

func confidenceForReasons(reasons map[string]struct{}) string {
	if _, ok := reasons["existing_connection_active"]; ok {
		return "low"
	}
	if _, ok := reasons["pid_match"]; ok {
		return "high"
	}
	if hasReason(reasons, "after_sensitive_read") && hasReason(reasons, "within_10s") {
		if hasReason(reasons, "parent_match") || hasReason(reasons, "ancestor_match") {
			return "high"
		}
		if hasReason(reasons, "same_agent_session") && hasReason(reasons, "known_agent_binary_match") {
			return "high"
		}
		if hasReason(reasons, "same_agent_session") {
			return "medium"
		}
		if hasReason(reasons, "common_agent_ancestor") {
			return "medium"
		}
	}
	if _, ok := reasons["parent_match"]; ok {
		return "medium"
	}
	if _, ok := reasons["ancestor_match"]; ok {
		return "medium"
	}
	if hasReason(reasons, "destination_intent_match") && hasReason(reasons, "same_agent_session") && hasReason(reasons, "within_10s") {
		return "medium"
	}
	if _, ok := reasons["common_agent_ancestor"]; ok {
		return "low"
	}
	if _, ok := reasons["same_agent_session"]; ok {
		return "low"
	}
	if _, ok := reasons["known_agent_binary_match"]; ok {
		return "low"
	}
	return "low"
}

func hasReason(reasons map[string]struct{}, reason string) bool {
	_, ok := reasons[reason]
	return ok
}

func scoreForConfidence(confidence string) float64 {
	switch confidence {
	case "high":
		return 1.0
	case "medium":
		return 0.75
	default:
		return 0.5
	}
}

func scoreForReasons(confidence string, reasons map[string]struct{}) float64 {
	score := scoreForConfidence(confidence)
	if hasReason(reasons, "high_bytes") {
		score += 0.15
	}
	if hasReason(reasons, "first_destination") {
		score += 0.10
	}
	if hasReason(reasons, "destination_intent_match") {
		score += 0.15
	}
	if score > 1.0 {
		return 1.0
	}
	return score
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func hasSensitiveTag(e event.SemanticEvent) bool {
	for _, t := range e.Tags {
		if t == "sensitive_read" || t == "credential_output" || t == "structured_secret" {
			return true
		}
	}
	return false
}

func hasCredentialOutputTag(e event.SemanticEvent) bool {
	for _, t := range e.Tags {
		if t == "credential_output" || t == "structured_secret" {
			return true
		}
	}
	return false
}

func isKnownClaudeFlow(flow event.NetworkFlowEvent) bool {
	host := flowHost(flow)
	return defaultHeuristics.HostMatchesAnyDomain(
		host,
		defaultHeuristics.DestinationCategoryDomains("known Claude service"),
	)
}

func isPlaywrightBridgeFlow(flow event.NetworkFlowEvent) bool {
	host := flowHost(flow)
	return defaultHeuristics.HostMatchesAnyDomain(
		host,
		defaultHeuristics.DestinationCategoryDomains("Playwright bridge traffic"),
	)
}

func flowHost(flow event.NetworkFlowEvent) string {
	host := strings.TrimSpace(flow.SNI)
	if host == "" {
		host = strings.TrimSpace(flow.Hostname)
	}
	if host == "" {
		host = strings.TrimSpace(flow.Remote)
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if before, _, ok := strings.Cut(host, ":"); ok {
		host = strings.Trim(before, "[]")
	}
	return host
}

func isEgressLike(e event.SemanticEvent) bool {
	for _, t := range e.Tags {
		if t == "external_egress_attempt" || t == "mcp_tool_use" {
			return true
		}
	}
	if strings.HasPrefix(strings.ToLower(e.Tool), "mcp__") {
		return true
	}
	if e.Tool == "WebFetch" || e.Tool == "WebSearch" {
		return true
	}
	return false
}

func isMCPToolEvent(e event.SemanticEvent) bool {
	if strings.HasPrefix(strings.ToLower(e.Tool), "mcp__") {
		return true
	}
	for _, t := range e.Tags {
		if t == "mcp_tool_use" {
			return true
		}
	}
	return false
}

func noisyAutomationFamily(e event.SemanticEvent) string {
	candidates := []string{e.Tool, e.Target}
	for _, key := range []string{"url", "command", "description"} {
		if value, ok := e.InputSummary[key].(string); ok {
			candidates = append(candidates, value)
		}
	}
	joined := strings.ToLower(strings.Join(candidates, " "))
	for _, rule := range defaultHeuristics.NoisyAutomation {
		if rule.RequiresLocalhost && !looksLocalhost(joined) {
			continue
		}
		for _, pattern := range rule.Contains {
			if strings.Contains(joined, strings.ToLower(pattern)) {
				return rule.Family
			}
		}
	}
	return ""
}

func (s *SessionState) flowLooksLikeMCPServerLocked(flow event.NetworkFlowEvent) bool {
	candidates := []string{flow.ProcessPath, flow.ProcessBundleID}
	if info, ok := s.Processes[flow.PID]; ok {
		candidates = append(candidates, info.Name, info.Source)
	}
	for _, candidate := range candidates {
		lower := strings.ToLower(candidate)
		if strings.Contains(lower, "modelcontextprotocol") || strings.Contains(lower, "@modelcontextprotocol") {
			return true
		}
		if strings.Contains(lower, "mcp-server") || strings.Contains(lower, "mcp_server") || strings.Contains(lower, "/mcp-") {
			return true
		}
		if strings.Contains(lower, " mcp ") || strings.Contains(lower, "/mcp/") || strings.HasSuffix(lower, "/mcp") {
			return true
		}
	}
	return false
}

func isActiveFlow(flow event.NetworkFlowEvent) bool {
	switch strings.ToLower(strings.TrimSpace(flow.State)) {
	case "established", "data":
		return true
	default:
		return false
	}
}

func (s *SessionState) knownAgentBinaryMatchLocked(e event.SemanticEvent, flow event.NetworkFlowEvent) bool {
	info, ok := s.Processes[flow.PID]
	if !ok {
		if flow.ProcessPath == "" {
			return false
		}
		info = ProcessInfo{PID: flow.PID, Name: flow.ProcessPath}
		annotateAgentProcess(&info)
	}
	if !info.IsAgentBinary || info.AgentID == "" {
		return false
	}
	if !strings.HasSuffix(info.AgentKind, "_cli") {
		return false
	}
	if e.Agent.ID == "" && e.Agent.Name == "" {
		return false
	}
	if strings.EqualFold(e.Agent.ID, info.AgentID) || strings.EqualFold(e.Agent.Name, info.AgentID) {
		return true
	}
	return false
}

func (s *SessionState) pidInSet(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, ok := s.KnownPIDs[pid]
	return ok
}

func annotateAgentProcess(info *ProcessInfo) {
	if info == nil || info.Name == "" {
		return
	}
	id, kind, ok := IdentifyAgentProcess(info.Name)
	if !ok {
		return
	}
	info.AgentID = id
	info.AgentKind = kind
	info.IsAgentBinary = true
}

// IdentifyAgentProcess classifies known AI agent process names. Claude Code CLI
// is intentionally distinct from desktop Claude helper processes because they
// should not be treated as equivalent roots.
func IdentifyAgentProcess(name string) (agentID, kind string, ok bool) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", "", false
	}
	first := strings.Fields(trimmed)[0]
	rawBase := filepath.Base(first)
	base := strings.ToLower(rawBase)
	lower := strings.ToLower(trimmed)
	switch {
	case rawBase == "Claude" || strings.Contains(lower, ".app/") && strings.Contains(lower, "claude"):
		return "claude", "claude_desktop", true
	case base == "claude":
		if strings.Contains(lower, ".app/") || strings.Contains(lower, "claude helper") {
			return "claude", "claude_desktop", true
		}
		return "claude", "claude_cli", true
	case base == "claude helper" || strings.Contains(lower, "claude helper"):
		return "claude", "claude_desktop", true
	case rawBase == "Cursor" || strings.Contains(lower, ".app/") && strings.Contains(lower, "cursor"):
		return "cursor", "cursor_desktop", true
	case base == "cursor":
		if strings.Contains(lower, ".app/") || strings.Contains(lower, "cursor helper") {
			return "cursor", "cursor_desktop", true
		}
		return "cursor", "cursor_cli", true
	case base == "cursor helper" || strings.Contains(lower, "cursor helper"):
		return "cursor", "cursor_desktop", true
	case rawBase == "Codex" || strings.Contains(lower, "codex (service)") || strings.Contains(lower, ".app/") && strings.Contains(lower, "codex"):
		return "codex", "codex_desktop", true
	case base == "codex":
		return "codex", "codex_cli", true
	case base == "openai":
		return "openai", "openai_cli", true
	case base == "gemini":
		return "gemini", "gemini_cli", true
	default:
		return "", "", false
	}
}

func withSource(info ProcessInfo, source string) ProcessInfo {
	info.Source = joinSource(info.Source, source)
	return info
}

func withAgentTracking(info ProcessInfo, source string) ProcessInfo {
	info.Source = joinSource(info.Source, source)
	info.TrackAsAgent = true
	return info
}

func joinSource(existing, next string) string {
	if existing == "" {
		return next
	}
	if next == "" || strings.Contains(existing, next) {
		return existing
	}
	return existing + "," + next
}

func shouldTrackAsAgentPID(info ProcessInfo) bool {
	if info.TrackAsAgent {
		return true
	}
	return info.IsAgentBinary && strings.HasSuffix(info.AgentKind, "_cli")
}

// SnapshotAgentProcesses runs a simple pgrep fallback (as specified for MVP
// process tracking) to discover "claude|cursor" etc. processes and seed the
// KnownPIDs set. Returns the discovered PIDs (may be empty).
//
// This is deliberately crude: real code would walk the process tree using
// sysctl(3) + libproc or kqueue on macOS, cross-referencing with PIDs from
// hook events. See sir/pkg/runtime for related darwin process ideas (sandbox,
// proxy) but we keep this local and simple.
func (s *SessionState) SnapshotAgentProcesses() ([]int, error) {
	// pgrep -af matches against full command line and prints "pid command".
	cmd := exec.Command("pgrep", "-af", "claude|cursor|gemini|codex|openai")
	out, err := cmd.Output()
	if err != nil {
		// pgrep exits 1 when no processes match; treat as "none found".
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var pids []int
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(fields[0], "%d", &pid); err == nil && pid > 0 {
			name := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
			_, kind, ok := IdentifyAgentProcess(name)
			if !ok || !strings.HasSuffix(kind, "_cli") {
				continue
			}
			pids = append(pids, pid)
			s.addProcessLockedFromSnapshot(ProcessInfo{PID: pid, Name: name, Source: "pgrep", TrackAsAgent: true})
		}
	}
	return pids, nil
}

func (s *SessionState) addProcessLockedFromSnapshot(info ProcessInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addProcessLocked(info)
}

// Summary returns a tiny human-readable snapshot for logging / dev UI.
func (s *SessionState) Summary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("session: pids=%d processes=%d events=%d has_sensitive=%v age=%s",
		len(s.KnownPIDs), len(s.Processes), len(s.Events), s.HasSensitive, time.Since(s.StartTime).Round(time.Second))
}
