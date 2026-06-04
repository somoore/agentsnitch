package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/somoore/agentsnitch/internal/correlator"
	"github.com/somoore/agentsnitch/internal/event"
	asruntime "github.com/somoore/agentsnitch/internal/runtime"
)

const NetworkRefreshTranscriptInterval = 30 * time.Second
const LsofDefaultPollInterval = 2 * time.Second
const LsofHookBurstPolls = 5
const LsofHookBurstInterval = 250 * time.Millisecond
const MaxDaemonSocketConnections = 64
const DaemonSocketReadIdleTimeout = 30 * time.Second
const SubagentDelegationWindow = 30 * time.Second
const SubagentSessionWindow = 2 * time.Minute
const SubagentBurstWindow = 15 * time.Second
const SubagentBurstThreshold = 3
const SidechainDiscoveryInterval = 10 * time.Second
const SidechainDiscoveryWindow = 6 * time.Hour
const ReverseDNSLookupTimeout = 150 * time.Millisecond
const ReverseDNSCacheTTL = 6 * time.Hour
const ReverseDNSNegativeCacheTTL = 30 * time.Minute

var reverseDNSLookup = net.DefaultResolver.LookupAddr

type reverseDNSCacheEntry struct {
	name      string
	expiresAt time.Time
}

var reverseDNSCache = struct {
	sync.Mutex
	entries map[string]reverseDNSCacheEntry
}{
	entries: make(map[string]reverseDNSCacheEntry),
}

func resolveSocketPath() string {
	return asruntime.SocketPath()
}

func verboseNetworkLogging() bool {
	return os.Getenv("AGENTSNITCH_VERBOSE_NETWORK_LOG") == "1"
}

func lsofNetworkObserverEnabled() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("AGENTSNITCH_DISABLE_LSOF")))
	return value != "1" && value != "true" && value != "yes"
}

func networkStatisticsObserverEnabled() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("AGENTSNITCH_DISABLE_NETWORK_STATISTICS")))
	return value != "1" && value != "true" && value != "yes"
}

func main() {
	sock := resolveSocketPath()
	_ = os.Remove(sock)

	l, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatalf("listen %s: %v", sock, err)
	}
	defer l.Close()
	_ = os.Chmod(sock, 0o600)

	log.Printf("AgentSnitch daemon listening on %s", sock)

	sessions := newDaemonSessions()
	status := newStatusReporter()
	status.write()
	transcripts := asruntime.NewTranscriptWriter()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	go defaultUIForwarder.run(ctx)
	var lsofBurstRequests chan struct{}
	if lsofNetworkObserverEnabled() {
		lsofBurstRequests = make(chan struct{}, 1)
	}
	var startLsofFallbackOnce sync.Once
	startLsofFallback := func(reason string) {
		if !lsofNetworkObserverEnabled() {
			log.Printf("network observer: lsof fallback disabled; %s", reason)
			return
		}
		startLsofFallbackOnce.Do(func() {
			log.Printf("network observer: starting lsof fallback: %s", reason)
			go startLsofNetworkObserver(ctx, sessions, status, transcripts, lsofBurstRequests)
		})
	}
	if networkStatisticsObserverEnabled() {
		go startNetworkStatisticsObserver(ctx, sessions, status, transcripts, startLsofFallback)
	} else {
		startLsofFallback("NetworkStatistics observer disabled")
	}
	go startProcessGraphObserver(ctx, sessions)

	var wg sync.WaitGroup
	connSlots := make(chan struct{}, MaxDaemonSocketConnections)
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		select {
		case connSlots <- struct{}{}:
		default:
			log.Printf("daemon socket: connection limit reached; dropping client")
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func(cc net.Conn) {
			defer wg.Done()
			defer func() { <-connSlots }()
			defer cc.Close()
			done := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					_ = cc.Close()
				case <-done:
				}
			}()
			handleConn(ctx, cc, sessions, status, transcripts, lsofBurstRequests)
			close(done)
		}(c)
	}
	wg.Wait()
	log.Print("daemon done")
}

func startProcessGraphObserver(ctx context.Context, sessions *daemonSessions) {
	log.Print("process tracking: process snapshot observer enabled")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			processes := snapshotProcessTable()
			if len(processes) == 0 {
				continue
			}
			forwardSubagentEventsToUI(sessions.applyProcessSnapshot(processes))
		}
	}
}

func handleConn(ctx context.Context, c net.Conn, sessions *daemonSessions, status *statusReporter, transcripts *asruntime.TranscriptWriter, lsofBurstRequests chan<- struct{}) {
	peerPID, hasPeerPID := peerPIDForConn(c)
	refreshReadDeadline := func() {
		_ = c.SetReadDeadline(time.Now().Add(DaemonSocketReadIdleTimeout))
	}
	refreshReadDeadline()
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		refreshReadDeadline()
		if ctx.Err() != nil {
			return
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		dispatch(line, peerPID, hasPeerPID, sessions, status, transcripts, lsofBurstRequests)
	}
	_ = sc.Err()
}

func dispatch(line string, peerPID int, hasPeerPID bool, sessions *daemonSessions, status *statusReporter, transcripts *asruntime.TranscriptWriter, lsofBurstRequests chan<- struct{}) {
	// Smarter dispatch for dev: network events have "remote" (or network schema); semantics have tool or semantic schema.
	raw := []byte(line)
	if strings.Contains(line, `"remote"`) || strings.Contains(line, "agentsnitch.network") {
		var nf event.NetworkFlowEvent
		if json.Unmarshal(raw, &nf) == nil {
			handleSocketNetwork(nf, peerPID, hasPeerPID, sessions, status, transcripts)
			return
		}
	}
	var se event.SemanticEvent
	if json.Unmarshal(raw, &se) == nil && (se.PID != 0 || se.Tool != "" || strings.Contains(line, "agentsnitch.semantic")) {
		handleSemantic(se, peerPID, hasPeerPID, sessions, status, transcripts, lsofBurstRequests)
		return
	}
	// fallback try network anyway
	var nf event.NetworkFlowEvent
	if json.Unmarshal(raw, &nf) == nil && nf.Remote != "" {
		handleSocketNetwork(nf, peerPID, hasPeerPID, sessions, status, transcripts)
		return
	}
	log.Printf("UNRECOGNIZED LINE: %s", line)
}

func handleSemantic(se event.SemanticEvent, peerPID int, hasPeerPID bool, sessions *daemonSessions, status *statusReporter, transcripts *asruntime.TranscriptWriter, lsofBurstRequests chan<- struct{}) {
	event.NormalizeSemanticEvent(&se)
	processes := snapshotProcessTable()
	// peerPID is the kernel-attested PID of the socket peer (LOCAL_PEERPID /
	// SO_PEERCRED). There is an inherent TOCTOU race: the peer can exit between
	// the connection's accept and the trust check, and the kernel can reuse its
	// PID for an unrelated process. We accept that race here because the threat
	// model is local-only and the trust check below resolves the peer's actual
	// executable path (kernel-reported, not argv) and requires it to be the
	// installed AgentSnitch emitter, which makes practical spoofing hard.
	if hasPeerPID && peerPID > 0 && se.PID != peerPID {
		log.Printf("SEMANTIC_INVALID: claimed pid %d does not match socket peer pid %d", se.PID, peerPID)
		return
	}
	if hasPeerPID && peerPID > 0 && !trustedSemanticSocketPeer(peerPID, processes) {
		log.Printf("SEMANTIC_INVALID: socket peer pid %d is not an AgentSnitch emitter", peerPID)
		return
	}
	if err := event.ValidateSemanticEvent(se); err != nil {
		log.Printf("SEMANTIC_INVALID: %v", err)
		return
	}
	session := sessions.forSemantic(se)
	session.state.ApplyProcessSnapshot(processes)
	forwardSubagentEventsToUI(session.subagents.observe(processes, cwdForPID))
	forwardSubagentEventsToUI(session.subagents.annotateSemantic(&se, processes))
	log.Printf("SEMANTIC: %s", se.String())
	if b, err := json.Marshal(se); err == nil {
		log.Printf("SEMANTIC_JSON: %s", string(b))
	}
	status.recordSemantic(se)
	appendTranscript(transcripts, status, se.Session.ID, "semantic", se)
	session.state.AddSemanticEvent(se)
	sessions.recordActivity(session, se.TS)
	// A held flow arrived before any session claimed its PID. Now that this
	// session exists, replay each drained flow through full correlation rather
	// than only AddNetworkFlow: TryCorrelateSemantic below only looks backward
	// over ExistingConnectionWindow, so without this a drained flow would never
	// get its own forward within_10s/pid_match (high-confidence) evaluation.
	for _, flow := range sessions.drainPendingForSession(session, se.TS) {
		correlateSessionFlow(sessions, session, flow, status, transcripts)
	}
	session.subagents.recordSemantic(se)
	if se.PID != 0 {
		log.Printf("  (process tracking: PID %d learned from event)", se.PID)
	}
	requestLsofBurstPoll(lsofBurstRequests)
	if se.IsEgressLike() && session.state.HasSensitive {
		log.Printf("NOTE: egress-like after sensitive in session %s", session.id)
	}
	if len(session.state.GetRecent())%5 == 0 {
		log.Printf("SESSION %s: %s", session.id, session.state.Summary())
	}
	for _, c := range session.state.TryCorrelateSemantic(se) {
		logCorrelation(c, status, transcripts)
		forwardToUI(c)
	}
	forwardToUI(se)
}

func handleSocketNetwork(nf event.NetworkFlowEvent, peerPID int, hasPeerPID bool, sessions *daemonSessions, status *statusReporter, transcripts *asruntime.TranscriptWriter) {
	var processes map[int]correlator.ProcessInfo
	if hasPeerPID && peerPID > 0 {
		processes = snapshotProcessTable()
		if !trustedNetworkSocketPeer(peerPID, processes) {
			log.Printf("NETFLOW_INVALID: socket peer pid %d is not an AgentSnitch network sender", peerPID)
			return
		}
	}
	// Reuse the snapshot taken for the trust check above so handleNetwork does
	// not take a second one. When there was no peer PID to verify, processes is
	// nil and handleNetwork falls back to snapshotting itself.
	handleNetworkWithProcesses(nf, processes, sessions, status, transcripts)
}

// peerExePath resolves a PID's actual executable path (kernel-reported, NOT the
// argv/command line). It is a package var so tests can inject a fake resolver;
// the default delegates to a per-platform resolver (peercred_{darwin,linux}.go).
//
// SECURITY: trust must be based on the executable image, not the command string.
// The old check matched substrings of `ps -o command=` (argv included), so a
// same-user process could put an AgentSnitch-looking path in its arguments and
// pass trust. The per-platform resolvers report the kernel's executable path,
// which argv cannot forge.
var peerExePath = func(pid int) (string, bool) {
	return resolvePeerExePath(pid)
}

// trustedSemanticSocketPeer reports whether the socket peer is the installed
// AgentSnitch emitter, validated by its actual executable path.
func trustedSemanticSocketPeer(pid int, _ map[int]correlator.ProcessInfo) bool {
	exe, ok := peerExePath(pid)
	if !ok {
		return false
	}
	return isTrustedEmitterExe(exe)
}

// trustedNetworkSocketPeer reports whether the socket peer is the installed
// AgentSnitch UI / Network Extension, validated by its actual executable path.
func trustedNetworkSocketPeer(pid int, _ map[int]correlator.ProcessInfo) bool {
	exe, ok := peerExePath(pid)
	if !ok {
		return false
	}
	return isTrustedNetworkSenderExe(exe)
}

// agentSnitchSupportBins returns the canonical installed support-binary
// directories. AgentSnitch installs two ways: scripts/create.sh and the .pkg
// install both stage the emitter under an "Application Support/AgentSnitch/bin"
// dir — per-user ($HOME/Library/...) for create.sh and system-wide
// (/Library/...) for the signed pkg. AGENTSNITCH_SUPPORT_DIR overrides both.
func agentSnitchSupportBins() []string {
	if dir := strings.TrimSpace(os.Getenv("AGENTSNITCH_SUPPORT_DIR")); dir != "" {
		return []string{filepath.Join(dir, "bin")}
	}
	var bins []string
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		bins = append(bins, filepath.Join(home, "Library", "Application Support", "AgentSnitch", "bin"))
	}
	bins = append(bins, "/Library/Application Support/AgentSnitch/bin")
	return bins
}

// agentSnitchAppPath returns the canonical installed app bundle path, honoring the
// same env override as scripts/create.sh.
func agentSnitchAppPath() string {
	if p := strings.TrimSpace(os.Getenv("AGENTSNITCH_APP_PATH")); p != "" {
		return p
	}
	return "/Applications/AgentSnitch.app"
}

// networkExtensionBundleID is the AgentSnitch Network Extension bundle identifier.
// Activated macOS system extensions run from the system extension store
// (/Library/SystemExtensions/<uuid>/<bundle-id>/...), NOT from the .app bundle,
// so the trust check must also accept that path shape.
const networkExtensionBundleID = "com.somoore.agentsnitch.network-extension.systemextension"

// isTrustedEmitterExe is a pure validator: the resolved executable path must be
// exactly the installed emitter binary in one of the canonical support dirs.
func isTrustedEmitterExe(exe string) bool {
	exe = filepath.Clean(strings.TrimSpace(exe))
	if exe == "" {
		return false
	}
	for _, bin := range agentSnitchSupportBins() {
		if exe == filepath.Join(bin, "emitter") {
			return true
		}
	}
	return false
}

// isTrustedNetworkSenderExe is a pure validator: the resolved executable path must
// be the installed AgentSnitch UI / Network Extension. Trusted shapes:
//   - inside the installed .app bundle (UI, or NE embedded in the bundle), and
//   - inside the macOS system extension store path for the AgentSnitch NE
//     (/Library/SystemExtensions/.../<bundle-id>/...), where activated system
//     extensions actually execute.
func isTrustedNetworkSenderExe(exe string) bool {
	exe = filepath.Clean(strings.TrimSpace(exe))
	if exe == "" {
		return false
	}
	app := filepath.Clean(agentSnitchAppPath())
	if app != "" && (exe == app || strings.HasPrefix(exe, app+string(filepath.Separator))) {
		return true
	}
	// Activated Network Extension in the system extension store. The store path
	// is /Library/SystemExtensions/<uuid>/<bundle-id>/...; require BOTH the store
	// root prefix and the AgentSnitch NE bundle id to appear as a path segment.
	const storeRoot = "/Library/SystemExtensions/"
	if strings.HasPrefix(exe, storeRoot) &&
		strings.Contains(exe, string(filepath.Separator)+networkExtensionBundleID+string(filepath.Separator)) {
		return true
	}
	return false
}

func handleNetwork(nf event.NetworkFlowEvent, sessions *daemonSessions, status *statusReporter, transcripts *asruntime.TranscriptWriter) {
	handleNetworkWithProcesses(nf, nil, sessions, status, transcripts)
}

// handleNetworkWithProcesses processes a network flow against an optional
// pre-fetched process snapshot. Callers that have already snapshotted the
// process table (e.g. socket peer verification) pass it in to avoid a redundant
// snapshot; passing nil makes this function take its own.
func handleNetworkWithProcesses(nf event.NetworkFlowEvent, processes map[int]correlator.ProcessInfo, sessions *daemonSessions, status *statusReporter, transcripts *asruntime.TranscriptWriter) {
	event.NormalizeNetworkFlow(&nf)
	enrichNetworkHostname(&nf)
	if processes == nil {
		processes = snapshotProcessTable()
	}
	enrichNetworkFlowFromProcesses(&nf, processes)
	candidates := sessions.applyProcessSnapshotAndMatch(processes, nf)
	candidateFlows := make(map[*daemonSession]event.NetworkFlowEvent, len(candidates))
	for _, session := range candidates {
		forwardSubagentEventsToUI(session.subagents.observe(processes, cwdForPID))
		candidateFlows[session] = annotatedNetworkFlowForSession(nf, session, processes)
	}
	event.NormalizeNetworkFlow(&nf)
	if err := event.ValidateNetworkFlow(nf); err != nil {
		log.Printf("NETFLOW_INVALID: %v", err)
		return
	}
	statusFlow := nf
	if len(candidates) == 1 {
		statusFlow = candidateFlows[candidates[0]]
	}
	if verboseNetworkLogging() {
		log.Printf("NETFLOW: pid=%d remote=%s sni=%s out=%d", statusFlow.PID, statusFlow.Remote, statusFlow.SNI, statusFlow.BytesOut)
		if b, err := json.Marshal(statusFlow); err == nil {
			log.Printf("NETFLOW_JSON: %s", string(b))
		}
	}
	status.recordNetwork(statusFlow)
	appendTranscript(transcripts, status, "network-observer", "network", statusFlow)
	correlated := false
	for _, session := range candidates {
		if correlateSessionFlow(sessions, session, candidateFlows[session], status, transcripts) {
			correlated = true
		}
	}
	if len(candidates) == 0 && shouldHoldUnattributedNetworkFlow(nf) {
		sessions.holdPendingNetworkFlow(nf, time.Now())
	}
	if shouldForwardRawNetworkToUIForSessions(statusFlow, sessions, candidates, correlated) {
		forwardToUI(statusFlow)
	}
}

func annotatedNetworkFlowForSession(nf event.NetworkFlowEvent, session *daemonSession, processes map[int]correlator.ProcessInfo) event.NetworkFlowEvent {
	flow := nf
	if flow.Agent == nil && session != nil && session.subagents != nil {
		session.subagents.annotateNetwork(&flow, processes)
	}
	event.NormalizeNetworkFlow(&flow)
	return flow
}

func enrichNetworkHostname(nf *event.NetworkFlowEvent) {
	if nf == nil || nf.SNI != "" {
		return
	}
	host := remoteHost(nf.Remote)
	if host == "" {
		return
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !publicAddrForDNS(addr) {
		return
	}
	if name := cachedReverseDNS(addr.String(), time.Now()); name != "" {
		nf.SNI = name
	}
}

func remoteHost(endpoint string) string {
	host := strings.TrimSpace(endpoint)
	if host == "" {
		return ""
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	return strings.Trim(host, "[]")
}

func publicAddrForDNS(addr netip.Addr) bool {
	return addr.IsGlobalUnicast() &&
		!addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast()
}

func cachedReverseDNS(ip string, now time.Time) string {
	reverseDNSCache.Lock()
	if entry, ok := reverseDNSCache.entries[ip]; ok && now.Before(entry.expiresAt) {
		reverseDNSCache.Unlock()
		return entry.name
	}
	reverseDNSCache.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), ReverseDNSLookupTimeout)
	defer cancel()
	names, err := reverseDNSLookup(ctx, ip)
	name := ""
	ttl := ReverseDNSNegativeCacheTTL
	if err == nil && len(names) > 0 {
		name = strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
		if name != "" {
			ttl = ReverseDNSCacheTTL
		}
	}

	reverseDNSCache.Lock()
	reverseDNSCache.entries[ip] = reverseDNSCacheEntry{name: name, expiresAt: now.Add(ttl)}
	reverseDNSCache.Unlock()
	return name
}

// correlateSessionFlow adds a flow to one session and runs full correlation,
// logging and forwarding any linked evidence. It is the single path used by
// live network handling, the lsof refresh, and pending-flow drains so a drained
// flow gets the same correlation treatment it would have received had the
// session existed when the flow first arrived. Returns whether anything linked.
func correlateSessionFlow(sessions *daemonSessions, session *daemonSession, flow event.NetworkFlowEvent, status *statusReporter, transcripts *asruntime.TranscriptWriter) bool {
	session.state.AddNetworkFlow(flow)
	sessions.recordActivity(session, flow.TS)
	correlated := false
	for _, c := range session.state.TryCorrelate(flow) {
		correlated = true
		logCorrelation(c, status, transcripts)
		forwardToUI(c)
	}
	return correlated
}

func shouldForwardRawNetworkToUIForSessions(nf event.NetworkFlowEvent, sessionStore *daemonSessions, candidates []*daemonSession, correlated bool) bool {
	if correlated {
		return true
	}
	now := time.Now()
	for _, session := range candidates {
		if session.shouldForwardRawNetworkToUI(nf, now) {
			return true
		}
	}
	return len(candidates) == 0 && sessionStore != nil && sessionStore.shouldForwardUnattributedRawNetworkToUI(nf, now)
}

func shouldForwardRawNetworkToUI(nf event.NetworkFlowEvent, state *correlator.SessionState, correlated bool) bool {
	if correlated {
		return true
	}
	if !nf.IsExternal() || nf.Direction == "in" || !isPublicRemoteForUI(nf.Remote) {
		return false
	}
	if !isAgentRelevantNetworkFlow(nf, state) {
		return false
	}
	switch nf.State {
	case "new", "established", "data":
		return true
	default:
		return nf.State == ""
	}
}

func (session *daemonSession) shouldForwardRawNetworkToUI(nf event.NetworkFlowEvent, now time.Time) bool {
	if session == nil || !shouldForwardRawNetworkToUI(nf, session.state, false) {
		return false
	}
	key := rawNetworkVisibilityKey(nf)
	if key == "" {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	session.rawNetworkMu.Lock()
	defer session.rawNetworkMu.Unlock()
	if session.rawNetworkSeen == nil {
		session.rawNetworkSeen = make(map[string]time.Time)
	}
	if _, ok := session.rawNetworkSeen[key]; ok {
		return false
	}
	session.rawNetworkSeen[key] = now
	return true
}

func (sessions *daemonSessions) shouldForwardUnattributedRawNetworkToUI(nf event.NetworkFlowEvent, now time.Time) bool {
	if sessions == nil || !shouldForwardRawNetworkToUI(nf, nil, false) {
		return false
	}
	key := rawNetworkVisibilityKey(nf)
	if key == "" {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	sessions.rawNetworkMu.Lock()
	defer sessions.rawNetworkMu.Unlock()
	if sessions.unattributedRawSeen == nil {
		sessions.unattributedRawSeen = make(map[string]time.Time)
	}
	if _, ok := sessions.unattributedRawSeen[key]; ok {
		return false
	}
	sessions.unattributedRawSeen[key] = now
	return true
}

func rawNetworkVisibilityKey(nf event.NetworkFlowEvent) string {
	host := strings.TrimSpace(nf.SNI)
	if host == "" {
		host = remoteHost(nf.Remote)
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func shouldHoldUnattributedNetworkFlow(nf event.NetworkFlowEvent) bool {
	if !nf.IsExternal() || nf.Direction == "in" || !isPublicRemoteForUI(nf.Remote) {
		return false
	}
	switch nf.State {
	case "new", "established", "data":
		return true
	default:
		return false
	}
}

func isAgentRelevantNetworkFlow(nf event.NetworkFlowEvent, state *correlator.SessionState) bool {
	if state != nil {
		if state.IsAgentPID(nf.PID) || state.IsAgentPID(nf.PPID) {
			return true
		}
	}
	if looksLikeAgentProcess(nf.ProcessPath) {
		return true
	}
	bundleID := strings.ToLower(nf.ProcessBundleID)
	return strings.Contains(bundleID, "claude-code")
}

func isPublicRemoteForUI(remote string) bool {
	host := strings.TrimSpace(remote)
	if host == "" {
		return false
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return true
	}
	return addr.IsGlobalUnicast() &&
		!addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast()
}

func logCorrelation(c event.Correlation, status *statusReporter, transcripts *asruntime.TranscriptWriter) {
	if err := event.ValidateCorrelatedEvent(c); err != nil {
		log.Printf("CORRELATED_INVALID: %v", err)
		return
	}
	log.Printf("CORRELATED: %s (score %.1f reasons %v)", c.Summary, c.Score, c.Reasons)
	for _, se := range c.Semantics {
		if se.HasTag("sensitive_read") && len(c.Flows) > 0 {
			log.Printf("CORRELATED: sensitive read -> flow to %s", c.Flows[0].Remote)
		}
	}
	status.recordCorrelated(c)
	appendTranscript(transcripts, status, correlationSessionID(c), "correlated", c)
}

func appendTranscript(transcripts *asruntime.TranscriptWriter, status *statusReporter, sessionID, kind string, ev interface{}) {
	if transcripts == nil {
		return
	}
	if err := transcripts.Append(sessionID, kind, ev); err != nil {
		log.Printf("transcript append failed: %v", err)
		return
	}
	status.recordTranscript(kind, asruntime.TranscriptPath(sessionID))
}

func correlationSessionID(c event.Correlation) string {
	for _, sem := range c.Semantics {
		if sem.Session.ID != "" {
			return sem.Session.ID
		}
	}
	return "correlated"
}

func startLsofNetworkObserver(ctx context.Context, sessions *daemonSessions, status *statusReporter, transcripts *asruntime.TranscriptWriter, burstRequests <-chan struct{}) {
	log.Print("network observer: lsof fallback enabled (set AGENTSNITCH_DISABLE_LSOF=1 to disable)")
	ticker := time.NewTicker(LsofDefaultPollInterval)
	defer ticker.Stop()

	seen := make(map[string]time.Time)
	transcriptSeen := make(map[string]time.Time)
	poll := func() {
		flows, err := snapshotEstablishedTCP()
		if err != nil {
			log.Printf("network observer: lsof snapshot failed: %v", err)
			return
		}
		cutoff := time.Now().Add(-10 * time.Minute)
		for k, ts := range seen {
			if ts.Before(cutoff) {
				delete(seen, k)
				delete(transcriptSeen, k)
			}
		}
		for _, flow := range flows {
			if !flow.IsExternal() {
				continue
			}
			if !sessions.anySessionMatchesNetworkFlow(flow) && !sessions.anyAgentPID(flow.PID) && !looksLikeAgentProcess(flow.ProcessPath) {
				continue
			}
			if flow.ProcessPath == "" && flow.ProcessBundleID == "" {
				continue
			}
			key := fmt.Sprintf("%d|%s|%s", flow.PID, flow.Local, flow.Remote)
			if _, ok := seen[key]; ok {
				now := time.Now()
				seen[key] = now
				refreshNetworkObservationForSessions(flow, sessions, status, transcripts, shouldAppendNetworkRefreshTranscript(transcriptSeen, key, now))
				continue
			}
			now := time.Now()
			seen[key] = now
			transcriptSeen[key] = now
			log.Printf("network observer: observed pid=%d proc=%s remote=%s", flow.PID, flow.ProcessPath, flow.Remote)
			handleNetwork(flow, sessions, status, transcripts)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		case <-burstRequests:
			log.Print("network observer: hook-triggered lsof burst poll")
			for i := 0; i < LsofHookBurstPolls; i++ {
				poll()
				if i == LsofHookBurstPolls-1 {
					break
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(LsofHookBurstInterval):
				}
			}
		}
	}
}

func requestLsofBurstPoll(ch chan<- struct{}) {
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

type nettopProcessContext struct {
	PID  int
	Name string
}

func startNetworkStatisticsObserver(ctx context.Context, sessions *daemonSessions, status *statusReporter, transcripts *asruntime.TranscriptWriter, fallback func(string)) {
	log.Print("network observer: NetworkStatistics/nettop enabled (set AGENTSNITCH_DISABLE_NETWORK_STATISTICS=1 to disable)")
	err := runNetworkStatisticsObserver(ctx, sessions, status, transcripts)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		log.Printf("network observer: NetworkStatistics failed: %v", err)
	}
	if fallback != nil {
		fallback("NetworkStatistics observer unavailable")
	}
}

func runNetworkStatisticsObserver(ctx context.Context, sessions *daemonSessions, status *statusReporter, transcripts *asruntime.TranscriptWriter) error {
	cmd := exec.CommandContext(ctx, "nettop", "-L", "0", "-x", "-t", "external", "-s", "1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go logCommandStderr(ctx, "network observer: nettop", stderr)

	processes := snapshotProcessTable()
	lastProcessSnapshot := time.Now()
	current := nettopProcessContext{}
	seen := make(map[string]time.Time)
	transcriptSeen := make(map[string]time.Time)
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			break
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "time,") {
			continue
		}
		if time.Since(lastProcessSnapshot) > 2*time.Second {
			processes = snapshotProcessTable()
			lastProcessSnapshot = time.Now()
		}
		flow, ok, err := parseNettopCSVLine(line, &current, processes, time.Now().UTC())
		if err != nil {
			if verboseNetworkLogging() {
				log.Printf("network observer: nettop parse skipped: %v line=%q", err, line)
			}
			continue
		}
		if !ok || !flow.IsExternal() {
			continue
		}
		if !sessions.anySessionMatchesNetworkFlow(flow) && !sessions.anyAgentPID(flow.PID) && !looksLikeAgentProcess(flow.ProcessPath) {
			continue
		}
		key := fmt.Sprintf("%d|%s|%s|%s", flow.PID, flow.Protocol, flow.Local, flow.Remote)
		now := time.Now()
		cutoff := now.Add(-10 * time.Minute)
		for k, ts := range seen {
			if ts.Before(cutoff) {
				delete(seen, k)
				delete(transcriptSeen, k)
			}
		}
		if _, ok := seen[key]; ok {
			seen[key] = now
			refreshNetworkObservationForSessions(flow, sessions, status, transcripts, shouldAppendNetworkRefreshTranscript(transcriptSeen, key, now))
			continue
		}
		seen[key] = now
		transcriptSeen[key] = now
		log.Printf("network observer: observed pid=%d proc=%s remote=%s via network_statistics", flow.PID, flow.ProcessPath, flow.Remote)
		handleNetwork(flow, sessions, status, transcripts)
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("nettop exited")
}

func logCommandStderr(ctx context.Context, prefix string, r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			log.Printf("%s: %s", prefix, line)
		}
	}
}

func parseNettopCSVLine(line string, current *nettopProcessContext, processes map[int]correlator.ProcessInfo, now time.Time) (event.NetworkFlowEvent, bool, error) {
	reader := csv.NewReader(strings.NewReader(line))
	reader.FieldsPerRecord = -1
	record, err := reader.Read()
	if err != nil {
		return event.NetworkFlowEvent{}, false, err
	}
	return parseNettopCSVRecord(record, current, processes, now)
}

func parseNettopCSVRecord(record []string, current *nettopProcessContext, processes map[int]correlator.ProcessInfo, now time.Time) (event.NetworkFlowEvent, bool, error) {
	if len(record) < 6 {
		return event.NetworkFlowEvent{}, false, fmt.Errorf("short nettop record")
	}
	item := strings.TrimSpace(record[1])
	if item == "" {
		return event.NetworkFlowEvent{}, false, nil
	}
	if !strings.Contains(item, "<->") {
		pid, name, ok := parseNettopProcessLabel(item)
		if ok && current != nil {
			current.PID = pid
			current.Name = name
		}
		return event.NetworkFlowEvent{}, false, nil
	}
	if current == nil || current.PID <= 0 {
		return event.NetworkFlowEvent{}, false, fmt.Errorf("socket row before process row")
	}
	protocol, local, remote, ok := parseNettopSocketItem(item)
	if !ok || remote == "" {
		return event.NetworkFlowEvent{}, false, nil
	}
	state, ok := normalizeNettopState(protocol, record[3])
	if !ok {
		return event.NetworkFlowEvent{}, false, nil
	}
	bytesIn := parseNettopBytes(record[4])
	bytesOut := parseNettopBytes(record[5])
	ppid := 0
	processPath := current.Name
	if info, ok := processes[current.PID]; ok {
		ppid = info.PPID
		if resolved := resolveProcessPath(info.Name, current.Name); resolved != "" {
			processPath = resolved
		}
	}
	return event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          now,
		FlowID:      networkStatisticsFlowID(current.PID, protocol, local, remote),
		Observer:    "network_statistics",
		PID:         current.PID,
		PPID:        ppid,
		ProcessPath: processPath,
		Local:       local,
		Remote:      remote,
		Protocol:    protocol,
		Direction:   "out",
		BytesOut:    bytesOut,
		BytesIn:     bytesIn,
		State:       state,
	}, true, nil
}

func parseNettopProcessLabel(label string) (int, string, bool) {
	label = strings.TrimSpace(label)
	idx := strings.LastIndex(label, ".")
	if idx <= 0 || idx == len(label)-1 {
		return 0, "", false
	}
	pid := 0
	if _, err := fmt.Sscanf(label[idx+1:], "%d", &pid); err != nil || pid <= 0 {
		return 0, "", false
	}
	name := strings.TrimSpace(label[:idx])
	if name == "" {
		name = label
	}
	return pid, name, true
}

func parseNettopSocketItem(item string) (protocol, local, remote string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(item))
	if len(fields) != 2 {
		return "", "", "", false
	}
	token := strings.ToLower(fields[0])
	switch {
	case strings.HasPrefix(token, "tcp"):
		protocol = "tcp"
	case strings.HasPrefix(token, "udp"):
		protocol = "udp"
	case strings.HasPrefix(token, "quic"):
		protocol = "quic"
	default:
		return "", "", "", false
	}
	parts := strings.Split(fields[1], "<->")
	if len(parts) != 2 {
		return "", "", "", false
	}
	local = normalizeNettopEndpoint(parts[0])
	remote = normalizeNettopEndpoint(parts[1])
	if remote == "" {
		return "", "", "", false
	}
	return protocol, local, remote, true
}

func normalizeNettopEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || endpoint == "*:*" || endpoint == "*.*" || strings.HasPrefix(endpoint, "*.") || strings.HasPrefix(endpoint, "*:") {
		return ""
	}
	if host, port, err := net.SplitHostPort(endpoint); err == nil {
		return net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	idx := strings.LastIndex(endpoint, ".")
	if idx <= 0 || idx == len(endpoint)-1 {
		return endpoint
	}
	port := endpoint[idx+1:]
	if !allDigits(port) {
		return endpoint
	}
	host := endpoint[:idx]
	return net.JoinHostPort(strings.Trim(host, "[]"), port)
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func normalizeNettopState(protocol, state string) (string, bool) {
	state = strings.ToLower(strings.TrimSpace(state))
	if protocol == "udp" || protocol == "quic" {
		return "data", true
	}
	switch state {
	case "established", "closewait", "timewait":
		return "established", true
	case "synsent", "synreceived":
		return "new", true
	case "closed":
		return "closed", true
	case "":
		return "", false
	default:
		return "", false
	}
}

func parseNettopBytes(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	var n int64
	if _, err := fmt.Sscanf(value, "%d", &n); err != nil || n < 0 {
		return 0
	}
	return n
}

func networkStatisticsFlowID(pid int, protocol, local, remote string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(fmt.Sprintf("%d|%s|%s|%s", pid, protocol, local, remote)))
	return fmt.Sprintf("network_statistics-%d-%x", pid, h.Sum64())
}

func refreshNetworkObservationForSessions(nf event.NetworkFlowEvent, sessions *daemonSessions, status *statusReporter, transcripts *asruntime.TranscriptWriter, writeTranscript bool) {
	event.NormalizeNetworkFlow(&nf)
	enrichNetworkHostname(&nf)
	processes := snapshotProcessTable()
	enrichNetworkFlowFromProcesses(&nf, processes)
	event.NormalizeNetworkFlow(&nf)
	if err := event.ValidateNetworkFlow(nf); err != nil {
		return
	}
	candidates := sessions.applyProcessSnapshotAndMatch(processes, nf)
	candidateFlows := make(map[*daemonSession]event.NetworkFlowEvent, len(candidates))
	for _, session := range candidates {
		candidateFlows[session] = annotatedNetworkFlowForSession(nf, session, processes)
	}
	statusFlow := nf
	if len(candidates) == 1 {
		statusFlow = candidateFlows[candidates[0]]
	}
	status.recordNetwork(statusFlow)
	if writeTranscript {
		appendTranscript(transcripts, status, "network-observer", "network_refresh", statusFlow)
	}
	correlated := false
	for _, session := range candidates {
		if correlateSessionFlow(sessions, session, candidateFlows[session], status, transcripts) {
			correlated = true
		}
	}
	if len(candidates) == 0 && shouldHoldUnattributedNetworkFlow(nf) {
		sessions.holdPendingNetworkFlow(nf, time.Now())
	}
	if shouldForwardRawNetworkToUIForSessions(statusFlow, sessions, candidates, correlated) {
		forwardToUI(statusFlow)
	}
}

func refreshNetworkObservation(nf event.NetworkFlowEvent, state *correlator.SessionState, status *statusReporter, transcripts *asruntime.TranscriptWriter, writeTranscript bool) {
	event.NormalizeNetworkFlow(&nf)
	enrichNetworkHostname(&nf)
	enrichNetworkFlowFromProcesses(&nf, snapshotProcessTable())
	event.NormalizeNetworkFlow(&nf)
	if err := event.ValidateNetworkFlow(nf); err != nil {
		return
	}
	status.recordNetwork(nf)
	if writeTranscript {
		appendTranscript(transcripts, status, "network-observer", "network_refresh", nf)
	}
	state.AddNetworkFlow(nf)
	for _, c := range state.TryCorrelate(nf) {
		logCorrelation(c, status, transcripts)
		forwardToUI(c)
	}
}

func enrichNetworkFlowFromProcesses(nf *event.NetworkFlowEvent, processes map[int]correlator.ProcessInfo) {
	if nf == nil || nf.PID <= 0 || len(processes) == 0 {
		return
	}
	info, ok := processes[nf.PID]
	if !ok {
		return
	}
	if nf.PPID == 0 && info.PPID > 0 {
		nf.PPID = info.PPID
	}
	if nf.ProcessPath == "" {
		nf.ProcessPath = resolveProcessPath(info.Name, "")
	}
}

func shouldAppendNetworkRefreshTranscript(last map[string]time.Time, key string, now time.Time) bool {
	if key == "" {
		return false
	}
	if prev, ok := last[key]; ok && now.Sub(prev) < NetworkRefreshTranscriptInterval {
		return false
	}
	last[key] = now
	return true
}

func snapshotEstablishedTCP() ([]event.NetworkFlowEvent, error) {
	processes := snapshotProcessTable()
	cmd := exec.Command("lsof", "-nP", "-F", "pcnT", "-iTCP", "-sTCP:ESTABLISHED")
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}

	var flows []event.NetworkFlowEvent
	var pid int
	var proc string
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid = 0
			_, _ = fmt.Sscanf(line[1:], "%d", &pid)
		case 'c':
			proc = line[1:]
		case 'n':
			if pid <= 0 {
				continue
			}
			local, remote := splitLsofEndpoint(line[1:])
			if remote == "" {
				continue
			}
			ppid := 0
			processPath := ""
			if info, ok := processes[pid]; ok {
				ppid = info.PPID
				processPath = resolveProcessPath(info.Name, proc)
			}
			if processPath == "" {
				processPath = resolveProcessPath(proc, "")
			}
			flows = append(flows, event.NetworkFlowEvent{
				Schema:      event.SchemaNetworkV0,
				TS:          time.Now().UTC(),
				FlowID:      fmt.Sprintf("lsof-%d-%x", pid, len(flows)+1),
				Observer:    "lsof",
				PID:         pid,
				PPID:        ppid,
				ProcessPath: processPath,
				Local:       local,
				Remote:      remote,
				Protocol:    "tcp",
				Direction:   "out",
				State:       "established",
			})
		}
	}
	return flows, nil
}

func snapshotProcessTable() map[int]correlator.ProcessInfo {
	out, err := exec.Command("ps", "-axo", "pid=,ppid=,lstart=,command=").Output()
	if err != nil {
		return nil
	}
	return parseProcessTableOutput(string(out))
}

func parseProcessTableOutput(out string) map[int]correlator.ProcessInfo {
	processes := make(map[int]correlator.ProcessInfo)
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		var pid, ppid int
		if _, err := fmt.Sscanf(fields[0], "%d", &pid); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(fields[1], "%d", &ppid); err != nil {
			continue
		}
		startedAt := parseProcessStartTime(fields[2:7])
		command := ""
		if len(fields) > 7 {
			command = strings.Join(fields[7:], " ")
		}
		processes[pid] = correlator.ProcessInfo{
			PID:       pid,
			PPID:      ppid,
			StartedAt: startedAt,
			Name:      command,
			Source:    "ps",
		}
	}
	return processes
}

func parseProcessStartTime(fields []string) time.Time {
	if len(fields) != 5 {
		return time.Time{}
	}
	startedAt, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(fields, " "), time.Local)
	if err != nil {
		return time.Time{}
	}
	return startedAt
}

func splitLsofEndpoint(name string) (local, remote string) {
	parts := strings.Split(name, "->")
	if len(parts) != 2 {
		return name, ""
	}
	return parts[0], parts[1]
}

type statusReporter struct {
	mu     sync.Mutex
	status asruntime.Status
}

func newStatusReporter() *statusReporter {
	now := time.Now().UTC()
	return &statusReporter{
		status: asruntime.Status{
			DaemonStartedAt: now,
			UpdatedAt:       now,
		},
	}
}

func (r *statusReporter) recordSemantic(ev event.SemanticEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.LastSemantic = &ev
	r.writeLocked()
}

func (r *statusReporter) recordNetwork(ev event.NetworkFlowEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.LastNetwork = &ev
	r.writeLocked()
}

func (r *statusReporter) recordCorrelated(ev event.CorrelatedEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.LastCorrelated = &ev
	r.writeLocked()
}

func (r *statusReporter) recordTranscript(kind, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.LastTranscriptKind = kind
	r.status.LastTranscriptPath = path
	r.status.LastTranscriptAt = time.Now().UTC()
	r.writeLocked()
}

func (r *statusReporter) write() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writeLocked()
}

func (r *statusReporter) writeLocked() {
	r.status.UpdatedAt = time.Now().UTC()
	if err := asruntime.WriteStatus(r.status); err != nil {
		log.Printf("status write failed: %v", err)
	}
}

func forwardSubagentEventsToUI(events subagentEvents) {
	for _, agentEvent := range events.lifecycle {
		forwardToUI(agentEvent)
	}
	for _, semantic := range events.semantics {
		forwardToUI(semantic)
	}
}

// uiForwarder owns the single connection to the Tauri UI socket and drains a
// bounded queue of newline-framed events. Centralizing forwarding here replaces
// the old per-event goroutine + per-event dial, which had no backpressure and no
// write deadline: a wedged UI consumer could otherwise leak unbounded goroutines
// each blocked on Write. On a full queue we drop the oldest event (visibility is
// best-effort and the UI keeps only a recent ring anyway).
type uiForwarder struct {
	queue chan []byte
}

const (
	uiForwardQueueSize  = 256
	uiForwardWriteLimit = 2 * time.Second
	uiForwardDialWindow = 15 * time.Second
)

var defaultUIForwarder = newUIForwarder()

func newUIForwarder() *uiForwarder {
	return &uiForwarder{queue: make(chan []byte, uiForwardQueueSize)}
}

// run drains the queue until ctx is cancelled, reusing one connection and
// reconnecting lazily on error. It coalesces multiple queued events onto the
// same connection; the UI processes every newline-framed line.
func (f *uiForwarder) run(ctx context.Context) {
	var conn net.Conn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-f.queue:
			if conn == nil {
				deadline := time.Now().Add(uiForwardDialWindow)
				for {
					c, err := asruntime.DialUI(300 * time.Millisecond)
					if err == nil {
						conn = c
						break
					}
					if time.Now().After(deadline) {
						// UI stayed down; drop this event and try again on the next.
						break
					}
					select {
					case <-ctx.Done():
						return
					case <-time.After(250 * time.Millisecond):
					}
				}
				if conn == nil {
					continue
				}
			}
			_ = conn.SetWriteDeadline(time.Now().Add(uiForwardWriteLimit))
			if _, err := conn.Write(msg); err != nil {
				_ = conn.Close()
				conn = nil
			}
		}
	}
}

// enqueue adds a marshaled event to the bounded queue, dropping the oldest event
// rather than blocking the caller (a hook/network handler) when the UI is slow.
func (f *uiForwarder) enqueue(b []byte) {
	for {
		select {
		case f.queue <- b:
			return
		default:
			select {
			case <-f.queue: // drop oldest, then retry
			default:
				return
			}
		}
	}
}

// forwardToUI sends validated daemon events to the Tauri UI over the local UI
// socket. The UI does not expose a raw HTTP ingestion endpoint; product events
// should flow through hooks/OS sensors into this daemon first. Non-blocking and
// best-effort: events are queued for the single forwarder goroutine.
func forwardToUI(v interface{}) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	defaultUIForwarder.enqueue(append(b, '\n'))
}
