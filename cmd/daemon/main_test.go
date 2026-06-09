package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/somoore/agentsnitch/internal/correlator"
	"github.com/somoore/agentsnitch/internal/event"
	"github.com/somoore/agentsnitch/internal/inspect"
	asruntime "github.com/somoore/agentsnitch/internal/runtime"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("AGENTSNITCH_DISABLE_SIDECHAIN_DISCOVERY", "1")
	tmp, err := os.MkdirTemp("", "agentsnitch-daemon-test-*")
	if err == nil {
		_ = os.Setenv("AGENTSNITCH_UI_SOCK", filepath.Join(tmp, "ui.sock"))
	}
	code := m.Run()
	if tmp != "" {
		_ = os.RemoveAll(tmp)
	}
	os.Exit(code)
}

func TestShouldAppendNetworkRefreshTranscriptThrottlesSameSocket(t *testing.T) {
	last := map[string]time.Time{}
	base := time.Now().UTC()
	key := "123|192.168.1.2:60000|93.184.216.34:443"

	if !shouldAppendNetworkRefreshTranscript(last, key, base) {
		t.Fatal("first refresh should append")
	}
	if shouldAppendNetworkRefreshTranscript(last, key, base.Add(2*time.Second)) {
		t.Fatal("nearby duplicate refresh should not append")
	}
	if !shouldAppendNetworkRefreshTranscript(last, key, base.Add(NetworkRefreshTranscriptInterval)) {
		t.Fatal("refresh at interval should append")
	}
}

func TestShouldAppendNetworkRefreshTranscriptRejectsEmptyKey(t *testing.T) {
	if shouldAppendNetworkRefreshTranscript(map[string]time.Time{}, "", time.Now()) {
		t.Fatal("empty key should not append")
	}
}

func TestLsofNetworkObserverEnabledTreatsOnlyExplicitTrueAsDisabled(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"", true},
		{"0", true},
		{"false", true},
		{"1", false},
		{"true", false},
		{"yes", false},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("AGENTSNITCH_DISABLE_LSOF", tc.value)
			if got := lsofNetworkObserverEnabled(); got != tc.want {
				t.Fatalf("lsofNetworkObserverEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNetworkStatisticsObserverEnabledTreatsOnlyExplicitTrueAsDisabled(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"", true},
		{"0", true},
		{"false", true},
		{"1", false},
		{"true", false},
		{"yes", false},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("AGENTSNITCH_DISABLE_NETWORK_STATISTICS", tc.value)
			if got := networkStatisticsObserverEnabled(); got != tc.want {
				t.Fatalf("networkStatisticsObserverEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStartInspectPayloadRetentionPurgesExpiredPayloads(t *testing.T) {
	paths := inspect.Paths{DataDir: filepath.Join(t.TempDir(), "payloads")}
	if err := os.MkdirAll(paths.DataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	expiredAt := time.Now().UTC().Add(-time.Minute)
	futureAt := time.Now().UTC().Add(time.Hour)
	expiredPath := writeInspectPayloadRecord(t, paths, "expired.json", &expiredAt)
	futurePath := writeInspectPayloadRecord(t, paths, "future.json", &futureAt)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		startInspectPayloadRetention(ctx, paths, time.Hour)
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(expiredPath); os.IsNotExist(err) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(expiredPath); !os.IsNotExist(err) {
		cancel()
		t.Fatalf("expired payload still exists or unexpected stat error: %v", err)
	}
	if _, err := os.Stat(futurePath); err != nil {
		cancel()
		t.Fatalf("future payload should remain: %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retention loop did not stop after context cancellation")
	}
}

func writeInspectPayloadRecord(t *testing.T, paths inspect.Paths, name string, expiresAt *time.Time) string {
	t.Helper()
	return writeInspectPayloadRecordWithFields(t, paths, name, inspect.PayloadRecord{
		Schema:    "agentsnitch.inspect_payload.v0",
		Captured:  time.Now().UTC(),
		ExpiresAt: expiresAt,
		Request:   "request",
		Response:  "response",
	})
}

func writeInspectPayloadRecordWithFields(t *testing.T, paths inspect.Paths, name string, record inspect.PayloadRecord) string {
	t.Helper()
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal payload record: %v", err)
	}
	path := filepath.Join(paths.DataDir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile payload record: %v", err)
	}
	return path
}

func TestReverseDNSLookupEnabledDefaultsOff(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"", false},
		{"0", false},
		{"false", false},
		{"1", true},
		{"true", true},
		{"yes", true},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("AGENTSNITCH_ENABLE_REVERSE_DNS", tc.value)
			if got := reverseDNSLookupEnabled(); got != tc.want {
				t.Fatalf("reverseDNSLookupEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEnrichNetworkHostnameSkipsReverseDNSByDefault(t *testing.T) {
	resetReverseDNSCacheForTest(t)
	reverseDNSLookup = func(context.Context, string) ([]string, error) {
		t.Fatal("reverse DNS should be opt-in")
		return nil, nil
	}

	flow := event.NetworkFlowEvent{Remote: "93.184.216.34:443"}
	enrichNetworkHostname(&flow)
	if flow.PTRHostname != "" {
		t.Fatalf("PTRHostname = %q, want empty when reverse DNS is disabled", flow.PTRHostname)
	}
}

func TestEnrichNetworkHostnameKeepsReverseDNSOutOfSNI(t *testing.T) {
	t.Setenv("AGENTSNITCH_ENABLE_REVERSE_DNS", "1")
	originalLookup := reverseDNSLookup
	defer func() {
		reverseDNSLookup = originalLookup
		reverseDNSCache.Lock()
		reverseDNSCache.entries = make(map[string]reverseDNSCacheEntry)
		reverseDNSCache.Unlock()
	}()
	reverseDNSCache.Lock()
	reverseDNSCache.entries = make(map[string]reverseDNSCacheEntry)
	reverseDNSCache.Unlock()
	reverseDNSLookup = func(ctx context.Context, addr string) ([]string, error) {
		if addr != "93.184.216.34" {
			t.Fatalf("lookup addr = %q", addr)
		}
		return []string{"ptr.example.net."}, nil
	}

	flow := event.NetworkFlowEvent{
		Remote: "93.184.216.34:443",
	}
	enrichNetworkHostname(&flow)

	if flow.SNI != "" {
		t.Fatalf("SNI = %q, want empty for PTR-only lookup", flow.SNI)
	}
	if flow.Hostname != "" || flow.HostnameSource != "" {
		t.Fatalf("hostname = %q source %q, want empty for PTR-only lookup", flow.Hostname, flow.HostnameSource)
	}
	if flow.PTRHostname != "ptr.example.net" {
		t.Fatalf("PTRHostname = %q, want ptr.example.net", flow.PTRHostname)
	}
}

func TestEnrichNetworkHostnameRecordsObserverHostnameSource(t *testing.T) {
	flow := event.NetworkFlowEvent{
		Observer: "network_statistics",
		Remote:   "api.example.com:443",
	}
	enrichNetworkHostname(&flow)

	if flow.Hostname != "api.example.com" {
		t.Fatalf("hostname = %q, want api.example.com", flow.Hostname)
	}
	if flow.HostnameSource != "network_statistics" {
		t.Fatalf("hostname source = %q, want network_statistics", flow.HostnameSource)
	}
	if flow.SNI != "" || flow.PTRHostname != "" {
		t.Fatalf("unexpected SNI/PTR = %q/%q", flow.SNI, flow.PTRHostname)
	}
}

func TestRequestLsofBurstPollCoalescesWithoutBlocking(t *testing.T) {
	ch := make(chan struct{}, 1)
	requestLsofBurstPoll(ch)
	requestLsofBurstPoll(ch)

	if got := len(ch); got != 1 {
		t.Fatalf("queued burst requests = %d, want coalesced single request", got)
	}
	select {
	case <-ch:
	default:
		t.Fatal("expected burst request to be queued")
	}
	requestLsofBurstPoll(nil)
}

func TestParseNettopCSVRecordUsesProcessContextAndEndpoint(t *testing.T) {
	current := nettopProcessContext{}
	processes := map[int]correlator.ProcessInfo{
		78676: {PID: 78676, PPID: 123, Name: "/usr/bin/curl https://example.com", Source: "ps"},
	}
	now := time.Date(2026, time.June, 4, 5, 0, 0, 0, time.UTC)

	if flow, ok, err := parseNettopCSVLine("00:21:46.517293,curl.78676,,,0,0,0,0,0,,,,,,,,,,,,", &current, processes, now); err != nil || ok || flow.PID != 0 {
		t.Fatalf("process row parse = flow=%+v ok=%v err=%v", flow, ok, err)
	}
	flow, ok, err := parseNettopCSVLine("00:21:46.502363,tcp4 192.168.1.2:53124<->93.184.216.34:443,en0,Closed,1024,2048,0,0,0,,,,,,,,,,,,", &current, processes, now)
	if err != nil {
		t.Fatalf("socket row parse returned error: %v", err)
	}
	if !ok {
		t.Fatal("socket row was not parsed as a flow")
	}
	if flow.Observer != "network_statistics" || flow.PID != 78676 || flow.PPID != 123 || flow.ProcessPath != "/usr/bin/curl" {
		t.Fatalf("flow identity = %+v", flow)
	}
	if flow.Local != "192.168.1.2:53124" || flow.Remote != "93.184.216.34:443" {
		t.Fatalf("flow endpoints = local %q remote %q", flow.Local, flow.Remote)
	}
	if flow.State != "closed" || flow.BytesIn != 1024 || flow.BytesOut != 2048 || flow.Protocol != "tcp" {
		t.Fatalf("flow state/bytes/protocol = %+v", flow)
	}
}

func TestParseNettopCSVRecordAcceptsExitedProcessLabel(t *testing.T) {
	current := nettopProcessContext{}
	if _, ok, err := parseNettopCSVLine("00:22:40.553818,curl.78676,,,0,0,0,0,0,,,,,,,,,,,,", &current, nil, time.Now().UTC()); err != nil || ok {
		t.Fatalf("process row parse ok=%v err=%v", ok, err)
	}
	flow, ok, err := parseNettopCSVLine("00:22:40.553144,quic4 192.168.1.2:60697<->104.18.32.47:443,en0,,323420,34414,,,,35.69 ms,0,,BE,,,,,,,ch,", &current, nil, time.Now().UTC())
	if err != nil {
		t.Fatalf("quic row parse returned error: %v", err)
	}
	if !ok {
		t.Fatal("quic row was not parsed")
	}
	if flow.ProcessPath != "curl" || flow.Protocol != "quic" || flow.State != "data" {
		t.Fatalf("flow from exited process = %+v", flow)
	}
	if err := event.ValidateNetworkFlow(flow); err != nil {
		t.Fatalf("NetworkStatistics flow with process label should validate: %v", err)
	}
}

func TestNormalizeNettopEndpointIPv6DotPort(t *testing.T) {
	got := normalizeNettopEndpoint("fe80::3a09:4419:8e79:e079%utun4.1024")
	want := "[fe80::3a09:4419:8e79:e079%utun4]:1024"
	if got != want {
		t.Fatalf("normalizeNettopEndpoint() = %q, want %q", got, want)
	}
}

func TestParseProcessStartTime(t *testing.T) {
	got := parseProcessStartTime([]string{"Wed", "Jun", "3", "14:05:06", "2026"})
	want := time.Date(2026, time.June, 3, 14, 5, 6, 0, time.Local)
	if !got.Equal(want) {
		t.Fatalf("parseProcessStartTime() = %s, want %s", got, want)
	}
}

func TestParseProcessTableOutputPreservesProcessTreeAndCommand(t *testing.T) {
	out := strings.Join([]string{
		" 100 1 Wed Jun 3 14:05:06 2026 /Users/me/.local/bin/claude --dangerously-skip-permissions",
		" 200 100 Wed Jun 3 14:05:08 2026 /bin/zsh -c curl https://example.invalid",
	}, "\n")
	got := parseProcessTableOutput(out)

	parent := got[100]
	if parent.PPID != 1 || parent.Source != "ps" || !strings.Contains(parent.Name, "claude --dangerously") {
		t.Fatalf("parent process = %+v", parent)
	}
	child := got[200]
	if child.PPID != 100 || child.Source != "ps" || !strings.Contains(child.Name, "/bin/zsh -c curl") {
		t.Fatalf("child process = %+v", child)
	}
}

func TestDaemonSessionsRouteNetworkBySessionProcessGraph(t *testing.T) {
	sessions := newDaemonSessions()
	base := time.Now().UTC()

	sessionA := sessions.forSemantic(semanticForSessionTest("session-a", 100, 90, base))
	sessionA.state.AddSemanticEvent(semanticForSessionTest("session-a", 100, 90, base))
	sessionB := sessions.forSemantic(semanticForSessionTest("session-b", 200, 190, base))
	sessionB.state.AddSemanticEvent(semanticForSessionTest("session-b", 200, 190, base))

	got := sessions.candidatesForNetwork(event.NetworkFlowEvent{
		PID:    200,
		PPID:   190,
		Remote: "93.184.216.34:443",
	})

	if len(got) != 1 || got[0].id != "session-b" {
		t.Fatalf("network candidates = %+v, want only session-b", got)
	}
}

func TestDaemonSessionsRouteNetworkByDescendantAncestry(t *testing.T) {
	sessions := newDaemonSessions()
	base := time.Now().UTC()

	session := sessions.forSemantic(semanticForSessionTest("session-a", 100, 90, base))
	session.state.AddSemanticEvent(semanticForSessionTest("session-a", 100, 90, base))
	sessions.applyProcessSnapshotToStates(map[int]correlator.ProcessInfo{
		100: {PID: 100, PPID: 90, Name: "/opt/homebrew/bin/claude"},
		150: {PID: 150, PPID: 100, Name: "/bin/sh -c curl https://example.com"},
		200: {PID: 200, PPID: 150, Name: "/usr/bin/curl https://example.com"},
	})

	got := sessions.candidatesForNetwork(event.NetworkFlowEvent{
		PID:         200,
		PPID:        150,
		ProcessPath: "/usr/bin/curl",
		Remote:      "93.184.216.34:443",
	})

	if len(got) != 1 || got[0].id != "session-a" {
		t.Fatalf("network candidates = %+v, want session-a by descendant ancestry", got)
	}
}

func TestDaemonSessionsPruneIdleSessionsWithoutLiveAgentPID(t *testing.T) {
	sessions := newDaemonSessions()
	now := time.Now().UTC()

	expired := sessions.getOrCreate("expired")
	live := sessions.getOrCreate("live")
	live.state.AddPID(200)

	sessions.mu.Lock()
	expired.lastActivity = now.Add(-2 * defaultDaemonSessionIdle)
	live.lastActivity = now.Add(-2 * defaultDaemonSessionIdle)
	sessions.mu.Unlock()

	sessions.pruneIdle(now, map[int]correlator.ProcessInfo{
		200: {PID: 200, PPID: 1, Name: "/opt/homebrew/bin/claude"},
	}, defaultDaemonSessionIdle)

	got := sessions.list()
	if len(got) != 1 || got[0].id != "live" {
		t.Fatalf("sessions after prune = %+v, want only live session", got)
	}
}

func TestDaemonSessionPrunePurgesUntilSessionEndsPayloads(t *testing.T) {
	base := t.TempDir()
	t.Setenv("AGENTSNITCH_INSPECT_DIR", filepath.Join(base, "inspect"))
	paths := inspect.DefaultPaths()
	if err := os.MkdirAll(paths.DataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	endedSessionPath := writeInspectPayloadRecordWithFields(t, paths, "ended-session.json", inspect.PayloadRecord{
		Schema:    "agentsnitch.inspect_payload.v0",
		Captured:  time.Now().UTC(),
		Retention: inspect.FullPayloadUntilSession,
		SessionID: "expired",
		Request:   "request",
		Response:  "response",
	})
	manualPath := writeInspectPayloadRecordWithFields(t, paths, "manual.json", inspect.PayloadRecord{
		Schema:    "agentsnitch.inspect_payload.v0",
		Captured:  time.Now().UTC(),
		Retention: inspect.FullPayloadManual,
		SessionID: "expired",
		Request:   "request",
		Response:  "response",
	})
	livePath := writeInspectPayloadRecordWithFields(t, paths, "live.json", inspect.PayloadRecord{
		Schema:    "agentsnitch.inspect_payload.v0",
		Captured:  time.Now().UTC(),
		Retention: inspect.FullPayloadUntilSession,
		SessionID: "live",
		Request:   "request",
		Response:  "response",
	})

	sessions := newDaemonSessions()
	now := time.Now().UTC()
	expired := sessions.getOrCreate("expired")
	live := sessions.getOrCreate("live")
	live.state.AddPID(200)
	sessions.mu.Lock()
	expired.lastActivity = now.Add(-2 * defaultDaemonSessionIdle)
	live.lastActivity = now.Add(-2 * defaultDaemonSessionIdle)
	sessions.mu.Unlock()

	sessions.pruneIdle(now, map[int]correlator.ProcessInfo{
		200: {PID: 200, PPID: 1, Name: "/opt/homebrew/bin/claude"},
	}, defaultDaemonSessionIdle)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(endedSessionPath); os.IsNotExist(err) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(endedSessionPath); !os.IsNotExist(err) {
		t.Fatalf("ended-session payload still exists or unexpected stat error: %v", err)
	}
	for _, path := range []string{manualPath, livePath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("payload should remain at %s: %v", path, err)
		}
	}
}

func TestReconcileInspectCorrelationRequiresActiveToolSpan(t *testing.T) {
	sessions := newDaemonSessions()
	session := sessions.getOrCreate("session-1")
	session.state.AddSemanticEvent(event.SemanticEvent{
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PreToolUse",
		Tool:      "Bash",
		Tags:      []string{"external_egress_attempt"},
		ToolUseID: "tool-1",
		TS:        time.Now().UTC(),
	})

	exchange := event.InspectedHTTPExchange{
		Schema:    event.SchemaInspectedHTTPV0,
		TS:        time.Now().UTC(),
		SessionID: "session-1",
		ToolUseID: "tool-1",
		Request: event.InspectedHTTPRequest{
			Method: "POST",
			Scheme: "https",
			Host:   "api.example.com",
			Path:   "/upload",
		},
		TLS: event.InspectedHTTPTLS{InspectionMode: "local_mitm"},
		Correlation: event.InspectedHTTPCorrelation{
			Basis:      []string{"managed_proxy", "exact_requested_host"},
			Confidence: "medium",
		},
	}
	got := reconcileInspectCorrelation(exchange, sessions)
	if got.SpanID != "tool-1" || got.Correlation.Confidence != "high" || !containsString(got.Correlation.Basis, "active_tool_span") {
		t.Fatalf("active span not attached: %+v", got)
	}

	session.state.AddSemanticEvent(event.SemanticEvent{
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PostToolUse",
		Tool:      "Bash",
		ToolUseID: "tool-1",
		TS:        time.Now().UTC().Add(time.Second),
	})
	got = reconcileInspectCorrelation(exchange, sessions)
	if containsString(got.Correlation.Basis, "active_tool_span") || got.Correlation.Confidence != "medium" {
		t.Fatalf("closed span should not be active basis: %+v", got)
	}
}

func TestInspectScopeForActiveToolSpanRequiresLiveEgressSpan(t *testing.T) {
	sessions := newDaemonSessions()
	ctx := inspect.Context{SessionID: "session-1"}
	if _, ok := inspectScopeForActiveToolSpan(ctx, "api.example.com", sessions); ok {
		t.Fatal("scope allowed missing session")
	}

	session := sessions.getOrCreate("session-1")
	session.state.AddSemanticEvent(event.SemanticEvent{
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PreToolUse",
		Tool:      "Read",
		ToolUseID: "read-1",
		TS:        time.Now().UTC(),
	})
	if _, ok := inspectScopeForActiveToolSpan(ctx, "api.example.com", sessions); ok {
		t.Fatal("scope allowed non-egress span")
	}

	session.state.AddSemanticEvent(event.SemanticEvent{
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PreToolUse",
		Tool:      "Bash",
		Target:    "curl https://api.example.com",
		Tags:      []string{"external_egress_attempt"},
		ToolUseID: "tool-1",
		TS:        time.Now().UTC().Add(time.Second),
	})
	scoped, ok := inspectScopeForActiveToolSpan(ctx, "api.example.com", sessions)
	if !ok {
		t.Fatal("scope denied active egress span")
	}
	if scoped.ToolUseID != "tool-1" || scoped.SpanID != "tool-1" {
		t.Fatalf("scope did not enrich active span context: %+v", scoped)
	}

	session.state.AddSemanticEvent(event.SemanticEvent{
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PostToolUse",
		Tool:      "Bash",
		ToolUseID: "tool-1",
		TS:        time.Now().UTC().Add(2 * time.Second),
	})
	if _, ok := inspectScopeForActiveToolSpan(ctx, "api.example.com", sessions); ok {
		t.Fatal("scope allowed closed egress span")
	}
}

func TestHandleSemanticDrainsPendingNetworkFlowForExistingConnection(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("AGENTSNITCH_STATUS", filepath.Join(tmp, "status.json"))
	t.Setenv("AGENTSNITCH_TRANSCRIPTS_DIR", filepath.Join(tmp, "sessions"))

	sessions := newDaemonSessions()
	status := newStatusReporter()
	transcripts := asruntime.NewTranscriptWriter()
	base := time.Now().UTC()

	flow := networkFlowForSessionTest(123, 122, "192.0.2.1:50000", base)
	flow.State = "established"
	handleNetwork(flow, sessions, status, transcripts)
	if got := sessions.pendingCount(); got != 1 {
		t.Fatalf("pending flow count after unmatched network = %d, want 1", got)
	}

	handleSemantic(semanticForSessionTest("session-pending", 123, 122, base.Add(2*time.Second)), 0, false, sessions, status, transcripts, nil)
	if got := sessions.pendingCount(); got != 0 {
		t.Fatalf("pending flow count after semantic = %d, want 0", got)
	}

	got, err := asruntime.ReadStatus()
	if err != nil {
		t.Fatalf("ReadStatus returned error: %v", err)
	}
	if got.LastCorrelated == nil {
		t.Fatal("pending flow was not correlated after semantic event")
	}
	if !containsString(got.LastCorrelated.Reasons, "existing_connection_active") {
		t.Fatalf("correlation reasons = %v, want existing_connection_active", got.LastCorrelated.Reasons)
	}
}

// TestHandleSemanticDrainedFlowGetsForwardCorrelation guards architecture finding
// D: a flow held because no session yet owned its PID must, once drained, run
// through full TryCorrelate so it earns its forward within_10s/pid_match reasons,
// not only the backward existing_connection_active downgrade. If the drain loop
// regresses to AddNetworkFlow-only, this flow links with weaker reasons (or, for
// a "new"-state flow, not at all via the backward path) and the test fails.
func TestHandleSemanticDrainedFlowGetsForwardCorrelation(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("AGENTSNITCH_STATUS", filepath.Join(tmp, "status.json"))
	t.Setenv("AGENTSNITCH_TRANSCRIPTS_DIR", filepath.Join(tmp, "sessions"))

	sessions := newDaemonSessions()
	status := newStatusReporter()
	transcripts := asruntime.NewTranscriptWriter()
	base := time.Now().UTC()

	// The flow is observed (and held) before any session owns its PID, and its
	// timestamp is NEWER than the semantic event that later drains it. The
	// backward TryCorrelateSemantic path skips newer-than-now flows
	// (flow.TS.After(now) -> continue), so only the drain-time TryCorrelate(flow)
	// can link it — earning the forward within_10s + pid_match (high-confidence)
	// reasons. Without the fix the flow correlates via neither path and
	// LastCorrelated stays nil.
	flow := networkFlowForSessionTest(123, 122, "192.0.2.1:50000", base.Add(3*time.Second))
	flow.State = "new"
	handleNetwork(flow, sessions, status, transcripts)
	if got := sessions.pendingCount(); got != 1 {
		t.Fatalf("pending flow count after unmatched network = %d, want 1", got)
	}

	handleSemantic(semanticForSessionTest("session-fwd", 123, 122, base), 0, false, sessions, status, transcripts, nil)
	if got := sessions.pendingCount(); got != 0 {
		t.Fatalf("pending flow count after semantic = %d, want 0", got)
	}

	got, err := asruntime.ReadStatus()
	if err != nil {
		t.Fatalf("ReadStatus returned error: %v", err)
	}
	if got.LastCorrelated == nil {
		t.Fatal("drained flow was not correlated after semantic event")
	}
	if !containsString(got.LastCorrelated.Reasons, "within_10s") ||
		!containsString(got.LastCorrelated.Reasons, "pid_match") {
		t.Fatalf("drained-flow correlation reasons = %v, want within_10s and pid_match (forward, high-confidence)", got.LastCorrelated.Reasons)
	}
	if got.LastCorrelated.Confidence != "high" {
		t.Fatalf("drained-flow correlation confidence = %q, want high", got.LastCorrelated.Confidence)
	}
}

func TestAnnotatedNetworkFlowForSessionDoesNotMutateSharedFlow(t *testing.T) {
	nf := networkFlowForSessionTest(123, 122, "192.0.2.1:50000", time.Now().UTC())
	sessionA := newDaemonSessionWithNetworkAgent("session-a", "agent-a", 123)
	sessionB := newDaemonSessionWithNetworkAgent("session-b", "agent-b", 123)

	flowA := annotatedNetworkFlowForSession(nf, sessionA, nil)
	flowB := annotatedNetworkFlowForSession(nf, sessionB, nil)

	if nf.Agent != nil {
		t.Fatalf("base network flow Agent = %+v, want nil", nf.Agent)
	}
	if flowA.Agent == nil || flowA.Agent.ID != "agent-a" {
		t.Fatalf("flowA Agent = %+v, want agent-a", flowA.Agent)
	}
	if flowB.Agent == nil || flowB.Agent.ID != "agent-b" {
		t.Fatalf("flowB Agent = %+v, want agent-b", flowB.Agent)
	}
}

func TestDaemonSessionsKeepFirstDestinationPerSession(t *testing.T) {
	sessions := newDaemonSessions()
	base := time.Now().UTC()

	sessionA := sessions.forSemantic(semanticForSessionTest("session-a", 100, 90, base))
	sessionA.state.AddSemanticEvent(semanticForSessionTest("session-a", 100, 90, base))
	corrsA := sessionA.state.TryCorrelate(networkFlowForSessionTest(100, 90, "192.0.2.10:50000", base.Add(time.Second)))
	if len(corrsA) != 1 || !containsString(corrsA[0].Reasons, "first_destination") {
		t.Fatalf("session-a first destination reasons = %+v", corrsA)
	}

	sessionB := sessions.forSemantic(semanticForSessionTest("session-b", 200, 190, base))
	sessionB.state.AddSemanticEvent(semanticForSessionTest("session-b", 200, 190, base))
	corrsB := sessionB.state.TryCorrelate(networkFlowForSessionTest(200, 190, "192.0.2.11:50000", base.Add(time.Second)))
	if len(corrsB) != 1 || !containsString(corrsB[0].Reasons, "first_destination") {
		t.Fatalf("session-b first destination reasons = %+v", corrsB)
	}
}

func TestRefreshNetworkObservationRunsCorrelation(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("AGENTSNITCH_STATUS", tmp+"/status.json")
	t.Setenv("AGENTSNITCH_TRANSCRIPTS_DIR", tmp+"/sessions")

	state := correlator.NewSessionState()
	base := time.Now().UTC()
	state.AddSemanticEvent(event.SemanticEvent{
		Schema:    event.SchemaSemanticV0,
		TS:        base,
		Agent:     event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PreToolUse",
		Tool:      "Read",
		Target:    "/Users/me/.env",
		CWD:       "/Users/me/project",
		PID:       123,
		PPID:      122,
		Tags:      []string{"sensitive_read"},
		ToolUseID: "toolu-sensitive",
		InputSummary: map[string]interface{}{
			"file_path": "/Users/me/.env",
		},
	})

	status := newStatusReporter()
	transcripts := asruntime.NewTranscriptWriter()
	refreshNetworkObservation(event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base.Add(2 * time.Second),
		Observer:    "lsof",
		PID:         123,
		ProcessPath: "/opt/homebrew/bin/claude",
		Local:       "192.0.2.1:50000",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "established",
	}, state, status, transcripts, false)

	got, err := asruntime.ReadStatus()
	if err != nil {
		t.Fatalf("ReadStatus returned error: %v", err)
	}
	if got.LastCorrelated == nil {
		t.Fatal("refresh observation did not record a correlation")
	}
	if !containsString(got.LastCorrelated.Reasons, "within_10s") {
		t.Fatalf("expected within_10s reason, got %v", got.LastCorrelated.Reasons)
	}
}

func semanticForSessionTest(sessionID string, pid, ppid int, ts time.Time) event.SemanticEvent {
	return event.SemanticEvent{
		Schema:    event.SchemaSemanticV0,
		TS:        ts,
		Agent:     event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Session:   event.SessionInfo{ID: sessionID},
		Event:     "PreToolUse",
		Tool:      "Read",
		Target:    "/Users/me/project/.env",
		CWD:       "/Users/me/project",
		PID:       pid,
		PPID:      ppid,
		Tags:      []string{"sensitive_read"},
		ToolUseID: "toolu-sensitive-" + sessionID,
		InputSummary: map[string]interface{}{
			"file_path": "/Users/me/project/.env",
		},
	}
}

func networkFlowForSessionTest(pid, ppid int, local string, ts time.Time) event.NetworkFlowEvent {
	return event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          ts,
		Observer:    "network_extension",
		PID:         pid,
		PPID:        ppid,
		ProcessPath: "/opt/homebrew/bin/claude",
		Local:       local,
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "new",
	}
}

func newDaemonSessionWithNetworkAgent(sessionID, agentID string, pid int) *daemonSession {
	sess := &daemonSession{
		id:        sessionID,
		state:     correlator.NewSessionState(),
		subagents: newSubagentMonitor(),
	}
	sess.subagents.mu.Lock()
	defer sess.subagents.mu.Unlock()
	sess.subagents.agents[agentID] = event.AgentInfo{
		ID:   agentID,
		Type: "sub",
		Name: "claude",
		PID:  pid,
	}
	sess.subagents.pidToAgentID[pid] = agentID
	return sess
}

func TestEnrichNetworkFlowFromProcessesFillsMissingParentAndPath(t *testing.T) {
	nf := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        time.Now().UTC(),
		Observer:  "network_extension",
		PID:       4242,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	enrichNetworkFlowFromProcesses(&nf, map[int]correlator.ProcessInfo{
		4242: {
			PID:  4242,
			PPID: 4000,
			Name: "/bin/sh -c curl https://example.com",
		},
	})

	if nf.PPID != 4000 {
		t.Fatalf("PPID = %d, want 4000", nf.PPID)
	}
	if nf.ProcessPath != "/bin/sh" {
		t.Fatalf("ProcessPath = %q, want /bin/sh", nf.ProcessPath)
	}
}

func TestEnrichNetworkFlowFromProcessesPreservesObserverIdentity(t *testing.T) {
	nf := event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          time.Now().UTC(),
		Observer:    "network_extension",
		PID:         4242,
		PPID:        4001,
		ProcessPath: "/usr/bin/curl",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "established",
	}

	enrichNetworkFlowFromProcesses(&nf, map[int]correlator.ProcessInfo{
		4242: {
			PID:  4242,
			PPID: 4000,
			Name: "/bin/sh -c curl https://example.com",
		},
	})

	if nf.Observer != "network_extension" {
		t.Fatalf("Observer = %q, want network_extension", nf.Observer)
	}
	if nf.PPID != 4001 {
		t.Fatalf("PPID = %d, want existing 4001", nf.PPID)
	}
	if nf.ProcessPath != "/usr/bin/curl" {
		t.Fatalf("ProcessPath = %q, want existing /usr/bin/curl", nf.ProcessPath)
	}
}

func TestResolveProcessPathFindsUserLocalBinWhenPathIsMinimal(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
	binDir := filepath.Join(tmp, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir local bin: %v", err)
	}
	claudePath := filepath.Join(binDir, "claude")
	if err := os.WriteFile(claudePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake claude: %v", err)
	}

	got := resolveProcessPath("claude --dangerously-skip-permissions", "2.1.162")
	if got != claudePath {
		t.Fatalf("resolveProcessPath() = %q, want %q", got, claudePath)
	}
}

func TestDelegationPatternDetectsTmuxClaudeHookInput(t *testing.T) {
	got := delegationPattern(event.SemanticEvent{
		Tool:   "Bash",
		Target: "tmux new-session -d claude",
		InputSummary: map[string]interface{}{
			"command": "tmux new-session -d claude",
		},
	})
	if got != "tmux" {
		t.Fatalf("delegation pattern = %q, want tmux", got)
	}

	got = delegationPattern(event.SemanticEvent{
		Tool:   "Bash",
		Target: "start another claude in this repo",
		InputSummary: map[string]interface{}{
			"command": "echo start another claude",
		},
	})
	if got != "another claude" {
		t.Fatalf("delegation pattern = %q, want another claude", got)
	}
}

func TestSubagentMonitorLogsNewClaudeWithTmuxAncestor(t *testing.T) {
	var lines []string
	monitor := newSubagentMonitor()
	monitor.logf = func(format string, args ...interface{}) {
		lines = append(lines, formatLog(format, args...))
	}
	processes := map[int]correlator.ProcessInfo{
		100: {PID: 100, PPID: 1, Name: "/opt/homebrew/bin/tmux new-session"},
		200: {PID: 200, PPID: 100, Name: "/Users/scottmoore/.local/bin/claude"},
	}

	monitor.observe(processes, func(pid int) string {
		if pid == 200 {
			return "/tmp/project"
		}
		return ""
	})

	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "[SUBAGENT?]") || !strings.Contains(joined, "method=tmux") {
		t.Fatalf("missing tmux subagent log:\n%s", joined)
	}
	if !strings.Contains(joined, "pid=200") || !strings.Contains(joined, "cwd=/tmp/project") {
		t.Fatalf("subagent log missing pid/cwd context:\n%s", joined)
	}
}

func TestSubagentMonitorLogsNewClaudeAfterDelegationHookWithSameCWD(t *testing.T) {
	var lines []string
	monitor := newSubagentMonitor()
	monitor.logf = func(format string, args ...interface{}) {
		lines = append(lines, formatLog(format, args...))
	}
	monitor.recordSemantic(event.SemanticEvent{
		TS:     time.Now().UTC(),
		Tool:   "Bash",
		Target: "tmux new-session -d claude",
		CWD:    "/tmp/project",
		PID:    300,
		PPID:   250,
		InputSummary: map[string]interface{}{
			"command": "tmux new-session -d claude",
		},
	})

	monitor.observe(map[int]correlator.ProcessInfo{
		400: {PID: 400, PPID: 1, Name: "/Users/scottmoore/.local/bin/claude"},
	}, func(pid int) string {
		return "/tmp/project"
	})

	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "[SUBAGENT-DELEGATION]") {
		t.Fatalf("missing delegation log:\n%s", joined)
	}
	if !strings.Contains(joined, "[SUBAGENT?]") || !strings.Contains(joined, "method=hook") {
		t.Fatalf("missing hook subagent log:\n%s", joined)
	}
	if !strings.Contains(joined, "hook_pattern=tmux") || !strings.Contains(joined, "direct_child_of_hook=false") {
		t.Fatalf("subagent hook log missing expected context:\n%s", joined)
	}
}

func TestSubagentMonitorDoesNotMatchDelegationHookWithDifferentCWD(t *testing.T) {
	var lines []string
	monitor := newSubagentMonitor()
	monitor.logf = func(format string, args ...interface{}) {
		lines = append(lines, formatLog(format, args...))
	}
	monitor.recordSemantic(event.SemanticEvent{
		TS:     time.Now().UTC(),
		Tool:   "Bash",
		Target: "tmux new-session -d claude",
		CWD:    "/tmp/project-a",
		PID:    300,
		PPID:   250,
	})

	monitor.observe(map[int]correlator.ProcessInfo{
		400: {PID: 400, PPID: 1, Name: "/Users/scottmoore/.local/bin/claude"},
	}, func(pid int) string {
		return "/tmp/project-b"
	})

	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "[SUBAGENT?]") {
		t.Fatalf("different cwd should not log subagent candidate:\n%s", joined)
	}
}

func TestSubagentMonitorSuppressesBaselineClaudeProcesses(t *testing.T) {
	var lines []string
	monitor := newSubagentMonitor()
	monitor.logf = func(format string, args ...interface{}) {
		lines = append(lines, formatLog(format, args...))
	}
	processes := map[int]correlator.ProcessInfo{
		100: {PID: 100, PPID: 1, Name: "/opt/homebrew/bin/tmux new-session"},
		200: {PID: 200, PPID: 100, Name: "/Users/scottmoore/.local/bin/claude"},
	}
	monitor.markBaseline(processes)
	monitor.observe(processes, func(pid int) string { return "/tmp/project" })

	if joined := strings.Join(lines, "\n"); joined != "" {
		t.Fatalf("baseline processes should not log candidates:\n%s", joined)
	}
}

func TestSubagentMonitorLogsDirectClaudeChildWithoutTmux(t *testing.T) {
	var lines []string
	monitor := newSubagentMonitor()
	monitor.logf = func(format string, args ...interface{}) {
		lines = append(lines, formatLog(format, args...))
	}
	processes := map[int]correlator.ProcessInfo{
		100: {PID: 100, PPID: 1, Name: "/Users/scottmoore/.local/bin/claude"},
	}
	monitor.markBaseline(processes)

	processes[200] = correlator.ProcessInfo{PID: 200, PPID: 100, Name: "/Users/scottmoore/.local/bin/claude"}
	monitor.observe(processes, func(pid int) string {
		if pid == 200 {
			return "/tmp/project"
		}
		return ""
	})

	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "[SUBAGENT?]") || !strings.Contains(joined, "method=claude_ancestor") {
		t.Fatalf("missing direct Claude ancestry subagent log:\n%s", joined)
	}
	if strings.Contains(joined, "method=tmux") {
		t.Fatalf("direct Claude ancestry should not require tmux:\n%s", joined)
	}
}

func TestSubagentMonitorEmitsLifecycleAndTagsSubagentSemantic(t *testing.T) {
	monitor := newSubagentMonitor()
	processes := map[int]correlator.ProcessInfo{
		100: {PID: 100, PPID: 1, Name: "/Users/scottmoore/.local/bin/claude"},
	}
	monitor.markBaseline(processes)
	processes[200] = correlator.ProcessInfo{PID: 200, PPID: 100, Name: "/Users/scottmoore/.local/bin/claude"}

	events := monitor.observe(processes, func(pid int) string { return "/tmp/project" })
	if len(events.lifecycle) != 1 {
		t.Fatalf("lifecycle events = %d, want 1", len(events.lifecycle))
	}
	if events.lifecycle[0].Event != "new_subagent" || events.lifecycle[0].Agent.ID != "sub_200" {
		t.Fatalf("unexpected lifecycle event: %#v", events.lifecycle[0])
	}
	if events.lifecycle[0].Agent.ParentAgentID != "main_100" || events.lifecycle[0].Agent.SpawnMethod != "direct" {
		t.Fatalf("unexpected sub-agent parent/spawn: %#v", events.lifecycle[0].Agent)
	}

	semantic := event.SemanticEvent{
		TS:      time.Now().UTC(),
		Agent:   event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Session: event.SessionInfo{ID: "session-1"},
		Event:   "PreToolUse",
		Tool:    "Bash",
		CWD:     "/tmp/project",
		PID:     300,
		PPID:    200,
	}
	processes[300] = correlator.ProcessInfo{PID: 300, PPID: 200, Name: "/bin/zsh -c echo ok"}
	monitor.annotateSemantic(&semantic, processes)
	if semantic.Agent.ID != "sub_200" || semantic.Agent.Type != "sub" || semantic.Agent.PID != 200 {
		t.Fatalf("semantic not tagged with sub-agent: %#v", semantic.Agent)
	}
}

func TestSubagentMonitorEmitsHookInferredAgentToolSubagent(t *testing.T) {
	monitor := newSubagentMonitor()
	processes := map[int]correlator.ProcessInfo{
		100: {PID: 100, PPID: 1, Name: "/Users/scottmoore/.local/bin/claude"},
		300: {PID: 300, PPID: 100, Name: "/bin/zsh -c agentsnitch-emitter"},
	}
	monitor.markBaseline(processes)

	semantic := event.SemanticEvent{
		TS:        time.Now().UTC(),
		Agent:     event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PreToolUse",
		Tool:      "Agent",
		CWD:       "/tmp/project",
		PID:       300,
		PPID:      100,
		ToolUseID: "toolu_017A7jYHiDxn5K8M6mvYT3QL",
		InputSummary: map[string]interface{}{
			"description":   "Audit Connect/Teams/Members",
			"subagent_type": "general-purpose",
		},
	}

	events := monitor.annotateSemantic(&semantic, processes)
	if len(events.lifecycle) != 1 {
		t.Fatalf("lifecycle events = %d, want 1", len(events.lifecycle))
	}
	agent := events.lifecycle[0].Agent
	if events.lifecycle[0].Event != "new_subagent" || agent.Type != "sub" || agent.SpawnMethod != "hook" {
		t.Fatalf("unexpected hook lifecycle event: %#v", events.lifecycle[0])
	}
	if agent.Name != "Audit Connect/Teams/Members" || agent.Version != "general-purpose" {
		t.Fatalf("hook-inferred agent name/type missing: %#v", agent)
	}
	if agent.ParentAgentID != "main_100" || agent.PID != 300 {
		t.Fatalf("hook-inferred agent parent/pid missing: %#v", agent)
	}
	if semantic.Agent.ID != agent.ID {
		t.Fatalf("semantic not tagged with hook-inferred sub-agent: %#v", semantic.Agent)
	}

	post := event.SemanticEvent{
		TS:        time.Now().UTC(),
		Agent:     event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PostToolUse",
		Tool:      "Agent",
		CWD:       "/tmp/project",
		PID:       301,
		PPID:      100,
		ToolUseID: semantic.ToolUseID,
	}
	events = monitor.annotateSemantic(&post, processes)
	if len(events.lifecycle) != 0 {
		t.Fatalf("existing hook sub-agent should not re-emit lifecycle: %#v", events)
	}
	if post.Agent.ID != agent.ID || post.Agent.Name != agent.Name {
		t.Fatalf("post hook not tagged with existing hook-inferred sub-agent: %#v", post.Agent)
	}
}

func TestSubagentMonitorEmitsTaskCreateSubagent(t *testing.T) {
	monitor := newSubagentMonitor()
	processes := map[int]correlator.ProcessInfo{
		100: {PID: 100, PPID: 1, Name: "/Users/scottmoore/.local/bin/claude"},
		300: {PID: 300, PPID: 100, Name: "/bin/zsh -c agentsnitch-emitter"},
	}
	monitor.markBaseline(processes)

	semantic := event.SemanticEvent{
		TS:        time.Now().UTC(),
		Agent:     event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PreToolUse",
		Tool:      "TaskCreate",
		CWD:       "/tmp/project",
		PID:       300,
		PPID:      100,
		ToolUseID: "toolu_01VqBvZaQqBtHuiNt1TWDFTt",
		InputSummary: map[string]interface{}{
			"activeForm":  "Building Dashboard/Editor",
			"subject":     "Dashboard/Editor (engine integration)",
			"description": "Main-thread: client editor wired to transformAll().",
		},
	}

	events := monitor.annotateSemantic(&semantic, processes)
	if len(events.lifecycle) != 1 {
		t.Fatalf("lifecycle events = %d, want 1", len(events.lifecycle))
	}
	agent := events.lifecycle[0].Agent
	if events.lifecycle[0].Event != "new_subagent" || agent.Type != "sub" || agent.SpawnMethod != "hook" {
		t.Fatalf("unexpected task lifecycle event: %#v", events.lifecycle[0])
	}
	if agent.Name != "Building Dashboard/Editor" {
		t.Fatalf("task sub-agent name = %q", agent.Name)
	}
	if agent.ParentAgentID != "main_100" || agent.PID != 300 {
		t.Fatalf("task sub-agent parent/pid missing: %#v", agent)
	}
	if semantic.Agent.ID != agent.ID || semantic.Agent.Type != "sub" {
		t.Fatalf("semantic not tagged with task sub-agent: %#v", semantic.Agent)
	}
}

func TestSubagentMonitorIndexesClaudeSidechainTranscriptAndTagsSubagentSemantic(t *testing.T) {
	// The daemon only indexes transcripts under ~/.claude/projects (security
	// finding S-1: hook-supplied transcript_path is contained). Build the
	// transcript tree inside that root so the test exercises real indexing.
	home := t.TempDir()
	t.Setenv("HOME", home)
	tmp := filepath.Join(home, ".claude", "projects", "tmp-project")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatalf("MkdirAll projects dir returned error: %v", err)
	}
	parent := filepath.Join(tmp, "session.jsonl")
	subagentsDir := filepath.Join(tmp, "session", "subagents")
	if err := os.MkdirAll(subagentsDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	sidechain := filepath.Join(subagentsDir, "agent-a036ce88d8d00845a.jsonl")
	meta := filepath.Join(subagentsDir, "agent-a036ce88d8d00845a.meta.json")
	prompt := "You are doing QA.\n\nYOUR SCOPE\n- src/pages/Pasture.tsx\n- src/pages/PlantVM.tsx\n- src/pages/VMDetail.tsx\n\nAfter fixing, report."
	parentLine := `{"isSidechain":false,"message":{"content":[{"type":"tool_use","id":"toolu_parent_agent","name":"Agent","input":{"description":"Audit Pasture/PlantVM/VMDetail","subagent_type":"general-purpose"}}]}}`
	sidechainUser := fmt.Sprintf(`{"isSidechain":true,"agentId":"a036ce88d8d00845a","type":"user","cwd":"/tmp/project/frontend","message":{"content":%q}}`, prompt)
	sidechainTool := `{"isSidechain":true,"agentId":"a036ce88d8d00845a","cwd":"/tmp/project/frontend","message":{"content":[{"type":"tool_use","id":"toolu_sidechain_screenshot","name":"mcp__plugin_playwright_playwright__browser_take_screenshot","input":{"filename":"vmdetail-dark-1440.png"}}]}}`
	if err := os.WriteFile(parent, []byte(parentLine+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile parent returned error: %v", err)
	}
	if err := os.WriteFile(sidechain, []byte(sidechainUser+"\n"+sidechainTool+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile sidechain returned error: %v", err)
	}
	if err := os.WriteFile(meta, []byte(`{"agentType":"general-purpose","description":"QA Pasture/PlantVM/VMDetail"}`), 0o644); err != nil {
		t.Fatalf("WriteFile meta returned error: %v", err)
	}

	monitor := newSubagentMonitor()
	processes := map[int]correlator.ProcessInfo{
		100: {PID: 100, PPID: 1, Name: "/Users/scottmoore/.local/bin/claude"},
		300: {PID: 300, PPID: 100, Name: "/bin/zsh -c agentsnitch-emitter"},
	}
	monitor.markBaseline(processes)
	semantic := event.SemanticEvent{
		TS:        time.Now().UTC(),
		Agent:     event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PreToolUse",
		Tool:      "mcp__plugin_playwright_playwright__browser_take_screenshot",
		CWD:       "/tmp/project/frontend",
		PID:       300,
		PPID:      100,
		ToolUseID: "toolu_sidechain_screenshot",
		RawRef:    parent,
		InputSummary: map[string]interface{}{
			"filename": "vmdetail-dark-1440.png",
		},
	}

	events := monitor.annotateSemantic(&semantic, processes)
	if len(events.lifecycle) != 1 {
		t.Fatalf("lifecycle events = %d, want 1: %#v", len(events.lifecycle), events)
	}
	if events.lifecycle[0].Agent.ID != "subchain_a036ce88d8d00845a" || events.lifecycle[0].Agent.Name != "QA Pasture/PlantVM/VMDetail" {
		t.Fatalf("unexpected sidechain lifecycle: %#v", events.lifecycle[0].Agent)
	}
	if semantic.Agent.ID != events.lifecycle[0].Agent.ID || semantic.Agent.Type != "sub" {
		t.Fatalf("semantic not tagged with sidechain sub-agent: %#v", semantic.Agent)
	}
	if semantic.Agent.PID != 300 {
		t.Fatalf("semantic sidechain pid = %d, want latest hook pid 300", semantic.Agent.PID)
	}
	if len(events.semantics) != 0 {
		t.Fatalf("transcript-only sidechain activity should stay internal: %#v", events.semantics)
	}
}

func TestSubagentMonitorAliasesSidechainMetaToLaunchToolUse(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	projectDir := filepath.Join(tmp, ".claude", "projects", "-tmp-project")
	sessionDir := filepath.Join(projectDir, "session-launch")
	subagentsDir := filepath.Join(sessionDir, "subagents")
	if err := os.MkdirAll(subagentsDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	parent := filepath.Join(projectDir, "session-launch.jsonl")
	sidechain := filepath.Join(subagentsDir, "agent-a036ce88d8d00845a.jsonl")
	meta := filepath.Join(subagentsDir, "agent-a036ce88d8d00845a.meta.json")
	sidechainUser := `{"isSidechain":true,"agentId":"a036ce88d8d00845a","type":"user","cwd":"/tmp/project","message":{"content":"Build connections screen"}}`
	sidechainTool := `{"isSidechain":true,"agentId":"a036ce88d8d00845a","cwd":"/tmp/project","message":{"content":[{"type":"tool_use","id":"toolu_sidechain_read","name":"Read","input":{"file_path":"/tmp/project/app.ts"}}]}}`
	if err := os.WriteFile(parent, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile parent returned error: %v", err)
	}
	if err := os.WriteFile(sidechain, []byte(sidechainUser+"\n"+sidechainTool+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile sidechain returned error: %v", err)
	}
	if err := os.WriteFile(meta, []byte(`{"agentType":"general-purpose","description":"Build connections screen","toolUseId":"toolu_launch_agent"}`), 0o644); err != nil {
		t.Fatalf("WriteFile meta returned error: %v", err)
	}

	monitor := newSubagentMonitor()
	processes := map[int]correlator.ProcessInfo{
		100: {PID: 100, PPID: 1, Name: "/Users/scottmoore/.local/bin/claude"},
		300: {PID: 300, PPID: 100, Name: "/bin/zsh -c agentsnitch-emitter"},
		301: {PID: 301, PPID: 100, Name: "/bin/zsh -c agentsnitch-emitter"},
	}
	monitor.markBaseline(processes)
	launch := event.SemanticEvent{
		TS:        time.Now().UTC(),
		Agent:     event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Session:   event.SessionInfo{ID: "session-launch"},
		Event:     "PreToolUse",
		Tool:      "Agent",
		CWD:       "/tmp/project",
		PID:       300,
		PPID:      100,
		ToolUseID: "toolu_launch_agent",
		InputSummary: map[string]interface{}{
			"description":   "Build connections screen",
			"subagent_type": "general-purpose",
		},
	}
	launchEvents := monitor.annotateSemantic(&launch, processes)
	if len(launchEvents.lifecycle) != 1 {
		t.Fatalf("launch lifecycle events = %d, want 1", len(launchEvents.lifecycle))
	}
	launchID := launchEvents.lifecycle[0].Agent.ID
	if launchID != "subhook_toolu_launch_agent" {
		t.Fatalf("launch agent id = %q", launchID)
	}

	tool := event.SemanticEvent{
		TS:        time.Now().UTC(),
		Agent:     event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Session:   event.SessionInfo{ID: "session-launch"},
		Event:     "PreToolUse",
		Tool:      "Read",
		CWD:       "/tmp/project",
		PID:       301,
		PPID:      100,
		ToolUseID: "toolu_sidechain_read",
		RawRef:    parent,
		InputSummary: map[string]interface{}{
			"file_path": "/tmp/project/app.ts",
		},
	}
	toolEvents := monitor.annotateSemantic(&tool, processes)
	if tool.Agent.ID != launchID {
		t.Fatalf("sidechain tool agent id = %q, want launch id %q", tool.Agent.ID, launchID)
	}
	if tool.Agent.Name != "Build connections screen" {
		t.Fatalf("sidechain tool agent name = %q", tool.Agent.Name)
	}
	if tool.Agent.SpawnMethod != "claude_sidechain" {
		t.Fatalf("sidechain tool spawn method = %q", tool.Agent.SpawnMethod)
	}
	if tool.Agent.PID != 301 {
		t.Fatalf("sidechain tool pid = %d, want latest hook pid 301", tool.Agent.PID)
	}
	if len(toolEvents.lifecycle) != 0 {
		t.Fatalf("sidechain alias should not emit duplicate lifecycle: %#v", toolEvents.lifecycle)
	}
}

func TestSubagentMonitorLogsHookLineageWithoutDelegationKeyword(t *testing.T) {
	var lines []string
	monitor := newSubagentMonitor()
	monitor.logf = func(format string, args ...interface{}) {
		lines = append(lines, formatLog(format, args...))
	}
	monitor.recordSemantic(event.SemanticEvent{
		TS:      time.Now().UTC(),
		Agent:   event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Session: event.SessionInfo{ID: "session-1"},
		Tool:    "Bash",
		Target:  "pwd",
		CWD:     "/tmp/project",
		PID:     300,
		PPID:    250,
	})

	monitor.observe(map[int]correlator.ProcessInfo{
		300: {PID: 300, PPID: 250, Name: "/bin/zsh -c pwd"},
		301: {PID: 301, PPID: 300, Name: "/bin/sh -c claude"},
		400: {PID: 400, PPID: 301, Name: "/Users/scottmoore/.local/bin/claude"},
	}, func(pid int) string {
		if pid == 400 {
			return "/tmp/project"
		}
		return ""
	})

	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "[SUBAGENT-DELEGATION]") {
		t.Fatalf("generic hook should not be logged as delegation:\n%s", joined)
	}
	if !strings.Contains(joined, "[SUBAGENT?]") || !strings.Contains(joined, "method=hook_lineage|session_cwd") {
		t.Fatalf("missing hook lineage subagent log:\n%s", joined)
	}
}

func TestSubagentMonitorLogsClaudeBurstWithoutTmuxOrHook(t *testing.T) {
	var lines []string
	monitor := newSubagentMonitor()
	monitor.logf = func(format string, args ...interface{}) {
		lines = append(lines, formatLog(format, args...))
	}
	monitor.observe(map[int]correlator.ProcessInfo{
		200: {PID: 200, PPID: 1, Name: "/Users/scottmoore/.local/bin/claude"},
		201: {PID: 201, PPID: 1, Name: "/Users/scottmoore/.local/bin/claude"},
		202: {PID: 202, PPID: 1, Name: "/Users/scottmoore/.local/bin/claude"},
	}, func(pid int) string {
		return "/tmp/project"
	})

	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "[SUBAGENT-BURST?]") || !strings.Contains(joined, "count=3") {
		t.Fatalf("missing Claude burst summary:\n%s", joined)
	}
	if !strings.Contains(joined, "[SUBAGENT?]") || !strings.Contains(joined, "method=burst") {
		t.Fatalf("missing burst candidate log:\n%s", joined)
	}
}

func TestSubagentMonitorDoesNotLogSingleClaudeAfterGenericSessionHook(t *testing.T) {
	var lines []string
	monitor := newSubagentMonitor()
	monitor.logf = func(format string, args ...interface{}) {
		lines = append(lines, formatLog(format, args...))
	}
	monitor.recordSemantic(event.SemanticEvent{
		TS:      time.Now().UTC(),
		Agent:   event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Session: event.SessionInfo{ID: "session-1"},
		Tool:    "Bash",
		Target:  "pwd",
		CWD:     "/tmp/project",
		PID:     300,
		PPID:    250,
	})

	monitor.observe(map[int]correlator.ProcessInfo{
		400: {PID: 400, PPID: 1, Name: "/Users/scottmoore/.local/bin/claude"},
	}, func(pid int) string {
		return "/tmp/project"
	})

	if joined := strings.Join(lines, "\n"); joined != "" {
		t.Fatalf("single unrelated Claude in same cwd should not log without ancestry or burst:\n%s", joined)
	}
}

func formatLog(format string, args ...interface{}) string {
	return strings.TrimSpace(strings.ReplaceAll(fmt.Sprintf(format, args...), "\n", " "))
}

func TestShouldForwardRawNetworkToUIAllowsAgentRelevantNewFlow(t *testing.T) {
	state := correlator.NewSessionState()
	state.AddPID(4242)

	if !shouldForwardRawNetworkToUI(event.NetworkFlowEvent{
		PID:       4242,
		Remote:    "93.184.216.34:443",
		Direction: "out",
		State:     "new",
	}, state, false) {
		t.Fatal("agent-relevant new flow should be visible in the Network tab")
	}
}

func TestEnrichNetworkHostnameUsesCachedReverseDNS(t *testing.T) {
	t.Setenv("AGENTSNITCH_ENABLE_REVERSE_DNS", "1")
	resetReverseDNSCacheForTest(t)
	calls := 0
	reverseDNSLookup = func(_ context.Context, ip string) ([]string, error) {
		calls++
		if ip != "93.184.216.34" {
			t.Fatalf("lookup ip = %q", ip)
		}
		return []string{"example.invalid."}, nil
	}

	first := event.NetworkFlowEvent{Remote: "93.184.216.34:443"}
	enrichNetworkHostname(&first)
	if first.SNI != "" {
		t.Fatalf("SNI = %q, want empty for PTR-only lookup", first.SNI)
	}
	if first.PTRHostname != "example.invalid" {
		t.Fatalf("PTRHostname = %q, want reverse DNS hostname", first.PTRHostname)
	}

	second := event.NetworkFlowEvent{Remote: "93.184.216.34:443"}
	enrichNetworkHostname(&second)
	if second.SNI != "" {
		t.Fatalf("cached SNI = %q, want empty for PTR-only lookup", second.SNI)
	}
	if second.PTRHostname != "example.invalid" {
		t.Fatalf("cached PTRHostname = %q, want reverse DNS hostname", second.PTRHostname)
	}
	if calls != 1 {
		t.Fatalf("reverse DNS lookups = %d, want 1", calls)
	}
}

func TestEnrichNetworkHostnameSkipsExistingAndPrivateDestinations(t *testing.T) {
	resetReverseDNSCacheForTest(t)
	reverseDNSLookup = func(context.Context, string) ([]string, error) {
		t.Fatal("reverse DNS should not run")
		return nil, nil
	}

	existing := event.NetworkFlowEvent{Remote: "93.184.216.34:443", SNI: "api.example.com"}
	enrichNetworkHostname(&existing)
	if existing.SNI != "api.example.com" {
		t.Fatalf("existing SNI changed to %q", existing.SNI)
	}
	if existing.Hostname != "api.example.com" || existing.HostnameSource != "sni" {
		t.Fatalf("existing SNI did not populate hostname provenance: %+v", existing)
	}

	private := event.NetworkFlowEvent{Remote: "192.168.1.10:443"}
	enrichNetworkHostname(&private)
	if private.SNI != "" {
		t.Fatalf("private destination SNI = %q, want empty", private.SNI)
	}
}

func resetReverseDNSCacheForTest(t *testing.T) {
	t.Helper()
	originalLookup := reverseDNSLookup
	reverseDNSCache.Lock()
	reverseDNSCache.entries = make(map[string]reverseDNSCacheEntry)
	reverseDNSCache.Unlock()
	t.Cleanup(func() {
		reverseDNSLookup = originalLookup
		reverseDNSCache.Lock()
		reverseDNSCache.entries = make(map[string]reverseDNSCacheEntry)
		reverseDNSCache.Unlock()
	})
}

func TestShouldForwardRawNetworkToUIForSessionsShowsFirstEstablishedDestinationOnly(t *testing.T) {
	state := correlator.NewSessionState()
	state.AddPID(4242)
	session := &daemonSession{
		id:             "session-1",
		state:          state,
		rawNetworkSeen: make(map[string]time.Time),
	}
	flow := event.NetworkFlowEvent{
		PID:       4242,
		Remote:    "93.184.216.34:443",
		Direction: "out",
		State:     "established",
	}

	if !shouldForwardRawNetworkToUIForSessions(flow, nil, []*daemonSession{session}, false) {
		t.Fatal("first agent-relevant established flow should be visible in the Network tab")
	}
	if shouldForwardRawNetworkToUIForSessions(flow, nil, []*daemonSession{session}, false) {
		t.Fatal("repeat established refresh should not flood the UI")
	}
}

func TestShouldForwardRawNetworkToUIAllowsFirstUnattributedKnownAgentEstablishedDestination(t *testing.T) {
	sessions := newDaemonSessions()
	flow := event.NetworkFlowEvent{
		PID:         4242,
		ProcessPath: "/Users/scottmoore/.local/bin/claude",
		Remote:      "93.184.216.34:443",
		Direction:   "out",
		State:       "established",
	}

	if !shouldForwardRawNetworkToUIForSessions(flow, sessions, nil, false) {
		t.Fatal("first pre-hook known-agent established flow should be visible in the Network tab")
	}
	if shouldForwardRawNetworkToUIForSessions(flow, sessions, nil, false) {
		t.Fatal("repeat pre-hook established refresh should not flood the UI")
	}
}

func TestShouldForwardRawNetworkToUISuppressesPrivateAgentFlow(t *testing.T) {
	state := correlator.NewSessionState()
	state.AddPID(4242)

	if shouldForwardRawNetworkToUI(event.NetworkFlowEvent{
		PID:       4242,
		Remote:    "192.168.185.1:53",
		Direction: "out",
		State:     "new",
	}, state, false) {
		t.Fatal("private/local infrastructure flow should not clutter the UI Network tab")
	}
}

func TestShouldForwardRawNetworkToUISuppressesUntrackedCodexHelper(t *testing.T) {
	if shouldForwardRawNetworkToUI(event.NetworkFlowEvent{
		PID:             27929,
		ProcessPath:     "/Applications/Codex.app/Contents/Frameworks/Codex Framework.framework/Helpers/Codex (Service).app",
		ProcessBundleID: "com.openai.codex.helper",
		Remote:          "104.18.32.47:443",
		Direction:       "out",
		State:           "new",
	}, correlator.NewSessionState(), false) {
		t.Fatal("untracked desktop helper flow should not appear as Claude Code network evidence")
	}
}

func TestShouldForwardRawNetworkToUIAllowsCorrelatedFlow(t *testing.T) {
	if !shouldForwardRawNetworkToUI(event.NetworkFlowEvent{PID: 677, ProcessPath: "/usr/libexec/syspolicyd"}, correlator.NewSessionState(), true) {
		t.Fatal("correlated flow should forward raw network event")
	}
}

func TestShouldForwardRawNetworkToUISuppressesSystemNoise(t *testing.T) {
	if shouldForwardRawNetworkToUI(event.NetworkFlowEvent{
		PID:         677,
		ProcessPath: "/usr/libexec/syspolicyd",
		Remote:      "93.184.216.34:443",
		Direction:   "out",
		State:       "new",
	}, correlator.NewSessionState(), false) {
		t.Fatal("unrelated system flow should not forward raw network event")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// TestUIForwarderEnqueueNeverBlocksAndDropsOldest guards architecture finding G:
// forwarding to the UI must never block a hook/network handler and must bound
// memory when the UI is slow or absent. With a small queue we enqueue more than
// capacity and assert enqueue returns promptly (non-blocking) and the queue
// never exceeds capacity (drop-oldest, not unbounded growth).
func TestUIForwarderEnqueueNeverBlocksAndDropsOldest(t *testing.T) {
	f := &uiForwarder{queue: make(chan []byte, 2)}

	done := make(chan struct{})
	go func() {
		// No reader drains f.queue, so a blocking implementation would hang here.
		for i := 0; i < 100; i++ {
			f.enqueue([]byte{byte(i)})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("enqueue blocked when queue was full; forwarder is not non-blocking")
	}

	if got := len(f.queue); got > cap(f.queue) {
		t.Fatalf("queue length %d exceeds capacity %d; drop-oldest not enforced", got, cap(f.queue))
	}

	// The most recently enqueued events should be the ones retained.
	var last byte
	for len(f.queue) > 0 {
		last = (<-f.queue)[0]
	}
	if last != 99 {
		t.Fatalf("newest retained event = %d, want 99 (oldest should be dropped)", last)
	}
}

// TestWithinClaudeProjectsRootContainsHookSuppliedPaths guards security finding
// S-1: transcript_path arrives in the hook payload and must only be indexed when
// it resolves inside ~/.claude/projects. A prompt-injected sub-agent with Write/
// Bash is an in-scope adversary, so the guard must reject both parent-escapes
// and symlinks planted inside the root that point outward.
func TestWithinClaudeProjectsRootContainsHookSuppliedPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	projects := filepath.Join(home, ".claude", "projects")
	sessionDir := filepath.Join(projects, "proj", "subagents")
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatalf("mkdir session dir: %v", err)
	}
	inRoot := filepath.Join(sessionDir, "agent-x.jsonl")
	if err := os.WriteFile(inRoot, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write in-root transcript: %v", err)
	}

	// A real secret-like file outside the root, and a symlink inside the root
	// that points at the directory containing it.
	outside := filepath.Join(home, "secrets")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	secret := filepath.Join(outside, "id_rsa")
	if err := os.WriteFile(secret, []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	escapeLink := filepath.Join(projects, "escape")
	if err := os.Symlink(outside, escapeLink); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"in-root transcript", inRoot, true},
		{"projects root itself", projects, true},
		{"absolute outside path", secret, false},
		{"parent traversal", filepath.Join(projects, "..", "..", "secrets", "id_rsa"), false},
		{"symlink escape inside root", filepath.Join(escapeLink, "id_rsa"), false},
		{"empty path", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := withinClaudeProjectsRoot(tc.path); got != tc.want {
				t.Fatalf("withinClaudeProjectsRoot(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// isTrustedEmitterExe / isTrustedNetworkSenderExe are the pure path validators.
// These are the security-critical core: trust must key off the kernel-reported
// executable path, never the argv/command string.
func TestIsTrustedEmitterExe(t *testing.T) {
	t.Setenv("AGENTSNITCH_SUPPORT_DIR", "/Users/dev/Library/Application Support/AgentSnitch")
	t.Setenv("AGENTSNITCH_APP_PATH", "/Applications/AgentSnitch.app")
	const emitter = "/Users/dev/Library/Application Support/AgentSnitch/bin/emitter"
	cases := []struct {
		name string
		exe  string
		want bool
	}{
		{"installed emitter (env support dir)", emitter, true},
		{"evil emitter elsewhere", "/tmp/evil/emitter", false},
		{"emitter basename only (no path)", "emitter", false},
		{"sibling binary in support bin", "/Users/dev/Library/Application Support/AgentSnitch/bin/doctor", false},
		// SPOOF: a real binary whose ARGS mention the emitter path. The exe path is
		// /usr/bin/perl, so trust must be denied. (Old substring code accepted this.)
		{"spoof: real exe, fake path in args", "/usr/bin/perl", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		if got := isTrustedEmitterExe(tc.exe); got != tc.want {
			t.Errorf("%s: isTrustedEmitterExe(%q) = %v, want %v", tc.name, tc.exe, got, tc.want)
		}
	}
}

// Without AGENTSNITCH_SUPPORT_DIR, both the per-user (create.sh) and system-wide
// (signed .pkg) install dirs must be trusted.
func TestIsTrustedEmitterExeDefaultInstallDirs(t *testing.T) {
	t.Setenv("AGENTSNITCH_SUPPORT_DIR", "")
	t.Setenv("HOME", "/Users/dev")
	cases := map[string]bool{
		"/Users/dev/Library/Application Support/AgentSnitch/bin/emitter": true, // create.sh per-user
		"/Library/Application Support/AgentSnitch/bin/emitter":           true, // signed pkg system-wide
		"/tmp/evil/emitter": false,
	}
	for exe, want := range cases {
		if got := isTrustedEmitterExe(exe); got != want {
			t.Errorf("isTrustedEmitterExe(%q) = %v, want %v", exe, got, want)
		}
	}
}

func TestIsTrustedNetworkSenderExe(t *testing.T) {
	t.Setenv("AGENTSNITCH_APP_PATH", "/Applications/AgentSnitch.app")
	cases := []struct {
		name string
		exe  string
		want bool
	}{
		{"UI binary in bundle", "/Applications/AgentSnitch.app/Contents/MacOS/agentsnitch-ui", true},
		{"network extension in bundle", "/Applications/AgentSnitch.app/Contents/Library/SystemExtensions/com.somoore.agentsnitch.network-extension.systemextension/Contents/MacOS/AgentSnitchNetworkExtension", true},
		{"the app dir itself", "/Applications/AgentSnitch.app", true},
		// Activated Network Extension runs from the macOS system extension store.
		{"NE in system extension store", "/Library/SystemExtensions/AB12CD34-0000/com.somoore.agentsnitch.network-extension.systemextension/Contents/MacOS/AgentSnitchNetworkExtension", true},
		{"unrelated binary in system extension store", "/Library/SystemExtensions/AB12CD34-0000/com.evil.other/Contents/MacOS/x", false},
		{"evil binary outside bundle", "/tmp/evil/agentsnitch-ui", false},
		// SPOOF: prefix-confusion — a sibling dir that merely starts with the bundle name.
		{"spoof: bundle-name prefix sibling", "/Applications/AgentSnitch.app.evil/x", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		if got := isTrustedNetworkSenderExe(tc.exe); got != tc.want {
			t.Errorf("%s: isTrustedNetworkSenderExe(%q) = %v, want %v", tc.name, tc.exe, got, tc.want)
		}
	}
}

// The trusted*SocketPeer wrappers resolve the peer's executable path (injected
// here) and apply the validators. Confirms the resolver→validator wiring.
func TestTrustedSocketPeersUseExecutablePath(t *testing.T) {
	t.Setenv("AGENTSNITCH_SUPPORT_DIR", "/Users/dev/Library/Application Support/AgentSnitch")
	t.Setenv("AGENTSNITCH_APP_PATH", "/Applications/AgentSnitch.app")
	t.Setenv("AGENTSNITCH_TRUSTED_TEAM_ID", "ABCDE12345")

	exeByPID := map[int]string{
		100: "/Users/dev/Library/Application Support/AgentSnitch/bin/emitter", // real emitter
		101: "/usr/bin/perl",                                                  // spoof: AgentSnitch path only in args
		102: "/Applications/AgentSnitch.app/Contents/MacOS/agentsnitch-ui",    // real UI
		103: "/tmp/evil/agentsnitch-ui",                                       // impostor
	}
	orig := peerExePath
	t.Cleanup(func() { peerExePath = orig })
	peerExePath = func(pid int) (string, bool) {
		p, ok := exeByPID[pid]
		return p, ok
	}
	origIdentity := peerCodeIdentity
	t.Cleanup(func() { peerCodeIdentity = origIdentity })
	peerCodeIdentity = func(path string) (codeIdentity, bool) {
		if strings.HasPrefix(path, "/Users/dev/Library/Application Support/AgentSnitch/") ||
			strings.HasPrefix(path, "/Applications/AgentSnitch.app/") {
			return codeIdentity{TeamID: "ABCDE12345", CDHash: "abc"}, true
		}
		return codeIdentity{TeamID: "EVILTEAM00", CDHash: "bad"}, true
	}

	if !trustedSemanticSocketPeer(100, nil) {
		t.Fatal("installed emitter should be trusted for semantic events")
	}
	if trustedSemanticSocketPeer(101, nil) {
		t.Fatal("spoofed argv (real exe /usr/bin/perl) must NOT be trusted")
	}
	if !trustedNetworkSocketPeer(102, nil) {
		t.Fatal("installed UI should be trusted for network forwarding")
	}
	if !trustedControlSocketPeer(102) {
		t.Fatal("installed UI should be trusted for control messages")
	}
	if trustedNetworkSocketPeer(103, nil) {
		t.Fatal("impostor outside the app bundle must NOT be trusted")
	}
	if trustedControlSocketPeer(103) {
		t.Fatal("impostor outside the app bundle must NOT be trusted for control")
	}
	if trustedSemanticSocketPeer(999, nil) {
		t.Fatal("unresolvable peer PID must NOT be trusted")
	}
}

func TestTrustedControlSocketPeerRejectsNetworkExtension(t *testing.T) {
	t.Setenv("AGENTSNITCH_APP_PATH", "/Applications/AgentSnitch.app")
	t.Setenv("AGENTSNITCH_TRUSTED_TEAM_ID", "ABCDE12345")

	origExe := peerExePath
	t.Cleanup(func() { peerExePath = origExe })
	peerExePath = func(pid int) (string, bool) {
		switch pid {
		case 200:
			return "/Applications/AgentSnitch.app/Contents/MacOS/agentsnitch-ui", true
		case 201:
			return "/Library/SystemExtensions/AB12CD34-0000/com.somoore.agentsnitch.network-extension.systemextension/Contents/MacOS/AgentSnitchNetworkExtension", true
		default:
			return "", false
		}
	}

	origIdentity := peerCodeIdentity
	t.Cleanup(func() { peerCodeIdentity = origIdentity })
	peerCodeIdentity = func(string) (codeIdentity, bool) {
		return codeIdentity{TeamID: "ABCDE12345", CDHash: "abc"}, true
	}

	if !trustedControlSocketPeer(200) {
		t.Fatal("UI binary should be trusted for daemon control")
	}
	if !trustedNetworkSocketPeer(201, nil) {
		t.Fatal("Network Extension should remain trusted for network forwarding")
	}
	if trustedControlSocketPeer(201) {
		t.Fatal("Network Extension must not be trusted for pause/resume control")
	}
}

func TestSocketIngressRejectsMissingPeerIdentity(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("AGENTSNITCH_STATUS", filepath.Join(tmp, "status.json"))
	t.Setenv("AGENTSNITCH_TRANSCRIPTS_DIR", filepath.Join(tmp, "sessions"))

	sessions := newDaemonSessions()
	status := newStatusReporter()
	transcripts := asruntime.NewTranscriptWriter()
	base := time.Now().UTC()

	handleSocketSemantic(semanticForSessionTest("socket-no-peer", 123, 122, base), 0, false, sessions, status, transcripts, nil)
	if got := sessions.list(); len(got) != 0 {
		t.Fatalf("socket semantic without peer creds created sessions: %+v", got)
	}

	handleSocketNetwork(networkFlowForSessionTest(123, 122, "192.0.2.1:50000", base), 0, false, sessions, status, transcripts)
	if got := sessions.pendingCount(); got != 0 {
		t.Fatalf("socket network without peer creds created pending flows: %d", got)
	}
}

func TestTrustedSemanticHookOriginRequiresCLIAncestor(t *testing.T) {
	semantic := semanticForSessionTest("socket-origin", 300, 200, time.Now().UTC())
	processes := map[int]correlator.ProcessInfo{
		100: {PID: 100, PPID: 1, Name: "/opt/homebrew/bin/claude"},
		200: {PID: 200, PPID: 100, Name: "/bin/sh -c agentsnitch-emitter"},
		300: {PID: 300, PPID: 200, Name: "/Users/dev/Library/Application Support/AgentSnitch/bin/emitter"},
	}
	if !trustedSemanticHookOrigin(semantic, 300, processes) {
		t.Fatal("emitter under a CLI agent ancestor should be accepted")
	}
}

func TestTrustedSemanticHookOriginRejectsUnrelatedShell(t *testing.T) {
	semantic := semanticForSessionTest("socket-origin", 300, 200, time.Now().UTC())
	processes := map[int]correlator.ProcessInfo{
		200: {PID: 200, PPID: 1, Name: "/bin/zsh"},
		300: {PID: 300, PPID: 200, Name: "/Users/dev/Library/Application Support/AgentSnitch/bin/emitter"},
	}
	if trustedSemanticHookOrigin(semantic, 300, processes) {
		t.Fatal("emitter without a CLI agent ancestor must not be accepted as hook-origin evidence")
	}
}

func TestTrustedSocketPeersRejectWrongSignature(t *testing.T) {
	t.Setenv("AGENTSNITCH_SUPPORT_DIR", "/Users/dev/Library/Application Support/AgentSnitch")
	t.Setenv("AGENTSNITCH_TRUSTED_TEAM_ID", "ABCDE12345")

	origExe := peerExePath
	t.Cleanup(func() { peerExePath = origExe })
	peerExePath = func(int) (string, bool) {
		return "/Users/dev/Library/Application Support/AgentSnitch/bin/emitter", true
	}

	origIdentity := peerCodeIdentity
	t.Cleanup(func() { peerCodeIdentity = origIdentity })
	peerCodeIdentity = func(string) (codeIdentity, bool) {
		return codeIdentity{TeamID: "EVILTEAM00", CDHash: "bad"}, true
	}

	if trustedSemanticSocketPeer(100, nil) {
		t.Fatal("path-matching emitter with wrong TeamIdentifier must NOT be trusted")
	}
}

func TestTrustedSocketPeersAllowAdHocInstalledPeersWhenDaemonIsAdHoc(t *testing.T) {
	t.Setenv("AGENTSNITCH_SUPPORT_DIR", "/Users/dev/Library/Application Support/AgentSnitch")
	t.Setenv("AGENTSNITCH_TRUSTED_TEAM_ID", "")

	origExe := peerExePath
	t.Cleanup(func() { peerExePath = origExe })
	peerExePath = func(int) (string, bool) {
		return "/Users/dev/Library/Application Support/AgentSnitch/bin/emitter", true
	}

	origIdentity := peerCodeIdentity
	t.Cleanup(func() { peerCodeIdentity = origIdentity })
	peerCodeIdentity = func(string) (codeIdentity, bool) {
		return codeIdentity{AdHoc: true, CDHash: "abc"}, true
	}

	daemonCodeIdentity.Lock()
	origDaemonIdentity := daemonCodeIdentity.value
	origLoaded := daemonCodeIdentity.loaded
	daemonCodeIdentity.loaded = true
	daemonCodeIdentity.value = codeIdentity{AdHoc: true, CDHash: "daemon"}
	daemonCodeIdentity.Unlock()
	t.Cleanup(func() {
		daemonCodeIdentity.Lock()
		daemonCodeIdentity.value = origDaemonIdentity
		daemonCodeIdentity.loaded = origLoaded
		daemonCodeIdentity.Unlock()
	})

	if !trustedSemanticSocketPeer(100, nil) {
		t.Fatal("installed ad-hoc emitter should be trusted when daemon is also ad-hoc signed")
	}
}

func TestParseCodeIdentity(t *testing.T) {
	identity, ok := parseCodeIdentity("Executable=/x\nCDHash=abcdef\nTeamIdentifier=ABCDE12345\n")
	if !ok {
		t.Fatal("parseCodeIdentity should accept a real team id")
	}
	if identity.TeamID != "ABCDE12345" || identity.CDHash != "abcdef" {
		t.Fatalf("parseCodeIdentity = %+v", identity)
	}
	adhoc, ok := parseCodeIdentity("TeamIdentifier=not set\nSignature=adhoc\nCDHash=123456\n")
	if !ok || !adhoc.AdHoc || adhoc.TeamID != "" || adhoc.CDHash != "123456" {
		t.Fatalf("parseCodeIdentity should preserve ad-hoc identity, got %+v ok=%v", adhoc, ok)
	}
}
