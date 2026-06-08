package correlator

import (
	"strings"
	"testing"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
)

func TestSessionState_RingAndPID(t *testing.T) {
	s := NewSessionState()

	now := time.Now().UTC()

	for i := 0; i < MaxRecentEvents+10; i++ {
		e := event.SemanticEvent{
			Schema: event.SchemaSemanticV0,
			TS:     now.Add(time.Duration(i) * time.Second),
			Agent:  event.AgentInfo{ID: "claude", Name: "Claude Code"},
			Event:  "PreToolUse",
			Tool:   "Read",
			Target: "file" + string(rune('0'+i%10)),
			PID:    1000 + i,
			Tags:   []string{},
		}
		s.AddSemanticEvent(e)
	}

	recent := s.GetRecent()
	if len(recent) != MaxRecentEvents {
		t.Fatalf("ring did not trim to %d, got %d", MaxRecentEvents, len(recent))
	}

	first := recent[0]
	if first.PID != 1010 {
		t.Errorf("expected first in ring PID=1010 after trim, got %d", first.PID)
	}

	if !s.IsAgentPID(1000 + MaxRecentEvents + 9) {
		t.Error("expected high PID tracked")
	}
}

func TestSessionState_TracksActiveEgressToolSpan(t *testing.T) {
	s := NewSessionState()
	read := event.SemanticEvent{
		Session:   event.SessionInfo{ID: "s1"},
		Event:     "PreToolUse",
		Tool:      "Read",
		ToolUseID: "read-1",
		TS:        time.Now(),
	}
	s.AddSemanticEvent(read)
	if _, ok := s.ActiveToolSpan("read-1"); ok {
		t.Fatal("non-egress tool should not open active inspect span")
	}

	egress := event.SemanticEvent{
		Session:   event.SessionInfo{ID: "s1"},
		Event:     "PreToolUse",
		Tool:      "Bash",
		Target:    "curl https://api.example.com",
		Tags:      []string{"external_egress_attempt"},
		ToolUseID: "tool-1",
		TS:        time.Now().Add(time.Second),
	}
	s.AddSemanticEvent(egress)
	span, ok := s.ActiveEgressToolSpan()
	if !ok || span.ToolUseID != "tool-1" || span.SessionID != "s1" {
		t.Fatalf("active egress span = %+v ok=%t", span, ok)
	}

	s.AddSemanticEvent(event.SemanticEvent{
		Session:   event.SessionInfo{ID: "s1"},
		Event:     "PostToolUse",
		Tool:      "Bash",
		ToolUseID: "tool-1",
		TS:        time.Now().Add(2 * time.Second),
	})
	if _, ok := s.ActiveToolSpan("tool-1"); ok {
		t.Fatal("PostToolUse should close active inspect span")
	}
}

func TestSessionState_AddPIDAndSnapshot(t *testing.T) {
	s := NewSessionState()
	s.AddPID(4242)
	if !s.IsAgentPID(4242) {
		t.Error("AddPID did not register")
	}
	pids, err := s.SnapshotAgentProcesses()
	if err != nil {
		t.Logf("snapshot err (acceptable): %v", err)
	}
	_ = pids
}

func TestSessionState_NetworkFlowDoesNotSeedAgentPID(t *testing.T) {
	s := NewSessionState()
	s.AddNetworkFlow(event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          time.Now().UTC(),
		PID:         9090,
		ProcessPath: "Google Chrome Helper",
		Remote:      "203.0.113.10:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "established",
	})
	if s.IsAgentPID(9090) {
		t.Fatal("network-only PID should enrich process graph without becoming an agent-session PID")
	}
}

func TestSessionState_ProcessSnapshotClearsReusedAgentPID(t *testing.T) {
	s := NewSessionState()
	s.AddProcess(4242, 4000, "/opt/homebrew/bin/claude", "hook-parent")
	if !s.IsAgentPID(4242) {
		t.Fatal("expected initial agent PID membership")
	}

	s.ApplyProcessSnapshot(map[int]ProcessInfo{
		4242: {
			PID:  4242,
			PPID: 1,
			Name: "/usr/bin/curl https://example.com",
		},
	})

	if s.IsAgentPID(4242) {
		t.Fatal("reused PID should not keep stale agent-session membership")
	}
}

func TestSessionState_TryCorrelate_RejectsReusedPIDWithDifferentParent(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()
	s.AddSemanticEvent(event.SemanticEvent{
		Schema:    event.SchemaSemanticV0,
		TS:        base,
		Agent:     event.AgentInfo{ID: "claude"},
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PreToolUse",
		Tool:      "Read",
		Target:    "/Users/me/.env",
		CWD:       "/Users/me/project",
		PID:       4242,
		PPID:      4000,
		Tags:      []string{"sensitive_read"},
		ToolUseID: "toolu-sensitive",
		InputSummary: map[string]interface{}{
			"file_path": "/Users/me/.env",
		},
	})

	flow := event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base.Add(2 * time.Second),
		Observer:    "network_extension",
		PID:         4242,
		PPID:        1,
		ProcessPath: "/usr/bin/curl",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "new",
	}

	if got := s.TryCorrelate(flow); len(got) != 0 {
		t.Fatalf("reused PID with different parent should not correlate, got %d", len(got))
	}
}

func TestSessionState_TryCorrelate_RejectsReusedPIDWithLaterStart(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()
	s.AddSemanticEvent(event.SemanticEvent{
		Schema:    event.SchemaSemanticV0,
		TS:        base,
		Agent:     event.AgentInfo{ID: "claude"},
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PreToolUse",
		Tool:      "Read",
		Target:    "/Users/me/.env",
		CWD:       "/Users/me/project",
		PID:       4242,
		PPID:      4000,
		Tags:      []string{"sensitive_read"},
		ToolUseID: "toolu-sensitive",
		InputSummary: map[string]interface{}{
			"file_path": "/Users/me/.env",
		},
	})
	s.ApplyProcessSnapshot(map[int]ProcessInfo{
		4000: {
			PID:       4000,
			PPID:      1,
			Name:      "/bin/zsh",
			StartedAt: base.Add(-time.Hour),
		},
		4242: {
			PID:       4242,
			PPID:      4000,
			Name:      "Read",
			StartedAt: base.Add(time.Second),
		},
	})

	flow := event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base.Add(2 * time.Second),
		Observer:    "network_extension",
		PID:         4242,
		PPID:        4000,
		ProcessPath: "/opt/homebrew/bin/claude",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "new",
	}

	if got := s.TryCorrelate(flow); len(got) != 0 {
		t.Fatalf("reused PID with later process start should not correlate, got %d", len(got))
	}
}

func TestIdentifyAgentProcessDistinguishesCLIFromDesktopAndBrowser(t *testing.T) {
	cases := []struct {
		name     string
		wantID   string
		wantKind string
		wantOK   bool
	}{
		{name: "/opt/homebrew/bin/claude", wantID: "claude", wantKind: "claude_cli", wantOK: true},
		{name: "Claude", wantID: "claude", wantKind: "claude_desktop", wantOK: true},
		{name: "Claude Helper", wantID: "claude", wantKind: "claude_desktop", wantOK: true},
		{name: "/Applications/Codex.app/Contents/MacOS/Codex", wantID: "codex", wantKind: "codex_desktop", wantOK: true},
		{name: "/opt/homebrew/bin/codex", wantID: "codex", wantKind: "codex_cli", wantOK: true},
		{name: "Google Chrome Helper --origin=https://chat.openai.com", wantOK: false},
	}
	for _, tc := range cases {
		gotID, gotKind, gotOK := IdentifyAgentProcess(tc.name)
		if gotOK != tc.wantOK || gotID != tc.wantID || gotKind != tc.wantKind {
			t.Fatalf("IdentifyAgentProcess(%q) = (%q, %q, %v), want (%q, %q, %v)", tc.name, gotID, gotKind, gotOK, tc.wantID, tc.wantKind, tc.wantOK)
		}
	}
}

func TestSessionState_TryCorrelate_NaiveJoin(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC().Add(-1 * time.Minute)

	sens := event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "/Users/me/.env",
		PID:    9876,
		Tags:   []string{"sensitive_read"},
	}
	s.AddSemanticEvent(sens)

	old := event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base.Add(-30 * time.Second),
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "/etc/passwd",
		PID:    9877,
		Tags:   []string{},
	}
	s.AddSemanticEvent(old)

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(3 * time.Second),
		PID:       9876,
		Remote:    "93.184.216.34:443",
		SNI:       "example.com",
		Protocol:  "tcp",
		Direction: "out",
		BytesOut:  1234,
	}
	corrs := s.TryCorrelate(flow)
	if len(corrs) == 0 {
		t.Fatalf("expected >=1 correlation for sensitive_read + recent ext flow, got 0")
	}
	c := corrs[0]
	if c.Score < 0.5 {
		t.Errorf("positive score expected, got %f", c.Score)
	}
	if len(c.Semantics) == 0 || c.Semantics[0].PID != 9876 {
		t.Error("expected linked semantics with the sensitive PID")
	}
	if !c.Semantics[0].HasTag("sensitive_read") {
		t.Error("linked semantic should have sensitive_read tag")
	}
	if !contains(c.Reasons, "within_10s") {
		t.Fatalf("expected within_10s reason, got %v", c.Reasons)
	}
	if contains(c.Reasons, "same_agent_session") {
		t.Fatalf("exact pid match should not also claim same_agent_session: %v", c.Reasons)
	}
	for _, want := range []string{
		"Sensitive read → outbound connection",
		"Claude Code read /Users/me/.env",
		"3.0s later",
		"PID 9876 connected to 93.184.216.34:443",
		"Why linked: within_10s, pid_match, first_destination, after_sensitive_read",
	} {
		if !strings.Contains(c.Summary, want) {
			t.Fatalf("summary missing %q:\n%s", want, c.Summary)
		}
	}
	for _, forbidden := range []string{"exfil", "leaked", "stolen"} {
		if strings.Contains(strings.ToLower(c.Summary), forbidden) {
			t.Fatalf("summary used overclaim %q: %s", forbidden, c.Summary)
		}
	}

	loop := flow
	loop.Remote = "127.0.0.1:9"
	if len(s.TryCorrelate(loop)) != 0 {
		t.Error("loopback should not produce correlation")
	}
}

func TestSessionState_TryCorrelate_DedupesSameSemanticAndFlow(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema:    event.SchemaSemanticV0,
		TS:        base,
		Agent:     event.AgentInfo{ID: "claude"},
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PreToolUse",
		Tool:      "Read",
		Target:    "/Users/me/.env",
		CWD:       "/Users/me/project",
		PID:       100,
		PPID:      99,
		Tags:      []string{"sensitive_read"},
		ToolUseID: "toolu-sensitive",
		InputSummary: map[string]interface{}{
			"file_path": "/Users/me/.env",
		},
	})

	flow := event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base.Add(2 * time.Second),
		FlowID:      "first-observation",
		Observer:    "lsof",
		PID:         100,
		ProcessPath: "/opt/homebrew/bin/claude",
		Local:       "192.0.2.1:50000",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "established",
	}

	if got := s.TryCorrelate(flow); len(got) != 1 {
		t.Fatalf("first observation should correlate once, got %d", len(got))
	}
	flow.FlowID = "refresh-observation"
	flow.TS = base.Add(4 * time.Second)
	if got := s.TryCorrelate(flow); len(got) != 0 {
		t.Fatalf("refresh of same semantic+stable flow should dedupe, got %d", len(got))
	}
}

func TestSessionState_TryCorrelate_SuppressesWeakerMatchAfterDirectMatch(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema:    event.SchemaSemanticV0,
		TS:        base,
		Agent:     event.AgentInfo{ID: "claude"},
		Session:   event.SessionInfo{ID: "session-1"},
		Event:     "PreToolUse",
		Tool:      "Bash",
		Target:    "https://example.com",
		CWD:       "/Users/me/project",
		PID:       1240,
		PPID:      1200,
		Tags:      []string{"external_egress_attempt"},
		ToolUseID: "toolu-egress",
	})
	s.AddProcess(2000, 1200, "sibling-shell", "test")
	s.AddProcess(3000, 2000, "/Applications/Codex.app/Contents/Resources/codex", "test")

	direct := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		FlowID:    "direct",
		PID:       1240,
		PPID:      1200,
		Local:     "192.0.2.1:50000",
		Remote:    "104.20.23.154:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}
	strong := s.TryCorrelate(direct)
	if len(strong) != 1 {
		t.Fatalf("expected direct PID match, got %d", len(strong))
	}
	if !contains(strong[0].Reasons, "pid_match") {
		t.Fatalf("expected pid_match, got %v", strong[0].Reasons)
	}

	weaker := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(4 * time.Second),
		FlowID:    "weaker",
		PID:       3000,
		PPID:      2000,
		Local:     "192.0.2.1:50001",
		Remote:    "172.64.155.209:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}
	if got := s.TryCorrelate(weaker); len(got) != 0 {
		t.Fatalf("weaker ancestor match after direct PID match should be suppressed, got %d: %+v", len(got), got[0].Reasons)
	}
}

func TestSessionState_TryCorrelate_DoesNotUseBroadSessionTaint(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "~/.env",
		PID:    1111,
		PPID:   2222,
		Tags:   []string{"sensitive_read"},
	})

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       9999,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
	}

	if got := s.TryCorrelate(flow); len(got) != 0 {
		t.Fatalf("unrelated PID should not correlate from broad session taint, got %d", len(got))
	}
}

func TestSessionState_TryCorrelate_AncestorMatch(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "~/.env",
		PID:    100,
		Tags:   []string{"sensitive_read"},
	})
	s.AddProcess(200, 100, "shell", "test")
	s.AddProcess(300, 200, "curl", "test")

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       300,
		PPID:      200,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected ancestor correlation, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "ancestor_match") {
		t.Fatalf("expected ancestor_match reason, got %v", corrs[0].Reasons)
	}
	if corrs[0].Confidence != "high" {
		t.Fatalf("expected high confidence for sensitive read ancestor match, got %q", corrs[0].Confidence)
	}
	if !processTreeContains(corrs[0].ProcessTree, 100, "hook") {
		t.Fatalf("expected hook PID in process tree, got %+v", corrs[0].ProcessTree)
	}
	if !processTreeContains(corrs[0].ProcessTree, 300, "flow") {
		t.Fatalf("expected flow PID in process tree, got %+v", corrs[0].ProcessTree)
	}
	if !processTreeContains(corrs[0].ProcessTree, 200, "ancestor") {
		t.Fatalf("expected shared ancestor in process tree, got %+v", corrs[0].ProcessTree)
	}
}

func TestSessionState_TryCorrelate_HookParentAncestorMatch(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "~/.env",
		PID:    100,
		PPID:   50,
		Tags:   []string{"sensitive_read"},
	})
	s.AddProcess(200, 50, "shell", "test")
	s.AddProcess(300, 200, "curl", "test")

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       300,
		PPID:      200,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected hook-parent ancestor correlation, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "ancestor_match") {
		t.Fatalf("expected ancestor_match reason, got %v", corrs[0].Reasons)
	}
	if corrs[0].Confidence != "high" {
		t.Fatalf("expected high confidence for sensitive hook-parent ancestor match, got %q", corrs[0].Confidence)
	}
	if !processTreeContains(corrs[0].ProcessTree, 50, "ancestor") {
		t.Fatalf("expected hook parent in process tree, got %+v", corrs[0].ProcessTree)
	}
}

func TestIsEgressLikeIncludesExplicitNetworkTools(t *testing.T) {
	for _, tool := range []string{"WebFetch", "WebSearch"} {
		if !isEgressLike(event.SemanticEvent{Tool: tool}) {
			t.Fatalf("expected %s to be egress-like", tool)
		}
	}
}

func TestSessionState_TryCorrelate_SameAgentSessionSibling(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Bash",
		Target: "curl",
		PID:    400,
		PPID:   300,
		Tags:   []string{"external_egress_attempt"},
	})

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       401,
		PPID:      300,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected sibling process correlation, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "same_agent_session") {
		t.Fatalf("expected same_agent_session reason, got %v", corrs[0].Reasons)
	}
	if corrs[0].Confidence != "low" {
		t.Fatalf("expected low confidence for sibling match, got %q", corrs[0].Confidence)
	}
}

func TestSessionState_TryCorrelate_SensitiveSameAgentSessionSiblingIsMediumConfidence(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "~/.env",
		PID:    400,
		PPID:   300,
		Tags:   []string{"sensitive_read"},
	})

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       401,
		PPID:      300,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected sensitive sibling correlation, got %d", len(corrs))
	}
	for _, want := range []string{"within_10s", "same_agent_session", "after_sensitive_read"} {
		if !contains(corrs[0].Reasons, want) {
			t.Fatalf("expected %s reason, got %v", want, corrs[0].Reasons)
		}
	}
	if corrs[0].Confidence != "medium" {
		t.Fatalf("expected medium confidence for sensitive sibling match, got %q", corrs[0].Confidence)
	}
}

func TestSessionState_TryCorrelate_SensitiveCommonTrackedAgentAncestor(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "~/.env",
		PID:    100,
		PPID:   80,
		Tags:   []string{"sensitive_read"},
	})
	addProcessInfoForTest(s, ProcessInfo{PID: 80, PPID: 50, Name: "hook-shell", Source: "test"})
	s.AddProcess(50, 1, "/opt/homebrew/bin/claude", "test")
	addProcessInfoForTest(s, ProcessInfo{PID: 200, PPID: 50, Name: "worker-shell", Source: "test"})
	addProcessInfoForTest(s, ProcessInfo{PID: 300, PPID: 200, Name: "curl", Source: "test"})

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       300,
		PPID:      200,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected common tracked ancestor correlation, got %d", len(corrs))
	}
	for _, want := range []string{"within_10s", "common_agent_ancestor", "after_sensitive_read"} {
		if !contains(corrs[0].Reasons, want) {
			t.Fatalf("expected %s reason, got %v", want, corrs[0].Reasons)
		}
	}
	for _, notWant := range []string{"ancestor_match", "same_agent_session"} {
		if contains(corrs[0].Reasons, notWant) {
			t.Fatalf("did not expect %s for separate branches, got %v", notWant, corrs[0].Reasons)
		}
	}
	if corrs[0].Confidence != "medium" {
		t.Fatalf("expected medium confidence for sensitive common tracked ancestor, got %q", corrs[0].Confidence)
	}
	if !processTreeContains(corrs[0].ProcessTree, 50, "ancestor") {
		t.Fatalf("expected common agent root in process tree, got %+v", corrs[0].ProcessTree)
	}
}

func TestSessionState_TryCorrelate_SharedUntrackedAncestorDoesNotCorrelate(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "~/.env",
		PID:    100,
		PPID:   80,
		Tags:   []string{"sensitive_read"},
	})
	addProcessInfoForTest(s, ProcessInfo{PID: 80, PPID: 50, Name: "hook-shell", Source: "test"})
	addProcessInfoForTest(s, ProcessInfo{PID: 50, PPID: 1, Name: "zsh", Source: "test"})
	addProcessInfoForTest(s, ProcessInfo{PID: 200, PPID: 50, Name: "worker-shell", Source: "test"})
	addProcessInfoForTest(s, ProcessInfo{PID: 300, PPID: 200, Name: "curl", Source: "test"})

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       300,
		PPID:      200,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	if got := s.TryCorrelate(flow); len(got) != 0 {
		t.Fatalf("shared untracked ancestor should not correlate, got %d: %+v", len(got), got)
	}
}

func TestSessionState_TryCorrelate_EgressCommonTrackedAgentAncestorIsLowConfidence(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Bash",
		Target: "curl https://example.com",
		PID:    100,
		PPID:   80,
		Tags:   []string{"external_egress_attempt"},
	})
	addProcessInfoForTest(s, ProcessInfo{PID: 80, PPID: 50, Name: "hook-shell", Source: "test"})
	s.AddProcess(50, 1, "/opt/homebrew/bin/claude", "test")
	addProcessInfoForTest(s, ProcessInfo{PID: 200, PPID: 50, Name: "worker-shell", Source: "test"})
	addProcessInfoForTest(s, ProcessInfo{PID: 300, PPID: 200, Name: "curl", Source: "test"})

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       300,
		PPID:      200,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected egress common tracked ancestor correlation, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "common_agent_ancestor") {
		t.Fatalf("expected common_agent_ancestor reason, got %v", corrs[0].Reasons)
	}
	if corrs[0].Confidence != "low" {
		t.Fatalf("expected low confidence for egress common tracked ancestor, got %q", corrs[0].Confidence)
	}
}

func TestSessionState_TryCorrelate_OrdinaryBashDoesNotCorrelateNearbyFlow(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Bash",
		Target: "ls -la",
		PID:    400,
		PPID:   300,
		Tags:   []string{},
	})

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       401,
		PPID:      300,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	if got := s.TryCorrelate(flow); len(got) != 0 {
		t.Fatalf("ordinary Bash should not correlate with nearby sibling flow, got %d", len(got))
	}
}

func TestSessionState_TryCorrelate_OrdinaryWriteDoesNotCorrelateNearbyFlow(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Write",
		Target: "/tmp/notes.txt",
		PID:    500,
		PPID:   300,
		Tags:   []string{},
	})

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       501,
		PPID:      300,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	if got := s.TryCorrelate(flow); len(got) != 0 {
		t.Fatalf("ordinary Write should not correlate with nearby sibling flow, got %d", len(got))
	}
}

func TestSessionState_TryCorrelate_MCPServerFlow(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "mcp__github__search_repositories",
		Target: "github.search_repositories",
		PID:    700,
		PPID:   600,
		Tags:   []string{"mcp_tool_use"},
	})
	s.AddProcess(701, 600, "node /Users/me/project/node_modules/@modelcontextprotocol/server-github/dist/index.js", "test")

	flow := event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base.Add(2 * time.Second),
		PID:         701,
		PPID:        600,
		ProcessPath: "/usr/local/bin/node",
		Remote:      "140.82.112.5:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "new",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected MCP server flow correlation, got %d", len(corrs))
	}
	for _, want := range []string{"within_10s", "same_agent_session", "mcp_server_flow"} {
		if !contains(corrs[0].Reasons, want) {
			t.Fatalf("expected %s reason, got %v", want, corrs[0].Reasons)
		}
	}
	if !strings.Contains(corrs[0].Summary, "Tool call → outbound connection") {
		t.Fatalf("summary should describe MCP linkage:\n%s", corrs[0].Summary)
	}
}

func TestSessionState_TryCorrelate_HighVolumeMCPUsesSpecificTitle(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Event:  "PreToolUse",
		Tool:   "mcp__playwright__browser_evaluate",
		PID:    700,
		PPID:   600,
		Tags:   []string{"mcp_tool_use"},
	})

	corrs := s.TryCorrelate(event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       700,
		PPID:      600,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
		BytesOut:  2 * 1024 * 1024,
	})
	if len(corrs) != 1 {
		t.Fatalf("expected high-volume MCP correlation, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "high_bytes") {
		t.Fatalf("expected high_bytes reason, got %v", corrs[0].Reasons)
	}
	if !strings.Contains(corrs[0].Summary, "Large outbound flow after MCP tool") {
		t.Fatalf("summary should describe high-volume MCP linkage:\n%s", corrs[0].Summary)
	}
}

func TestSessionState_TryCorrelate_HighVolumeKnownClaudeServiceUsesInformationalTitle(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Event:  "PreToolUse",
		Tool:   "mcp__playwright__browser_evaluate",
		PID:    700,
		PPID:   600,
		Tags:   []string{"mcp_tool_use"},
	})

	corrs := s.TryCorrelate(event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       700,
		PPID:      600,
		Remote:    "104.18.32.47:443",
		SNI:       "api.anthropic.com",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
		BytesOut:  2 * 1024 * 1024,
	})
	if len(corrs) != 1 {
		t.Fatalf("expected high-volume Claude service correlation, got %d", len(corrs))
	}
	if !strings.Contains(corrs[0].Summary, "High-volume Claude service traffic") {
		t.Fatalf("summary should describe known Claude service traffic:\n%s", corrs[0].Summary)
	}
}

func TestSessionState_TryCorrelate_CredentialOutputUsesSpecificTitle(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Event:  "PostToolUse",
		Tool:   "Read",
		PID:    700,
		PPID:   600,
		Tags:   []string{"credential_output"},
	})

	corrs := s.TryCorrelate(event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       700,
		PPID:      600,
		Remote:    "93.184.216.34:443",
		SNI:       "api.example.com",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
		BytesOut:  2048,
	})
	if len(corrs) != 1 {
		t.Fatalf("expected credential-output correlation, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "after_sensitive_read") {
		t.Fatalf("expected sensitive reason, got %v", corrs[0].Reasons)
	}
	if !strings.Contains(corrs[0].Summary, "Credential context → outbound connection") {
		t.Fatalf("summary should describe credential-output linkage:\n%s", corrs[0].Summary)
	}
}

func TestSessionState_TryCorrelate_SuppressesRepeatedNoisyAutomationPattern(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema:       event.SchemaSemanticV0,
		TS:           base,
		Agent:        event.AgentInfo{ID: "claude"},
		Event:        "PreToolUse",
		Tool:         "mcp__playwright__browser_screenshot",
		Target:       "http://localhost:5173/paste",
		PID:          700,
		PPID:         600,
		Tags:         []string{"mcp_tool_use"},
		ToolUseID:    "toolu-playwright",
		InputSummary: map[string]interface{}{"url": "http://localhost:5173/paste"},
	})
	s.AddProcess(701, 600, "node /project/node_modules/@modelcontextprotocol/mcp-server-playwright/index.js", "test")

	first := event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base.Add(2 * time.Second),
		FlowID:      "flow-first",
		PID:         701,
		PPID:        600,
		ProcessPath: "/usr/local/bin/node",
		Local:       "127.0.0.1:60001",
		Remote:      "93.184.216.34:443",
		SNI:         "example.com",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "new",
	}
	corrs := s.TryCorrelate(first)
	if len(corrs) != 1 {
		t.Fatalf("first noisy automation destination should be surfaced, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "first_destination") {
		t.Fatalf("first automation card should explain new destination, got %v", corrs[0].Reasons)
	}
	if !strings.Contains(corrs[0].Summary, "Local bridge → outbound connection") {
		t.Fatalf("localhost target should use bridge title:\n%s", corrs[0].Summary)
	}

	repeated := first
	repeated.FlowID = "flow-repeat"
	repeated.Local = "127.0.0.1:60002"
	repeated.TS = base.Add(3 * time.Second)
	if got := s.TryCorrelate(repeated); len(got) != 0 {
		t.Fatalf("repeated noisy automation pattern should be suppressed, got %d: %+v", len(got), got[0].Reasons)
	}

	large := repeated
	large.FlowID = "flow-large"
	large.Local = "127.0.0.1:60003"
	large.BytesOut = 2 * 1024 * 1024
	large.TS = base.Add(4 * time.Second)
	corrs = s.TryCorrelate(large)
	if len(corrs) != 1 {
		t.Fatalf("high-byte noisy automation pattern should still surface, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "high_bytes") {
		t.Fatalf("high-byte card should explain byte-volume boost, got %v", corrs[0].Reasons)
	}
}

func TestSessionState_TryCorrelate_RepeatedNoisyAutomationNewDestinationStillSurfaces(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema:       event.SchemaSemanticV0,
		TS:           base,
		Agent:        event.AgentInfo{ID: "claude"},
		Event:        "PreToolUse",
		Tool:         "mcp__playwright__browser_screenshot",
		Target:       "http://localhost:5173/paste",
		PID:          700,
		PPID:         600,
		Tags:         []string{"mcp_tool_use"},
		ToolUseID:    "toolu-playwright",
		InputSummary: map[string]interface{}{"url": "http://localhost:5173/paste"},
	})
	s.AddProcess(701, 600, "node /project/node_modules/@modelcontextprotocol/mcp-server-playwright/index.js", "test")

	first := event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base.Add(2 * time.Second),
		FlowID:      "flow-first",
		PID:         701,
		PPID:        600,
		ProcessPath: "/usr/local/bin/node",
		Local:       "127.0.0.1:60001",
		Remote:      "93.184.216.34:443",
		SNI:         "example.com",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "new",
	}
	if got := s.TryCorrelate(first); len(got) != 1 {
		t.Fatalf("first noisy automation destination should be surfaced, got %d", len(got))
	}

	newDestination := first
	newDestination.FlowID = "flow-new-destination"
	newDestination.Local = "127.0.0.1:60002"
	newDestination.Remote = "203.0.113.10:443"
	newDestination.SNI = "api.new-service.example"
	newDestination.TS = base.Add(3 * time.Second)
	corrs := s.TryCorrelate(newDestination)
	if len(corrs) != 1 {
		t.Fatalf("new destination for noisy automation should still surface, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "first_destination") {
		t.Fatalf("new destination should be called out, got %v", corrs[0].Reasons)
	}
}

func TestSessionState_TryCorrelate_UnrelatedMCPProcessDoesNotCorrelate(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "mcp__github__search_repositories",
		PID:    700,
		PPID:   600,
		Tags:   []string{"mcp_tool_use"},
	})
	s.AddProcess(901, 800, "node /Users/me/node_modules/@modelcontextprotocol/server-github/dist/index.js", "test")

	flow := event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base.Add(2 * time.Second),
		PID:         901,
		PPID:        800,
		ProcessPath: "/usr/local/bin/node",
		Remote:      "140.82.112.5:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "new",
	}

	if got := s.TryCorrelate(flow); len(got) != 0 {
		t.Fatalf("MCP-looking process without process relationship should not correlate, got %d", len(got))
	}
}

func TestSessionState_TryCorrelate_NonMCPEventDoesNotGetMCPReason(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Bash",
		Target: "curl https://github.com",
		PID:    700,
		PPID:   600,
		Tags:   []string{"external_egress_attempt"},
	})
	s.AddProcess(701, 600, "node /Users/me/node_modules/@modelcontextprotocol/server-github/dist/index.js", "test")

	flow := event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base.Add(2 * time.Second),
		PID:         701,
		PPID:        600,
		ProcessPath: "/usr/local/bin/node",
		Remote:      "140.82.112.5:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "new",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected ordinary sibling correlation, got %d", len(corrs))
	}
	if contains(corrs[0].Reasons, "mcp_server_flow") {
		t.Fatalf("non-MCP semantic event should not get mcp_server_flow: %v", corrs[0].Reasons)
	}
}

func TestSessionState_TryCorrelate_ExistingConnectionActiveIsLowConfidence(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "~/.env",
		PID:    500,
		PPID:   499,
		Tags:   []string{"sensitive_read"},
	})

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(-4 * time.Second),
		PID:       500,
		PPID:      499,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "established",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected existing-connection correlation, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "existing_connection_active") {
		t.Fatalf("expected existing_connection_active reason, got %v", corrs[0].Reasons)
	}
	if contains(corrs[0].Reasons, "within_10s") {
		t.Fatalf("pre-existing flow should not claim within_10s: %v", corrs[0].Reasons)
	}
	if corrs[0].Confidence != "low" {
		t.Fatalf("expected low confidence for existing connection, got %q", corrs[0].Confidence)
	}
	if !strings.Contains(corrs[0].Summary, "active 4.0s before access") {
		t.Fatalf("summary should describe pre-existing connection:\n%s", corrs[0].Summary)
	}
}

func TestSessionState_TryCorrelate_PreExistingNewFlowDoesNotCorrelate(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "~/.env",
		PID:    500,
		PPID:   499,
		Tags:   []string{"sensitive_read"},
	})

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(-4 * time.Second),
		PID:       500,
		PPID:      499,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	if got := s.TryCorrelate(flow); len(got) != 0 {
		t.Fatalf("pre-existing new flow should not correlate, got %d", len(got))
	}
}

func TestSessionState_TryCorrelateSemantic_LinksAlreadyActiveConnection(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	flow := event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base,
		FlowID:      "flow-1",
		PID:         500,
		PPID:        499,
		ProcessPath: "/opt/homebrew/bin/claude",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "established",
		BytesOut:    2 * 1024 * 1024,
	}
	s.AddNetworkFlow(flow)

	sem := event.SemanticEvent{
		Schema:    event.SchemaSemanticV0,
		TS:        base.Add(4 * time.Second),
		Agent:     event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Event:     "PreToolUse",
		Tool:      "Read",
		Target:    "~/.env",
		PID:       500,
		PPID:      499,
		Tags:      []string{"sensitive_read"},
		ToolUseID: "toolu-sensitive",
	}
	s.AddSemanticEvent(sem)

	corrs := s.TryCorrelateSemantic(sem)
	if len(corrs) != 1 {
		t.Fatalf("expected semantic-triggered existing connection correlation, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "existing_connection_active") {
		t.Fatalf("expected existing_connection_active reason, got %v", corrs[0].Reasons)
	}
	if !contains(corrs[0].Reasons, "after_sensitive_read") {
		t.Fatalf("expected after_sensitive_read reason, got %v", corrs[0].Reasons)
	}
	if contains(corrs[0].Reasons, "high_bytes") {
		t.Fatalf("already-active connection should not claim high byte transfer, got %v", corrs[0].Reasons)
	}
	if corrs[0].Confidence != "low" {
		t.Fatalf("expected low confidence, got %q", corrs[0].Confidence)
	}
	if len(corrs[0].SemanticIDs) != 1 || corrs[0].SemanticIDs[0] != "toolu-sensitive" {
		t.Fatalf("expected semantic id in correlation, got %v", corrs[0].SemanticIDs)
	}
	if len(corrs[0].FlowIDs) != 1 || corrs[0].FlowIDs[0] != "flow-1" {
		t.Fatalf("expected flow id in correlation, got %v", corrs[0].FlowIDs)
	}
	if !strings.Contains(corrs[0].Summary, "active 4.0s before access") {
		t.Fatalf("summary should describe already-active connection:\n%s", corrs[0].Summary)
	}
}

func TestSessionState_TryCorrelate_DestinationIntentLinksSameAgentNEFlow(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema:             event.SchemaSemanticV0,
		TS:                 base,
		Agent:              event.AgentInfo{ID: "sub_1", PID: 5000, Name: "claude"},
		Event:              "PostToolUse",
		Tool:               "Bash",
		Target:             "https://example.com",
		PID:                5100,
		PPID:               5000,
		Tags:               []string{"external_egress_attempt"},
		DestinationIntents: []string{"example.com"},
		ToolUseID:          "toolu-curl",
	})

	flow := event.NetworkFlowEvent{
		Schema:         event.SchemaNetworkV0,
		TS:             base.Add(500 * time.Millisecond),
		FlowID:         "nef-example",
		Observer:       "network_extension",
		Agent:          &event.AgentInfo{ID: "sub_1", PID: 5000, Name: "claude"},
		PID:            5200,
		PPID:           5199,
		ProcessPath:    "/usr/bin/curl",
		Remote:         "172.66.147.243:443",
		Hostname:       "example.com",
		HostnameSource: "network_extension_remote_hostname",
		Protocol:       "tcp",
		Direction:      "out",
		State:          "new",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected destination-intent correlation, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "destination_intent_match") {
		t.Fatalf("expected destination_intent_match reason, got %v", corrs[0].Reasons)
	}
	if !contains(corrs[0].Reasons, "same_agent_session") {
		t.Fatalf("expected same_agent_session reason, got %v", corrs[0].Reasons)
	}
	if corrs[0].Confidence != "medium" {
		t.Fatalf("expected medium confidence, got %q", corrs[0].Confidence)
	}
	if !strings.Contains(corrs[0].Summary, "example.com") {
		t.Fatalf("summary should name the requested destination:\n%s", corrs[0].Summary)
	}
}

func TestSessionState_TryCorrelateSemantic_DestinationIntentDoesNotBackdateNewFlow(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	flow := event.NetworkFlowEvent{
		Schema:         event.SchemaNetworkV0,
		TS:             base,
		FlowID:         "nef-earlier",
		Observer:       "network_extension",
		Agent:          &event.AgentInfo{ID: "sub_1", PID: 5000, Name: "claude"},
		PID:            5200,
		PPID:           5199,
		ProcessPath:    "/usr/bin/curl",
		Remote:         "172.66.147.243:443",
		Hostname:       "example.com",
		HostnameSource: "network_extension_remote_hostname",
		Protocol:       "tcp",
		Direction:      "out",
		State:          "new",
	}
	s.AddNetworkFlow(flow)

	sem := event.SemanticEvent{
		Schema:             event.SchemaSemanticV0,
		TS:                 base.Add(3 * time.Second),
		Agent:              event.AgentInfo{ID: "sub_1", PID: 5000, Name: "claude"},
		Event:              "PostToolUse",
		Tool:               "Bash",
		Target:             "https://example.com",
		PID:                5100,
		PPID:               5000,
		Tags:               []string{"external_egress_attempt"},
		DestinationIntents: []string{"example.com"},
		ToolUseID:          "toolu-late-curl",
	}
	s.AddSemanticEvent(sem)

	if got := s.TryCorrelateSemantic(sem); len(got) != 0 {
		t.Fatalf("later semantic event should not backdate a new flow, got %d", len(got))
	}
}

func TestSessionState_TryCorrelate_EgressIntentRejectsDifferentHostname(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema:             event.SchemaSemanticV0,
		TS:                 base,
		Agent:              event.AgentInfo{ID: "sub_1", PID: 5000, Name: "claude"},
		Event:              "PostToolUse",
		Tool:               "Bash",
		Target:             "https://example.com",
		PID:                5100,
		PPID:               5000,
		Tags:               []string{"external_egress_attempt"},
		DestinationIntents: []string{"example.com"},
		ToolUseID:          "toolu-curl",
	})

	flow := event.NetworkFlowEvent{
		Schema:         event.SchemaNetworkV0,
		TS:             base.Add(6 * time.Second),
		FlowID:         "nef-datadog",
		Observer:       "network_extension",
		Agent:          &event.AgentInfo{ID: "sub_1", PID: 5000, Name: "claude"},
		PID:            5000,
		PPID:           4999,
		ProcessPath:    "/Users/me/.local/share/claude/versions/2.1.168",
		Remote:         "34.149.66.137:443",
		Hostname:       "http-intake.logs.us5.datadoghq.com",
		HostnameSource: "network_extension_remote_hostname",
		Protocol:       "tcp",
		Direction:      "out",
		State:          "new",
	}

	if got := s.TryCorrelate(flow); len(got) != 0 {
		t.Fatalf("mismatched egress destination should not correlate, got %d", len(got))
	}
}

func TestSessionState_TryCorrelate_EgressIntentKeepsPIDMatchForIPOnlyFlow(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema:             event.SchemaSemanticV0,
		TS:                 base,
		Agent:              event.AgentInfo{ID: "sub_1", PID: 5000, Name: "claude"},
		Event:              "PostToolUse",
		Tool:               "Bash",
		Target:             "https://example.com",
		PID:                5100,
		PPID:               5000,
		Tags:               []string{"external_egress_attempt"},
		DestinationIntents: []string{"example.com"},
		ToolUseID:          "toolu-curl",
	})

	flow := event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base.Add(2 * time.Second),
		FlowID:      "netstat-ip-only",
		Observer:    "network_statistics",
		PID:         5100,
		PPID:        5000,
		ProcessPath: "/usr/bin/curl",
		Remote:      "93.184.216.34:443",
		PTRHostname: "example.com",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "established",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected PID correlation for IP-only userland flow, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "pid_match") {
		t.Fatalf("expected pid_match, got %v", corrs[0].Reasons)
	}
	if contains(corrs[0].Reasons, "destination_intent_match") {
		t.Fatalf("IP-only flow should not claim destination_intent_match, got %v", corrs[0].Reasons)
	}
}

func TestSessionState_TryCorrelateSemantic_LinksLateWebSearchToActiveConnection(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	flow := event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base,
		FlowID:      "flow-websearch",
		PID:         500,
		PPID:        499,
		ProcessPath: "/opt/homebrew/bin/claude",
		Remote:      "140.82.112.4:443",
		SNI:         "lb-140-82-112-4-iad.github.com",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "established",
	}
	s.AddNetworkFlow(flow)

	sem := event.SemanticEvent{
		Schema:             event.SchemaSemanticV0,
		TS:                 base.Add(3 * time.Second),
		Agent:              event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Event:              "PostToolUse",
		Tool:               "WebSearch",
		PID:                500,
		PPID:               499,
		Tags:               []string{"external_egress_attempt"},
		DestinationIntents: []string{"github.com"},
		ToolUseID:          "toolu-websearch",
	}
	s.AddSemanticEvent(sem)

	corrs := s.TryCorrelateSemantic(sem)
	if len(corrs) != 1 {
		t.Fatalf("expected late WebSearch correlation, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "existing_connection_active") {
		t.Fatalf("expected existing_connection_active reason, got %v", corrs[0].Reasons)
	}
	if len(corrs[0].SemanticIDs) != 1 || corrs[0].SemanticIDs[0] != "toolu-websearch" {
		t.Fatalf("expected WebSearch semantic id, got %v", corrs[0].SemanticIDs)
	}
	if !strings.Contains(corrs[0].Summary, "active 3.0s before tool event") {
		t.Fatalf("summary should describe already-active egress tool connection:\n%s", corrs[0].Summary)
	}
}

func TestSessionState_TryCorrelateSemantic_DedupesRefreshedActiveConnection(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddNetworkFlow(event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base,
		FlowID:      "lsof-older",
		PID:         500,
		PPID:        499,
		ProcessPath: "/opt/homebrew/bin/claude",
		Local:       "192.168.1.5:60000",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "established",
	})
	s.AddNetworkFlow(event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base.Add(25 * time.Second),
		FlowID:      "lsof-newer",
		PID:         500,
		PPID:        499,
		ProcessPath: "/opt/homebrew/bin/claude",
		Local:       "192.168.1.5:60000",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "established",
	})

	sem := event.SemanticEvent{
		Schema:    event.SchemaSemanticV0,
		TS:        base.Add(27 * time.Second),
		Agent:     event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Event:     "PreToolUse",
		Tool:      "Read",
		Target:    "~/.env",
		PID:       500,
		PPID:      499,
		Tags:      []string{"sensitive_read"},
		ToolUseID: "toolu-sensitive",
	}
	s.AddSemanticEvent(sem)

	corrs := s.TryCorrelateSemantic(sem)
	if len(corrs) != 1 {
		t.Fatalf("expected one deduped active connection correlation, got %d", len(corrs))
	}
	if len(corrs[0].FlowIDs) != 1 || corrs[0].FlowIDs[0] != "lsof-newer" {
		t.Fatalf("expected latest refreshed flow id, got %v", corrs[0].FlowIDs)
	}
	if !strings.Contains(corrs[0].Summary, "active 2.0s before access") {
		t.Fatalf("summary should use latest active observation:\n%s", corrs[0].Summary)
	}
}

func TestSessionState_TryCorrelateSemantic_IgnoresPreExistingNewFlow(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddNetworkFlow(event.NetworkFlowEvent{
		Schema:      event.SchemaNetworkV0,
		TS:          base,
		PID:         500,
		PPID:        499,
		ProcessPath: "/opt/homebrew/bin/claude",
		Remote:      "93.184.216.34:443",
		Protocol:    "tcp",
		Direction:   "out",
		State:       "new",
	})

	sem := event.SemanticEvent{
		Schema:    event.SchemaSemanticV0,
		TS:        base.Add(4 * time.Second),
		Agent:     event.AgentInfo{ID: "claude", Name: "Claude Code"},
		Event:     "PreToolUse",
		Tool:      "Read",
		Target:    "~/.env",
		PID:       500,
		PPID:      499,
		Tags:      []string{"sensitive_read"},
		ToolUseID: "toolu-sensitive",
	}
	s.AddSemanticEvent(sem)

	if got := s.TryCorrelateSemantic(sem); len(got) != 0 {
		t.Fatalf("pre-existing new flow should not correlate on semantic arrival, got %d", len(got))
	}
}

func TestSessionState_ApplyProcessSnapshotLearnsDescendants(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "~/.env",
		PID:    200,
		PPID:   100,
		Tags:   []string{"sensitive_read"},
	})
	s.ApplyProcessSnapshot(map[int]ProcessInfo{
		1:   {PID: 1, PPID: 0, Name: "/sbin/launchd"},
		100: {PID: 100, PPID: 1, Name: "/opt/homebrew/bin/claude"},
		200: {PID: 200, PPID: 100, Name: "/bin/zsh"},
		300: {PID: 300, PPID: 200, Name: "/usr/local/bin/node"},
		400: {PID: 400, PPID: 300, Name: "/usr/bin/curl"},
	})

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       400,
		PPID:      300,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected descendant snapshot correlation, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "ancestor_match") {
		t.Fatalf("expected ancestor_match from snapshot-enriched graph, got %v", corrs[0].Reasons)
	}
	if s.IsAgentPID(1) {
		t.Fatal("snapshot ancestor should support graph walks but not be treated as an agent flow owner")
	}
	if !s.IsAgentPID(400) {
		t.Fatal("snapshot descendant should be treated as an agent flow owner")
	}
}

func TestSessionState_TryCorrelate_KnownAgentBinaryAloneDoesNotMatch(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "~/.env",
		PID:    111,
		PPID:   110,
		Tags:   []string{"sensitive_read"},
	})
	s.AddProcess(999, 1, "/opt/homebrew/bin/claude", "test")

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       999,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 0 {
		t.Fatalf("known agent binary alone should not correlate across process trees, got %d", len(corrs))
	}
}

func TestSessionState_TryCorrelate_KnownAgentBinaryAnnotatesProcessMatch(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "~/.env",
		PID:    111,
		PPID:   110,
		Tags:   []string{"sensitive_read"},
	})
	s.AddProcess(999, 110, "/opt/homebrew/bin/claude", "test")

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       999,
		PPID:      110,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	corrs := s.TryCorrelate(flow)
	if len(corrs) != 1 {
		t.Fatalf("expected process-related known agent binary correlation, got %d", len(corrs))
	}
	if !contains(corrs[0].Reasons, "known_agent_binary_match") {
		t.Fatalf("expected known_agent_binary_match reason, got %v", corrs[0].Reasons)
	}
	if corrs[0].Confidence != "high" {
		t.Fatalf("expected high confidence for sensitive sibling known CLI match, got %q", corrs[0].Confidence)
	}
}

func TestSessionState_TryCorrelate_DesktopAgentBinaryAloneDoesNotMatch(t *testing.T) {
	s := NewSessionState()
	base := time.Now().UTC()

	s.AddSemanticEvent(event.SemanticEvent{
		Schema: event.SchemaSemanticV0,
		TS:     base,
		Agent:  event.AgentInfo{ID: "claude"},
		Event:  "PreToolUse",
		Tool:   "Read",
		Target: "~/.env",
		PID:    111,
		PPID:   110,
		Tags:   []string{"sensitive_read"},
	})
	s.AddProcess(999, 1, "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper", "test")

	flow := event.NetworkFlowEvent{
		Schema:    event.SchemaNetworkV0,
		TS:        base.Add(2 * time.Second),
		PID:       999,
		Remote:    "93.184.216.34:443",
		Protocol:  "tcp",
		Direction: "out",
		State:     "new",
	}

	if got := s.TryCorrelate(flow); len(got) != 0 {
		t.Fatalf("desktop helper binary alone should not correlate with CLI hook event, got %d", len(got))
	}
}

func TestSessionState_HasSensitiveFlag(t *testing.T) {
	s := NewSessionState()
	e := event.SemanticEvent{Tags: []string{"foo"}, PID: 1}
	s.AddSemanticEvent(e)
	if s.HasSensitive {
		t.Error("not yet sensitive")
	}
	e2 := event.SemanticEvent{Tags: []string{"sensitive_read"}, PID: 2}
	s.AddSemanticEvent(e2)
	if !s.HasSensitive {
		t.Error("tainted by sensitive_read")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func processTreeContains(nodes []event.ProcessNode, pid int, rolePart string) bool {
	for _, node := range nodes {
		if node.PID == pid && strings.Contains(node.Role, rolePart) {
			return true
		}
	}
	return false
}

func addProcessInfoForTest(s *SessionState, info ProcessInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addProcessLocked(info)
}
