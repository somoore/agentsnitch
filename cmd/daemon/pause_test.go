package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
	asruntime "github.com/somoore/agentsnitch/internal/runtime"
)

func TestPauseControllerTransitions(t *testing.T) {
	p := newPauseController()
	if p.Paused() {
		t.Fatal("new controller must start Live (not paused) — fail-safe")
	}

	base := time.Now().UTC()
	if !p.Pause(base) {
		t.Fatal("first Pause should report a transition")
	}
	if !p.Paused() {
		t.Fatal("controller should be paused after Pause")
	}
	if p.Pause(base.Add(time.Second)) {
		t.Fatal("second Pause should be a no-op (no transition)")
	}

	resumeAt := base.Add(5 * time.Second)
	from, to, transitioned := p.Resume(resumeAt)
	if !transitioned {
		t.Fatal("Resume after Pause should report a transition")
	}
	if p.Paused() {
		t.Fatal("controller should be Live after Resume")
	}
	if !from.Equal(base) {
		t.Fatalf("pause gap from = %v, want %v", from, base)
	}
	if !to.Equal(resumeAt) {
		t.Fatalf("pause gap to = %v, want %v", to, resumeAt)
	}

	if _, _, transitioned := p.Resume(resumeAt.Add(time.Second)); transitioned {
		t.Fatal("Resume while already Live should be a no-op")
	}
}

// TestDispatchControlMessageTogglesPause verifies a control message from the
// authenticated UI peer flips the daemon's paused flag. Control messages fail
// closed, so the peer must present credentials matching the installed UI binary.
func TestDispatchControlMessageTogglesPause(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("AGENTSNITCH_STATUS", filepath.Join(tmp, "status.json"))
	t.Setenv("AGENTSNITCH_TRANSCRIPTS_DIR", filepath.Join(tmp, "sessions"))
	t.Setenv("AGENTSNITCH_APP_PATH", "/Applications/AgentSnitch.app")
	t.Setenv("AGENTSNITCH_SUPPORT_DIR", filepath.Join(tmp, "support"))
	t.Setenv("AGENTSNITCH_TRUSTED_TEAM_ID", "ABCDE12345")
	orig := peerExePath
	t.Cleanup(func() { peerExePath = orig })
	peerExePath = func(int) (string, bool) {
		return "/Applications/AgentSnitch.app/Contents/MacOS/agentsnitch-ui", true
	}
	origIdentity := peerCodeIdentity
	t.Cleanup(func() { peerCodeIdentity = origIdentity })
	peerCodeIdentity = func(string) (codeIdentity, bool) {
		return codeIdentity{TeamID: "ABCDE12345", CDHash: "abc"}, true
	}

	sessions := newDaemonSessions()
	status := newStatusReporter()
	transcripts := asruntime.NewTranscriptWriter()
	pause := newPauseController()

	pauseMsg := `{"schema":"agentsnitch.control.v0","action":"pause"}`
	dispatch(pauseMsg, 4242, true, sessions, status, transcripts, nil, pause)
	if !pause.Paused() {
		t.Fatal("pause control message did not pause the daemon")
	}

	resumeMsg := `{"schema":"agentsnitch.control.v0","action":"resume"}`
	dispatch(resumeMsg, 4242, true, sessions, status, transcripts, nil, pause)
	if pause.Paused() {
		t.Fatal("resume control message did not resume the daemon")
	}
}

// TestControlMessageRejectedWithoutPeerCredentials is a fail-closed guard: when the
// socket peer cannot be authenticated (no peer PID available — e.g. a transient
// getsockopt failure), a control message must NOT be honored. Otherwise any
// same-user process able to open the 0600 socket could halt sensing.
func TestControlMessageRejectedWithoutPeerCredentials(t *testing.T) {
	pause := newPauseController()
	pauseMsg := `{"schema":"agentsnitch.control.v0","action":"pause"}`

	// hasPeerPID=false means we could not authenticate the peer: must fail closed.
	dispatch(pauseMsg, 0, false, newDaemonSessions(), newStatusReporter(), nil, nil, pause)
	if pause.Paused() {
		t.Fatal("control message without peer credentials must NOT pause the daemon")
	}
}

// TestDispatchDropsEvidenceWhilePaused verifies that while paused, a semantic
// event is neither correlated nor written to the transcript (sensing is halted).
func TestDispatchDropsEvidenceWhilePaused(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("AGENTSNITCH_STATUS", filepath.Join(tmp, "status.json"))
	t.Setenv("AGENTSNITCH_TRANSCRIPTS_DIR", filepath.Join(tmp, "sessions"))

	sessions := newDaemonSessions()
	status := newStatusReporter()
	transcripts := asruntime.NewTranscriptWriter()
	pause := newPauseController()
	pause.Pause(time.Now().UTC())

	se := semanticForSessionTest("paused-session", 4242, 4240, time.Now().UTC())
	raw, err := json.Marshal(se)
	if err != nil {
		t.Fatalf("marshal semantic: %v", err)
	}
	dispatch(string(raw), 0, false, sessions, status, transcripts, nil, pause)

	// No transcript should have been written for the dropped event.
	transcriptPath := asruntime.TranscriptPath("paused-session")
	if _, err := os.Stat(transcriptPath); !os.IsNotExist(err) {
		t.Fatalf("expected no transcript while paused, but %s exists (err=%v)", transcriptPath, err)
	}
	// The session should not have been created from the dropped event.
	if got := len(sessions.list()); got != 0 {
		t.Fatalf("expected 0 sessions while paused, got %d", got)
	}
}

// TestResumeWritesPauseGapTranscript verifies resume records the gap as an explicit
// pause_gap transcript record so the halted window is never an invisible hole.
func TestResumeWritesPauseGapTranscript(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("AGENTSNITCH_STATUS", filepath.Join(tmp, "status.json"))
	t.Setenv("AGENTSNITCH_TRANSCRIPTS_DIR", filepath.Join(tmp, "sessions"))

	transcripts := asruntime.NewTranscriptWriter()
	status := newStatusReporter()
	pause := newPauseController()

	pause.Pause(time.Now().UTC())
	handleControl(event.ControlMessage{Schema: event.SchemaControlV0, Action: event.ControlActionResume}, pause, transcripts, status, newDaemonSessions())

	got, err := asruntime.ReadStatus()
	if err != nil {
		t.Fatalf("ReadStatus: %v", err)
	}
	if got.LastTranscriptKind != "pause_gap" {
		t.Fatalf("last transcript kind = %q, want pause_gap", got.LastTranscriptKind)
	}

	// The pause_gap record must be present and well-formed in the transcript file.
	data, err := os.ReadFile(asruntime.TranscriptPath("pause-gap"))
	if err != nil {
		t.Fatalf("read pause-gap transcript: %v", err)
	}
	var rec asruntime.TranscriptRecord
	if err := json.Unmarshal(trimLastLine(data), &rec); err != nil {
		t.Fatalf("unmarshal transcript record: %v", err)
	}
	if rec.Kind != "pause_gap" {
		t.Fatalf("record kind = %q, want pause_gap", rec.Kind)
	}
}

// TestResumeWritesPauseGapToEachLiveSessionTranscript verifies that on resume the
// pause_gap is recorded in every live session's own transcript (not just a synthetic
// "pause-gap" stream), so per-session evidence shows the coverage gap explicitly.
func TestResumeWritesPauseGapToEachLiveSessionTranscript(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("AGENTSNITCH_STATUS", filepath.Join(tmp, "status.json"))
	t.Setenv("AGENTSNITCH_TRANSCRIPTS_DIR", filepath.Join(tmp, "sessions"))

	transcripts := asruntime.NewTranscriptWriter()
	status := newStatusReporter()
	pause := newPauseController()
	sessions := newDaemonSessions()

	base := time.Now().UTC()
	sessions.forSemantic(semanticForSessionTest("session-a", 100, 90, base))
	sessions.forSemantic(semanticForSessionTest("session-b", 200, 190, base))

	pause.Pause(base)
	handleControl(event.ControlMessage{Schema: event.SchemaControlV0, Action: event.ControlActionResume}, pause, transcripts, status, sessions)

	for _, id := range []string{"session-a", "session-b"} {
		data, err := os.ReadFile(asruntime.TranscriptPath(id))
		if err != nil {
			t.Fatalf("read transcript for %s: %v", id, err)
		}
		var rec asruntime.TranscriptRecord
		if err := json.Unmarshal(trimLastLine(data), &rec); err != nil {
			t.Fatalf("unmarshal transcript record for %s: %v", id, err)
		}
		if rec.Kind != "pause_gap" {
			t.Fatalf("session %s: record kind = %q, want pause_gap", id, rec.Kind)
		}
	}

	// With real sessions present, the synthetic "pause-gap" stream must NOT be used.
	if _, err := os.Stat(asruntime.TranscriptPath("pause-gap")); !os.IsNotExist(err) {
		t.Fatalf("synthetic pause-gap transcript should not exist when live sessions are known (err=%v)", err)
	}
}

// TestControlMessageRejectedFromUntrustedPeer is a security guard: a pause control
// message is honored only from the installed AgentSnitch UI binary (validated by
// executable path), never from an arbitrary same-user process.
func TestControlMessageRejectedFromUntrustedPeer(t *testing.T) {
	t.Setenv("AGENTSNITCH_APP_PATH", "/Applications/AgentSnitch.app")
	t.Setenv("AGENTSNITCH_SUPPORT_DIR", "/tmp/whatever")
	t.Setenv("AGENTSNITCH_TRUSTED_TEAM_ID", "ABCDE12345")
	orig := peerExePath
	t.Cleanup(func() { peerExePath = orig })
	origIdentity := peerCodeIdentity
	t.Cleanup(func() { peerCodeIdentity = origIdentity })
	peerCodeIdentity = func(path string) (codeIdentity, bool) {
		if path == "/Applications/AgentSnitch.app/Contents/MacOS/agentsnitch-ui" {
			return codeIdentity{TeamID: "ABCDE12345", CDHash: "abc"}, true
		}
		return codeIdentity{TeamID: "EVILTEAM00", CDHash: "bad"}, true
	}

	pause := newPauseController()
	pauseMsg := `{"schema":"agentsnitch.control.v0","action":"pause"}`

	// Untrusted peer (a random same-user binary) must be rejected.
	peerExePath = func(int) (string, bool) { return "/opt/homebrew/bin/python3", true }
	dispatch(pauseMsg, 4242, true, newDaemonSessions(), newStatusReporter(), nil, nil, pause)
	if pause.Paused() {
		t.Fatal("control message from untrusted peer must NOT pause the daemon")
	}

	// The installed UI binary must be accepted.
	peerExePath = func(int) (string, bool) {
		return "/Applications/AgentSnitch.app/Contents/MacOS/agentsnitch-ui", true
	}
	dispatch(pauseMsg, 4242, true, newDaemonSessions(), newStatusReporter(), nil, nil, pause)
	if !pause.Paused() {
		t.Fatal("control message from trusted UI peer should pause the daemon")
	}
}

func TestNewPauseGapEventClampsReversedWindow(t *testing.T) {
	now := time.Now().UTC()
	gap := event.NewPauseGapEvent(now, now.Add(-time.Minute))
	if gap.DurationSec < 0 {
		t.Fatalf("duration must not be negative, got %v", gap.DurationSec)
	}
	if gap.Schema != event.SchemaPauseGapV0 {
		t.Fatalf("schema = %q, want %q", gap.Schema, event.SchemaPauseGapV0)
	}
}

// trimLastLine returns the last non-empty newline-terminated line of a transcript
// file (transcripts are append-only JSONL).
func trimLastLine(data []byte) []byte {
	end := len(data)
	for end > 0 && (data[end-1] == '\n' || data[end-1] == '\r') {
		end--
	}
	start := end
	for start > 0 && data[start-1] != '\n' {
		start--
	}
	return data[start:end]
}
