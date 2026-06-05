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

// TestDispatchControlMessageTogglesPause verifies a UI control message flips the
// daemon's paused flag (peer trust is bypassed by passing hasPeerPID=false, the
// same convention other dispatch tests use).
func TestDispatchControlMessageTogglesPause(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("AGENTSNITCH_STATUS", filepath.Join(tmp, "status.json"))
	t.Setenv("AGENTSNITCH_TRANSCRIPTS_DIR", filepath.Join(tmp, "sessions"))

	sessions := newDaemonSessions()
	status := newStatusReporter()
	transcripts := asruntime.NewTranscriptWriter()
	pause := newPauseController()

	pauseMsg := `{"schema":"agentsnitch.control.v0","action":"pause"}`
	dispatch(pauseMsg, 0, false, sessions, status, transcripts, nil, pause)
	if !pause.Paused() {
		t.Fatal("pause control message did not pause the daemon")
	}

	resumeMsg := `{"schema":"agentsnitch.control.v0","action":"resume"}`
	dispatch(resumeMsg, 0, false, sessions, status, transcripts, nil, pause)
	if pause.Paused() {
		t.Fatal("resume control message did not resume the daemon")
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
	handleControl(event.ControlMessage{Schema: event.SchemaControlV0, Action: event.ControlActionResume}, pause, transcripts, status)

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

// TestControlMessageRejectedFromUntrustedPeer is a security guard: a pause control
// message is honored only from the installed AgentSnitch UI binary (validated by
// executable path), never from an arbitrary same-user process.
func TestControlMessageRejectedFromUntrustedPeer(t *testing.T) {
	t.Setenv("AGENTSNITCH_APP_PATH", "/Applications/AgentSnitch.app")
	t.Setenv("AGENTSNITCH_SUPPORT_DIR", "/tmp/whatever")
	orig := peerExePath
	t.Cleanup(func() { peerExePath = orig })

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
