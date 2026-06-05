package main

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
	asruntime "github.com/somoore/agentsnitch/internal/runtime"
)

// pauseController is the daemon's single source of truth for whether sensing is
// halted (the user engaged Pause in the UI). When paused, every observer and
// ingestion path consults Paused() and stops: no semantic/network ingestion, no
// correlation, no transcript writes, no process snapshots.
//
// Fail-safe by construction: the zero value is "not paused" (Live). The daemon
// never persists the paused flag, so a daemon restart always comes back Live — a
// stuck-paused security tool is worse than a noisy one (see docs/ui-ux-plan.md).
//
// SECURITY/HONESTY: while paused, agent activity is deliberately not recorded.
// On resume we write a pause_gap record so the gap is explicit in the transcript
// and surfaced in the UI, never an invisible hole.
type pauseController struct {
	paused atomic.Bool

	mu       sync.Mutex
	pausedAt time.Time
}

func newPauseController() *pauseController {
	return &pauseController{}
}

// Paused reports whether sensing is currently halted. Cheap and lock-free; safe
// to call on every observer tick / ingested line.
func (p *pauseController) Paused() bool {
	if p == nil {
		return false
	}
	return p.paused.Load()
}

// Pause halts sensing. Returns true if this call performed the transition (it was
// previously Live), false if it was already paused.
func (p *pauseController) Pause(now time.Time) bool {
	if p == nil {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if p.paused.Swap(true) {
		return false // already paused
	}
	p.mu.Lock()
	p.pausedAt = now.UTC()
	p.mu.Unlock()
	log.Printf("PAUSE: sensing halted at %s; agent activity will NOT be observed or recorded until resume", now.UTC().Format(time.RFC3339))
	return true
}

// Resume restarts sensing. Returns the pause-gap window [from, to] and true if
// this call performed the transition; false (and a zero window) if it was already
// Live.
func (p *pauseController) Resume(now time.Time) (from, to time.Time, transitioned bool) {
	if p == nil {
		return time.Time{}, time.Time{}, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !p.paused.Swap(false) {
		return time.Time{}, time.Time{}, false // already live
	}
	p.mu.Lock()
	from = p.pausedAt
	p.pausedAt = time.Time{}
	p.mu.Unlock()
	to = now.UTC()
	log.Printf("RESUME: sensing restored at %s after pause gap %s", to.Format(time.RFC3339), to.Sub(from).Round(time.Second))
	return from, to, true
}

// handleControl applies a UI->daemon control message (pause/resume). On resume it
// writes a pause_gap record to the transcript and forwards it to the UI so the gap
// is recorded as a gap. The peer is already trusted as the installed UI binary by
// the caller.
func handleControl(msg event.ControlMessage, pause *pauseController, transcripts *asruntime.TranscriptWriter, status *statusReporter) {
	switch msg.Action {
	case event.ControlActionPause:
		pause.Pause(time.Now().UTC())
	case event.ControlActionResume:
		from, to, transitioned := pause.Resume(time.Now().UTC())
		if !transitioned {
			return
		}
		gap := event.NewPauseGapEvent(from, to)
		// Record the gap in the active session transcript and surface it in the UI.
		appendTranscript(transcripts, status, "pause-gap", "pause_gap", gap)
		forwardToUI(gap)
	default:
		log.Printf("CONTROL_INVALID: unknown action %q", msg.Action)
	}
}
