package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const SchemaTranscriptV0 = "agentsnitch.transcript.v0"

type TranscriptRecord struct {
	Schema string      `json:"schema"`
	TS     time.Time   `json:"ts"`
	Kind   string      `json:"kind"`
	Event  interface{} `json:"event"`
}

type TranscriptWriter struct {
	mu sync.Mutex
}

func NewTranscriptWriter() *TranscriptWriter {
	return &TranscriptWriter{}
}

func TranscriptsDir() string {
	if p := os.Getenv("AGENTSNITCH_TRANSCRIPTS_DIR"); p != "" {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dir := filepath.Join(home, ".agentsnitch", "sessions")
		_ = os.MkdirAll(dir, 0o700)
		return dir
	}
	return filepath.Join(os.TempDir(), "agentsnitch-sessions")
}

func TranscriptPath(sessionID string) string {
	return filepath.Join(TranscriptsDir(), safeSessionID(sessionID), "events.jsonl")
}

func (w *TranscriptWriter) Append(sessionID, kind string, ev interface{}) (err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	path := TranscriptPath(sessionID)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	rec := TranscriptRecord{
		Schema: SchemaTranscriptV0,
		TS:     time.Now().UTC(),
		Kind:   strings.TrimSpace(kind),
		Event:  ev,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	// Handle the close of this writable handle explicitly: a failed close can
	// mean buffered data was not flushed, so surface it unless we are already
	// returning an earlier error.
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if _, err = f.Write(append(raw, '\n')); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

var unsafeSessionChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeSessionID(sessionID string) string {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return "unassigned"
	}
	sessionID = unsafeSessionChars.ReplaceAllString(sessionID, "_")
	sessionID = strings.Trim(sessionID, "._-")
	if sessionID == "" {
		return "unassigned"
	}
	if len(sessionID) > 128 {
		sessionID = sessionID[:128]
	}
	return sessionID
}
